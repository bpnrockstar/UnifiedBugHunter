"""
Unified Bug Hunter — Web Dashboard

Flask web app for viewing targets, findings, recon data, reports,
knowledge base, and monitoring status. All data is stored in a
searchable SQLite database.

CONFIG / HARDENING (env-driven, non-breaking — see the "Config" block below):
    DASHBOARD_SECRET_KEY   Flask secret_key. When unset, a per-process random dev
                           key is generated (so flash() works out of the box on
                           localhost) and a warning is printed. SET THIS in any
                           shared/exposed deployment so sessions survive restarts.
    DASHBOARD_DEBUG        When truthy ('1','true','yes','on'), run() uses Flask
                           debug mode. Default is OFF — debug is opt-in, never the
                           default (the reloader/debugger must not ship enabled).
    DASHBOARD_AUTH_USER /  When BOTH are set, a before_request hook enforces HTTP
    DASHBOARD_AUTH_PASS    Basic auth on every route. When either is unset the
                           dashboard stays OPEN (the localhost-default posture) —
                           auth is strictly opt-in so existing localhost use never
                           breaks. Health probes (see _AUTH_EXEMPT) stay open.

EXTERNAL DEPENDENCIES / GRACEFUL DEGRADATION:
    Everything here is stdlib + Flask + the local dashboard.database module. No
    network, no semgrep/playwright, no external binaries. The one subprocess hop
    (the retest route -> tools/retest.py) is guarded: any failure to run/parse
    degrades to a flash message instead of a 500, so the page always renders.

Importable surface (all logic lives in top-level functions; tests import them):
    create_app(config=None) -> Flask          build/configure an app instance
    resolve_secret_key(env=None) -> str        secret-key resolution + dev fallback
    auth_credentials(env=None) -> tuple|None   (user, pass) when both env vars set
    check_basic_auth(header, user, pass) -> bool   constant-time Basic-auth check
    findings_query_args(args) -> dict          parse /findings-style filters once
    findings_to_csv_rows(findings) -> list[list[str]]   header + one row/finding
    findings_to_markdown(findings) -> str      Markdown table of findings
    get_report(rid) -> dict | None             single report by id (reuses DB list)
    build_trends() -> dict                     /api/trends payload (reuses get_stats)

Usage:
    python3 dashboard/app.py
    # Then open http://127.0.0.1:5000
"""
import csv
import hmac
import io
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
)

from dashboard.database import (
    FINDING_STATUSES,
    add_finding,
    add_report,
    add_target,
    add_to_knowledge_base,
    get_finding,
    get_findings,
    get_monitoring_log,
    get_recon_data,
    get_reports,
    get_retest_specs,
    get_stats,
    get_target,
    get_targets,
    init_db,
    search_knowledge_base,
    set_finding_status,
)

# retest.py verdict -> findings.status enum. A live re-run can only tell us the
# bug is still exploitable (verified) or no longer exploitable (fixed); ERROR
# leaves the stored status untouched.
RETEST_TIMEOUT_SECONDS = 60
_VERDICT_TO_STATUS = {
    "STILL-VULN": "verified",
    "REGRESSED": "verified",
    "FIXED": "fixed",
}

# Findings export cap — mirrors the /findings page limit so an export can never
# stream the whole table unbounded. Kept generous (the page shows 200).
EXPORT_LIMIT = 1000

# Routes that stay reachable even when Basic auth is enabled, so uptime/health
# probes don't need credentials. Intentionally tiny.
_AUTH_EXEMPT = frozenset({"/healthz"})

# Truthy env-flag values for DASHBOARD_DEBUG.
_TRUTHY = frozenset({"1", "true", "yes", "on"})


# ─── Config helpers (env-driven, importable, non-breaking) ───────────────────

def resolve_secret_key(env=None):
    """Resolve the Flask secret key, generating a dev fallback when unset.

    Precedence: DASHBOARD_SECRET_KEY -> legacy UBH_SECRET_KEY -> a freshly
    generated random key (dev/localhost fallback). The generated key is NOT
    stable across restarts; a warning is printed so operators know to set
    DASHBOARD_SECRET_KEY for any shared/persistent deployment. Never raises and
    never returns empty, so flash()/sessions always work out of the box.
    """
    env = os.environ if env is None else env
    key = env.get("DASHBOARD_SECRET_KEY") or env.get("UBH_SECRET_KEY")
    if key:
        return key
    print(
        "WARNING: DASHBOARD_SECRET_KEY unset — using a generated, per-process dev "
        "key. Set DASHBOARD_SECRET_KEY for shared/persistent deployments.",
        file=sys.stderr,
    )
    return secrets.token_hex(32)


def auth_credentials(env=None):
    """Return (user, password) only when BOTH Basic-auth env vars are set.

    Auth is strictly opt-in: returns None (dashboard stays open, localhost
    default) unless DASHBOARD_AUTH_USER and DASHBOARD_AUTH_PASS are both present
    and non-empty. This is the detect-step of the degrade pattern — callers
    branch on None rather than assuming auth is configured.
    """
    env = os.environ if env is None else env
    user = env.get("DASHBOARD_AUTH_USER")
    password = env.get("DASHBOARD_AUTH_PASS")
    if user and password:
        return user, password
    return None


def check_basic_auth(authorization, expected_user, expected_pass):
    """Constant-time check of a Werkzeug Authorization object against creds.

    Returns True only for a Basic-auth header whose username and password both
    match. Uses hmac.compare_digest so the comparison does not leak length/prefix
    timing. Any malformed/absent header returns False.
    """
    if authorization is None or authorization.type != "basic":
        return False
    user_ok = hmac.compare_digest(str(authorization.username or ""), expected_user)
    pass_ok = hmac.compare_digest(str(authorization.password or ""), expected_pass)
    return user_ok and pass_ok


# ─── Findings export helpers (importable; honor the same filters as /findings) ─

# Columns exported to CSV / Markdown. A fixed allowlist (not finding.keys()) keeps
# the export stable and avoids leaking raw poc_spec JSON into a shared artifact.
EXPORT_COLUMNS = (
    "id",
    "severity",
    "title",
    "bug_class",
    "domain",
    "endpoint",
    "status",
    "cvss_score",
    "confidence",
    "source",
    "created_at",
)


def findings_query_args(args):
    """Parse the /findings-style query filters from a request args mapping once.

    Returns a kwargs dict ready to splat into get_findings(): keys severity,
    bug_class, status, search, target_id. Keeping this in one place means
    /findings, /findings.csv and /findings.md stay in lockstep on filtering.
    """
    target_id = args.get("target_id", type=int) if hasattr(args, "get") else None
    return {
        "severity": args.get("severity"),
        "bug_class": args.get("class"),
        "status": args.get("status"),
        "search": args.get("q"),
        "target_id": target_id,
    }


def _cell(value):
    """Render a finding field as a flat string for CSV/Markdown cells."""
    if value is None:
        return ""
    return str(value)


def findings_to_csv_rows(findings):
    """Return a list of rows (header first) for the EXPORT_COLUMNS schema.

    Pure data transform — no I/O — so tests can assert on the rows directly.
    """
    rows = [list(EXPORT_COLUMNS)]
    for f in findings:
        rows.append([_cell(f.get(col)) for col in EXPORT_COLUMNS])
    return rows


def findings_to_markdown(findings):
    """Render findings as a GitHub-flavored Markdown table.

    Pipe characters in cell values are escaped so a stray '|' in a title can't
    break the table layout. Always returns at least the header + separator rows,
    even for an empty finding set, so the output is a valid table.
    """
    header = "| " + " | ".join(EXPORT_COLUMNS) + " |"
    separator = "| " + " | ".join("---" for _ in EXPORT_COLUMNS) + " |"
    lines = [header, separator]
    for f in findings:
        cells = [_cell(f.get(col)).replace("|", "\\|").replace("\n", " ") for col in EXPORT_COLUMNS]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


# ─── Reports + trends helpers (importable; reuse existing DB queries) ─────────

def get_report(rid):
    """Fetch a single report by id, reusing the existing get_reports() query.

    database.py exposes only the list query (get_reports); rather than reach into
    the DB layer (owned elsewhere), we pull the recent set and select by id. The
    reports table is small (dashboard-scale), so this stays cheap. Returns the
    report dict (including .content markdown + joined .domain) or None.
    """
    for report in get_reports(limit=EXPORT_LIMIT):
        if report.get("id") == rid:
            return report
    return None


def build_trends():
    """Build the /api/trends payload by reusing get_stats()'s computed queries.

    get_stats() already runs the findings-over-time (last 30d) and top-classes
    aggregations; we surface exactly those two series so the charts page and the
    JSON endpoint share one source of truth (no duplicated SQL).

    Shape:
        {
          "findings_over_time": [ {"day": "YYYY-MM-DD", "cnt": <int>}, ... ],
          "top_classes":        [ {"bug_class": <str|None>, "cnt": <int>}, ... ]
        }
    """
    stats = get_stats()
    return {
        "findings_over_time": stats.get("findings_over_time", []),
        "top_classes": stats.get("top_classes", []),
    }


# ─── App factory ──────────────────────────────────────────────────────────────

def create_app(config=None):
    """Build and configure the Flask app.

    Factory form (over a module-global app) so tests can construct an isolated,
    fully-configured instance — including toggling Basic auth via the `config`
    overrides — without mutating process env or import-time globals.

    Args:
        config: optional dict merged into app.config AFTER defaults. Useful keys:
            SECRET_KEY, DEBUG, AUTH_USER, AUTH_PASS. When AUTH_USER/AUTH_PASS are
            both truthy, the Basic-auth before_request hook is active.

    Returns:
        A configured flask.Flask instance with every route registered.
    """
    app = Flask(__name__)
    app.config["TITLE"] = "Unified Bug Hunter"
    # Needed for flash() messaging used by the status/retest action loop.
    app.config["SECRET_KEY"] = resolve_secret_key()
    app.secret_key = app.config["SECRET_KEY"]

    creds = auth_credentials()
    app.config["AUTH_USER"] = creds[0] if creds else None
    app.config["AUTH_PASS"] = creds[1] if creds else None

    if config:
        app.config.update(config)
        # Keep secret_key in sync if the override set SECRET_KEY.
        if "SECRET_KEY" in config:
            app.secret_key = app.config["SECRET_KEY"]

    _register_auth(app)
    _register_csrf(app)
    _register_routes(app)
    return app


def _register_auth(app):
    """Install the opt-in Basic-auth before_request hook.

    The hook is always registered but is a no-op unless BOTH AUTH_USER and
    AUTH_PASS are configured — so a default (localhost) deployment stays open and
    non-breaking. _AUTH_EXEMPT paths (health probes) are never challenged.
    """

    @app.before_request
    def _require_basic_auth():  # noqa: ANN202 - Flask hook
        expected_user = app.config.get("AUTH_USER")
        expected_pass = app.config.get("AUTH_PASS")
        if not (expected_user and expected_pass):
            return None  # auth not configured → open (localhost default)
        if request.path in _AUTH_EXEMPT:
            return None
        if check_basic_auth(request.authorization, expected_user, expected_pass):
            return None
        return Response(
            "Authentication required.",
            401,
            {"WWW-Authenticate": 'Basic realm="Unified Bug Hunter"'},
        )


def _register_csrf(app):
    """Session-based CSRF protection for state-changing form POSTs.

    A per-session token is minted on first render and exposed to templates via
    the ``csrf_token()`` global. Every POST/PUT/PATCH/DELETE must echo it back as
    the ``csrf_token`` form field (or ``X-CSRFToken`` header); a missing/mismatched
    token is rejected with 400. Safe methods and health probes are exempt. No
    third-party dependency — uses the signed Flask session (SECRET_KEY) + a
    constant-time comparison. The dashboard re-test action performs a live request,
    so guarding its POST against cross-site forgery is the point of this hook.
    """

    def _get_token():
        tok = session.get("_csrf_token")
        if not tok:
            tok = secrets.token_urlsafe(32)
            session["_csrf_token"] = tok
        return tok

    @app.before_request
    def _csrf_protect():  # noqa: ANN202 - Flask hook
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None
        if request.path in _AUTH_EXEMPT:
            return None
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        expected = session.get("_csrf_token")
        if not (expected and sent and secrets.compare_digest(str(sent), str(expected))):
            abort(400, description="CSRF token missing or invalid")
        return None

    @app.context_processor
    def _inject_csrf():  # noqa: ANN202 - Flask hook
        return {"csrf_token": _get_token}


def _register_routes(app):
    """Register every dashboard route on `app`."""

    @app.route("/healthz")
    def healthz():
        """Unauthenticated liveness probe (also exempt from Basic auth)."""
        return jsonify({"status": "ok"})

    @app.route("/")
    def index():
        stats = get_stats()
        return render_template("index.html", stats=stats)

    @app.route("/targets")
    def targets():
        all_targets = get_targets()
        return render_template("targets.html", targets=all_targets)

    @app.route("/targets/<int:target_id>")
    def target_detail(target_id):
        target = get_target(target_id)
        if not target:
            return "Target not found", 404
        findings, _ = get_findings(target_id=target_id, limit=500)
        recon = get_recon_data(target_id=target_id, limit=500)
        reports = get_reports(target_id=target_id)
        return render_template(
            "target_detail.html", target=target, findings=findings, recon=recon, reports=reports
        )

    @app.route("/targets/add", methods=["POST"])
    def add_target_route():
        domain = request.form.get("domain")
        program = request.form.get("program")
        platform = request.form.get("platform")
        if domain:
            add_target(domain, program, platform)
        return redirect(url_for("targets"))

    @app.route("/findings")
    def findings():
        filters = findings_query_args(request.args)
        findings_list, total = get_findings(limit=200, **filters)
        return render_template(
            "findings.html",
            findings=findings_list,
            total=total,
            severity=filters["severity"],
            bug_class=filters["bug_class"],
            status=filters["status"],
            search=filters["search"],
            target_id=filters["target_id"],
        )

    @app.route("/findings.csv")
    def findings_csv():
        """Stream findings (honoring the same filters as /findings) as CSV."""
        filters = findings_query_args(request.args)
        findings_list, _ = get_findings(limit=EXPORT_LIMIT, **filters)
        rows = findings_to_csv_rows(findings_list)

        def generate():
            buf = io.StringIO()
            writer = csv.writer(buf)
            for row in rows:
                writer.writerow(row)
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)

        return Response(
            stream_with_context(generate()),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=findings.csv"},
        )

    @app.route("/findings.md")
    def findings_md():
        """Render findings (honoring the same filters as /findings) as Markdown."""
        filters = findings_query_args(request.args)
        findings_list, _ = get_findings(limit=EXPORT_LIMIT, **filters)
        md = findings_to_markdown(findings_list)
        return Response(md, mimetype="text/markdown")

    @app.route("/findings/<int:finding_id>")
    def finding_detail(finding_id):
        finding = get_finding(finding_id)
        if not finding:
            return "Finding not found", 404
        return render_template("finding_detail.html", finding=finding)

    @app.route("/findings/<int:fid>/status", methods=["POST"])
    def set_finding_status_route(fid):
        """Set a finding's status from the editable <select> on finding_detail."""
        status = request.form.get("status", "")
        try:
            updated = set_finding_status(fid, status)
        except ValueError:
            flash(f"Invalid status: {status!r}", "danger")
        else:
            if updated:
                flash(f"Status updated to '{status}'.", "success")
            else:
                flash("Finding not found — status unchanged.", "warning")
        return redirect(url_for("finding_detail", finding_id=fid))

    @app.route("/findings/<int:fid>/retest", methods=["POST"])
    def retest_finding_route(fid):
        """Re-run the stored PoC against the LIVE target and write back the verdict."""
        finding = get_finding(fid)
        if not finding:
            return "Finding not found", 404

        verdict, detail = _run_retest(fid)
        if verdict is None:
            flash(detail, "warning")
        else:
            msg = f"Retest verdict: {verdict}" + (f" — {detail}" if detail else "")
            new_status = _VERDICT_TO_STATUS.get(verdict)
            if new_status:
                try:
                    set_finding_status(fid, new_status)
                    msg += f" (status set to '{new_status}')"
                except ValueError:
                    pass
                flash(msg, "success" if verdict == "FIXED" else "danger")
            else:
                # ERROR verdict — status left untouched.
                flash(msg, "warning")

        return redirect(url_for("finding_detail", finding_id=fid))

    @app.route("/recon")
    def recon():
        rtype = request.args.get("type")
        search = request.args.get("q")
        data = get_recon_data(rtype=rtype, search=search, limit=500)
        return render_template("recon.html", recon_data=data, rtype=rtype, search=search)

    @app.route("/reports")
    def reports():
        all_reports = get_reports()
        return render_template("reports.html", reports=all_reports)

    @app.route("/reports/<int:rid>")
    def report_detail(rid):
        """Render a single report's markdown content."""
        report = get_report(rid)
        if not report:
            return "Report not found", 404
        return render_template("report_detail.html", report=report)

    @app.route("/charts")
    def charts():
        """Charts page; data is fetched client-side from /api/trends."""
        return render_template("charts.html")

    @app.route("/knowledge-base")
    def knowledge_base():
        search = request.args.get("q")
        bug_class = request.args.get("class")
        entries = search_knowledge_base(search=search, bug_class=bug_class)
        return render_template("knowledge_base.html", entries=entries, search=search, bug_class=bug_class)

    @app.route("/knowledge-base/add", methods=["POST"])
    def add_kb_entry():
        title = request.form.get("title")
        bug_class = request.form.get("bug_class")
        source = request.form.get("source")
        content = request.form.get("content")
        if title:
            add_to_knowledge_base(title, bug_class, source=source, content=content)
        return redirect(url_for("knowledge_base"))

    @app.route("/monitoring")
    def monitoring():
        logs = get_monitoring_log(limit=200)
        return render_template("monitoring.html", logs=logs)

    @app.route("/api/stats")
    def api_stats():
        return jsonify(get_stats())

    @app.route("/api/trends")
    def api_trends():
        """findings_over_time + top_classes JSON for the charts page."""
        return jsonify(build_trends())

    @app.route("/api/findings")
    def api_findings():
        findings_list, total = get_findings(
            severity=request.args.get("severity"),
            bug_class=request.args.get("class"),
            search=request.args.get("q"),
            limit=int(request.args.get("limit", 100)),
        )
        return jsonify({"findings": findings_list, "total": total})

    @app.route("/api/findings/<int:finding_id>")
    def api_finding(finding_id):
        finding = get_finding(finding_id)
        return jsonify(finding) if finding else ("Not found", 404)

    @app.route("/api/knowledge-base")
    def api_kb():
        entries = search_knowledge_base(search=request.args.get("q"), bug_class=request.args.get("class"))
        return jsonify(entries)

    @app.route("/api/recon")
    def api_recon():
        data = get_recon_data(rtype=request.args.get("type"), search=request.args.get("q"))
        return jsonify(data)


# ─── retest bridge (subprocess to tools/retest.py; fail-soft, never 500) ──────

def _run_retest(fid):
    """Resolve a finding's stored PoC-spec and replay it via tools/retest.py.

    retest.py's CLI consumes a PoC-spec JSON file (--finding/--batch); it has no
    DB awareness, so we bridge: pull the spec from the DB (get_retest_specs),
    drop it to a temp file, run the engine with --json, and parse the verdict.
    Scope gating is inherited from retest.py itself (fail-closed). Returns
    (verdict, detail) where verdict is one of FIXED / STILL-VULN / REGRESSED /
    ERROR, or (None, message) when there is nothing to replay / the run failed.
    """
    specs = get_retest_specs(ids=[fid])
    if not specs:
        return None, "No replayable PoC-spec stored for this finding."

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", prefix=f"retest_{fid}_", delete=False, encoding="utf-8"
        ) as tf:
            json.dump(specs[0], tf)
            tmp_path = tf.name

        proc = subprocess.run(
            [sys.executable, "tools/retest.py", "--finding", tmp_path, "--json"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=RETEST_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return None, f"Retest timed out after {RETEST_TIMEOUT_SECONDS}s."
    except Exception as exc:  # noqa: BLE001 - never let a subprocess failure 500 the page
        return None, f"Retest failed to run: {type(exc).__name__}: {exc}"
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # Parse the JSON report from stdout; fall back gracefully on any surprise.
    try:
        report = json.loads(proc.stdout)
        result = report["results"][0]
        return result.get("verdict", "ERROR"), result.get("detail") or ""
    except (ValueError, KeyError, IndexError, TypeError):
        snippet = (proc.stderr or proc.stdout or "no output").strip()[:300]
        return None, f"Could not parse retest output (exit {proc.returncode}): {snippet}"


# Module-level app instance (kept for `flask run` / existing imports of `app`).
app = create_app()


if __name__ == "__main__":
    init_db()
    debug = os.environ.get("DASHBOARD_DEBUG", "").strip().lower() in _TRUTHY
    print("Dashboard: http://127.0.0.1:5000")
    if auth_credentials():
        print("Basic auth: ENABLED (DASHBOARD_AUTH_USER/PASS set)")
    app.run(debug=debug, host="127.0.0.1", port=5000)
