"""
Unified Bug Hunter — Web Dashboard

Flask web app for viewing targets, findings, recon data, reports,
knowledge base, and monitoring status. All data is stored in a
searchable SQLite database.

Usage:
    python3 dashboard/app.py
    # Then open http://127.0.0.1:5000
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for

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

app = Flask(__name__)
app.config["TITLE"] = "Unified Bug Hunter"
# Needed for flash() messaging used by the status/retest action loop.
app.secret_key = os.environ.get("UBH_SECRET_KEY", "ubh-dashboard-dev-secret")

# retest.py verdict -> findings.status enum. A live re-run can only tell us the
# bug is still exploitable (verified) or no longer exploitable (fixed); ERROR
# leaves the stored status untouched.
RETEST_TIMEOUT_SECONDS = 60
_VERDICT_TO_STATUS = {
    "STILL-VULN": "verified",
    "REGRESSED": "verified",
    "FIXED": "fixed",
}


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
    return render_template("target_detail.html", target=target, findings=findings, recon=recon, reports=reports)


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
    severity = request.args.get("severity")
    bug_class = request.args.get("class")
    status = request.args.get("status")
    search = request.args.get("q")
    # Bug fix: /findings previously dropped target_id, so links like
    # ?target_id=5 silently showed every target's findings. Honor it when given.
    target_id = request.args.get("target_id", type=int)
    findings_list, total = get_findings(
        target_id=target_id, severity=severity, bug_class=bug_class, status=status, search=search, limit=200
    )
    return render_template(
        "findings.html",
        findings=findings_list,
        total=total,
        severity=severity,
        bug_class=bug_class,
        status=status,
        search=search,
        target_id=target_id,
    )


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


if __name__ == "__main__":
    init_db()
    print(f"Dashboard: http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)
