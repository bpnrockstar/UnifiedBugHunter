#!/usr/bin/env python3
"""
save_finding.py — persist a verified finding to the Unified Bug Hunter DB WITH a
replayable PoC-spec, so `/retest` (tools/retest.py) can re-run it later.

The free-text evidence (`poc`, `description`, …) is stored exactly as before via
database.add_finding(); on top of that we attach a structured, machine-replayable
`poc_spec` dict describing the HTTP request to replay and the `match` that defines
the VULNERABLE condition. That spec is what tools/retest.py consumes to decide
FIXED / STILL-VULN / REGRESSED.

PoC-spec shape (matches retest.py load_findings()):
    {
      "id": <DB row id, injected later by get_retest_specs()>,
      "target":  "api.target.com",
      "url":     "https://api.target.com/users/1",
      "method":  "GET",
      "headers": {"X-Foo": "bar"},
      "body":    "a=1&b=2",
      "match": {
          "status":          200,
          "body_contains":   "secret",
          "body_regex":      "id=\\d+",
          "header_contains": {"Server": "nginx"}
      },
      "previous_status": "FIXED"   # mapped from DB status by get_retest_specs()
    }

Importable:
    from tools.save_finding import save_finding
    fid = save_finding("api.target.com", "IDOR on /users/{id}", "high", "idor",
                       url="https://api.target.com/users/1",
                       match={"status": 200, "body_contains": "ssn"})

CLI:
    python3 tools/save_finding.py \\
        --target api.target.com \\
        --title "IDOR on /users/{id}" \\
        --severity high \\
        --class idor \\
        --url https://api.target.com/users/1 \\
        --method GET \\
        --header "Authorization: Bearer x" \\
        --match-status 200 \\
        --match-contains ssn
"""
import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

# ─── Defensive import of the dashboard DB layer ──────────────────────────────
# Mirror the rest of tools/* : add the repo root to sys.path then import
# dashboard.database. Keep it defensive so a missing/broken DB module yields a
# clear error instead of an opaque traceback.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

database = None
_DB_IMPORT_ERROR = None
try:
    from dashboard import database as database  # type: ignore
except Exception as _e:  # noqa: BLE001 - report cleanly, don't crash on import
    try:
        # Fallback: load the module directly by path (no package needed).
        import importlib.util as _ilu

        _db_path = _REPO_ROOT / "dashboard" / "database.py"
        if _db_path.is_file():
            _spec = _ilu.spec_from_file_location("ubh_dashboard_database", str(_db_path))
            if _spec and _spec.loader:
                _mod = _ilu.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                database = _mod
        if database is None:
            _DB_IMPORT_ERROR = _e
    except Exception as _e2:  # noqa: BLE001
        database = None
        _DB_IMPORT_ERROR = _e2


def _require_database():
    if database is None:
        raise RuntimeError(
            "could not import dashboard.database "
            f"(looked under {_REPO_ROOT}/dashboard/database.py): {_DB_IMPORT_ERROR!r}"
        )
    return database


def _resolve_target_id(db, target):
    """Resolve a target domain to its DB row id, creating the row if needed.

    add_target() uses INSERT OR IGNORE and returns None, so after ensuring the
    row exists we look it up by exact domain match. `target` may be a bare host
    or a URL — we normalise to the host component.
    """
    domain = (target or "").strip()
    if not domain:
        raise ValueError("target is required (a domain/host or URL)")
    # Accept a full URL and reduce it to its host.
    if "://" in domain:
        domain = urlparse(domain).hostname or domain
    # Strip any stray path / port that slipped through.
    domain = domain.split("/")[0].strip()

    db.init_db()
    db.add_target(domain)  # INSERT OR IGNORE; no-op if it already exists
    for row in db.get_targets():
        if row.get("domain") == domain:
            return row["id"]
    raise RuntimeError(f"failed to resolve target id for domain {domain!r}")


def _build_match(match):
    """Normalise a caller-supplied match dict to the retest.py 'match' shape.

    Only known keys are carried through, and empty values are dropped so the
    stored spec stays minimal. Returns None when nothing meaningful is present.
    """
    if not match:
        return None
    out = {}
    for key in ("status", "body_contains", "body_regex", "header_contains"):
        val = match.get(key)
        if val is None:
            continue
        if isinstance(val, str) and val == "":
            continue
        out[key] = val
    return out or None


def _build_poc_spec(target, url, method, headers, body, match):
    """Assemble the replayable retest.py PoC-spec dict.

    `id` and `previous_status` are intentionally omitted — get_retest_specs()
    injects the DB row id and maps the DB status onto previous_status at read
    time, so storing them here would just go stale.
    """
    if not url:
        raise ValueError("url is required to build a replayable poc_spec")

    # Derive the scope host from target, falling back to the URL host.
    host = (target or "").strip()
    if "://" in host:
        host = urlparse(host).hostname or host
    host = host.split("/")[0].strip()
    if not host:
        host = urlparse(url).hostname or ""

    spec = {
        "target": host,
        "url": url,
        "method": (method or "GET").upper(),
    }
    if headers:
        spec["headers"] = headers
    if body is not None and body != "":
        spec["body"] = body
    built_match = _build_match(match)
    if built_match:
        spec["match"] = built_match
    return spec


def save_finding(
    target,
    title,
    severity,
    bug_class,
    *,
    url,
    method="GET",
    headers=None,
    body=None,
    match=None,
    endpoint=None,
    description=None,
    poc=None,
    impact=None,
    remediation=None,
    cvss_score=None,
    cvss_vector=None,
):
    """Persist a verified finding plus a replayable PoC-spec; return finding_id.

    Resolves (or creates) the target row, builds the retest.py PoC-spec dict from
    url/method/headers/body/match, and calls database.add_finding(..., poc_spec=<dict>).
    If `endpoint` is not supplied it defaults to the PoC url so the finding still
    records where it lives.
    """
    db = _require_database()
    target_id = _resolve_target_id(db, target)
    poc_spec = _build_poc_spec(target, url, method, headers, body, match)
    if endpoint is None:
        endpoint = url

    return db.add_finding(
        target_id,
        title,
        severity,
        bug_class,
        endpoint=endpoint,
        description=description,
        poc=poc,
        impact=impact,
        remediation=remediation,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        poc_spec=poc_spec,
    )


def _parse_headers(pairs):
    """Turn repeatable --header "K: v" / "K:v" tokens into a dict."""
    headers = {}
    for raw in pairs or []:
        if ":" not in raw:
            raise argparse.ArgumentTypeError(
                f"--header must be 'Key: value' (got {raw!r})"
            )
        key, _, val = raw.partition(":")
        key = key.strip()
        val = val.strip()
        if not key:
            raise argparse.ArgumentTypeError(f"--header has empty key (got {raw!r})")
        headers[key] = val
    return headers


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Persist a verified finding to the DB with a replayable PoC-spec "
        "(consumable by tools/retest.py / the /retest command)."
    )
    parser.add_argument("--target", required=True, help="Target domain/host or URL")
    parser.add_argument("--title", required=True, help="Finding title")
    parser.add_argument(
        "--severity",
        required=True,
        choices=["critical", "high", "medium", "low", "info"],
        help="Finding severity",
    )
    parser.add_argument(
        "--class", dest="bug_class", required=True, help="Bug class (e.g. idor, ssrf, xss)"
    )

    parser.add_argument("--url", required=True, help="Request URL to replay")
    parser.add_argument("--method", default="GET", help="HTTP method (default GET)")
    parser.add_argument(
        "--header",
        dest="headers",
        action="append",
        metavar="K:v",
        help="Request header 'Key: value' (repeatable)",
    )
    parser.add_argument("--body", help="Request body (str sent as-is)")

    parser.add_argument(
        "--match-status", type=int, dest="match_status", help="Match: expected HTTP status"
    )
    parser.add_argument(
        "--match-contains",
        dest="match_contains",
        help="Match: substring that must be present in the response body",
    )
    parser.add_argument(
        "--match-regex",
        dest="match_regex",
        help="Match: regex that must search-match the response body",
    )

    parser.add_argument("--endpoint", help="Endpoint label (defaults to --url)")
    parser.add_argument("--description", help="Finding description")
    parser.add_argument("--poc", help="Free-text PoC / evidence")
    parser.add_argument("--impact", help="Impact statement")
    parser.add_argument("--remediation", help="Remediation guidance")
    parser.add_argument("--cvss", type=float, dest="cvss_score", help="CVSS base score")
    parser.add_argument("--cvss-vector", dest="cvss_vector", help="CVSS vector string")

    args = parser.parse_args(argv)

    headers = _parse_headers(args.headers)
    match = {
        "status": args.match_status,
        "body_contains": args.match_contains,
        "body_regex": args.match_regex,
    }

    finding_id = save_finding(
        args.target,
        args.title,
        args.severity,
        args.bug_class,
        url=args.url,
        method=args.method,
        headers=headers or None,
        body=args.body,
        match=match,
        endpoint=args.endpoint,
        description=args.description,
        poc=args.poc,
        impact=args.impact,
        remediation=args.remediation,
        cvss_score=args.cvss_score,
        cvss_vector=args.cvss_vector,
    )

    sys.stdout.write(f"{finding_id}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
