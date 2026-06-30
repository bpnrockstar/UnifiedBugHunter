#!/usr/bin/env python3
"""
retest.py — Scope-safe PoC-replay + regression-verdict engine.

Re-runs a stored proof-of-concept against a target and decides whether a
previously-reported vulnerability is STILL-VULN, has been FIXED, or has
REGRESSED (was fixed, vulnerable again). Built for closed-loop verification
of security-fix tickets (e.g. retesting resolved DevSecOps Jira issues).

A PoC spec is a dict/JSON describing the request to replay and the 'match'
that defines the VULNERABLE condition. If the match is still satisfied the
target is still vulnerable.

PoC-spec schema
---------------
{
  "id":            "BUG-123",          # str/int, identifier echoed into the result
  "target":        "api.target.com",   # host (used for scope gating); optional if url has a host
  "url":           "https://api.target.com/users/1",   # request URL (required)
  "method":        "GET",              # optional, default "GET"
  "headers":       {"X-Foo": "bar"},   # optional dict of request headers
  "body":          "a=1&b=2",          # optional; str sent as-is, dict sent as form data
  "match": {                           # describes the VULNERABLE condition
      "status":          200,              # optional int: response status must equal this
      "body_contains":   "secret",         # optional str: substring must be present in body
      "body_regex":      "id=\\d+",        # optional str: regex must search-match the body
      "header_contains": {"Server": "nginx"}  # optional dict: header must contain value (substr)
  },
  "previous_status": "FIXED"           # optional "FIXED" | "STILL-VULN"; drives REGRESSED detection
}

All keys present in 'match' are ANDed together: every condition listed must
hold for the match to be satisfied. An empty/absent 'match' never matches
(fail-closed), yielding FIXED.

Verdicts
--------
  STILL-VULN  match still satisfied
  FIXED       match no longer satisfied
  REGRESSED   previous_status == "FIXED" but match is satisfied now
  ERROR       request failed, out-of-scope, or malformed spec

CLI usage
---------
  # Single PoC
  python3 tools/retest.py --finding poc.json

  # Batch (JSON array of PoC specs)
  python3 tools/retest.py --batch findings.json

  # Scope-gated (fail-closed: out-of-scope hosts are never contacted)
  python3 tools/retest.py --batch findings.json --scope scope.json

  # Write a JSON report and tune transport
  python3 tools/retest.py --batch findings.json --out report.json \\
      --timeout 20 --rps 2.0 --insecure

  # Pull PoC specs straight from the dashboard DB (every finding with a poc_spec)
  python3 tools/retest.py --from-db

  # Restrict the DB pull to one target and/or specific finding ids
  python3 tools/retest.py --from-db --target-id 7 --id 12 --id 34

  # Retest from DB and write the verdict back onto each finding's status
  #   FIXED -> 'fixed';  STILL-VULN / REGRESSED -> 'open';  ERROR -> skipped
  python3 tools/retest.py --from-db --write-back

Exit codes: 0 always when retests run (verdicts are data, not failure);
non-zero only on usage error (bad args, unreadable/invalid input file).
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import json
import os
import re
import sys
import time
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # pragma: no cover - exercised by CLI smoke checks
    requests = None

# ─── Repo path bootstrap (so tools.* / memory.* import cleanly) ─────────────────
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# ─── Defensive imports: missing optional modules must never break `import retest`
ScopeChecker = None  # type: ignore[assignment]
try:
    from tools.scope_checker import ScopeChecker  # type: ignore[no-redef]
except Exception:  # pragma: no cover - scope_checker path may differ in some installs
    try:
        from scope_checker import ScopeChecker  # type: ignore[no-redef]
    except Exception:
        ScopeChecker = None

_AuditLog = None  # type: ignore[assignment]
try:
    from memory.audit_log import AuditLog as _AuditLog  # type: ignore[no-redef]
except Exception:  # pragma: no cover - audit log is best-effort only
    _AuditLog = None

# ─── Color codes (match tools/validate.py) ─────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ─── Verdict constants ──────────────────────────────────────────────────────────
STILL_VULN = "STILL-VULN"
FIXED      = "FIXED"
REGRESSED  = "REGRESSED"
ERROR      = "ERROR"

_VERDICT_COLOR = {
    STILL_VULN: RED,
    REGRESSED:  RED,
    FIXED:      GREEN,
    ERROR:      YELLOW,
}

_DEFAULT_AUDIT_PATH = os.path.join("hunt-memory", "audit.jsonl")

# ─── Verdict → DB-status mapping for --write-back ────────────────────────────────
# Maps a retest verdict onto a dashboard.database FINDING_STATUSES value.
#   FIXED       -> 'fixed'  (vuln confirmed resolved)
#   STILL-VULN  -> 'open'   (still exploitable right now → stays actionable)
#   REGRESSED   -> 'open'   (was fixed, vulnerable again → re-open it)
#   ERROR       -> None     (inconclusive: request failed / out-of-scope / bad
#                            spec — never overwrite a stored status on no signal)
_VERDICT_TO_DB_STATUS = {
    FIXED:      "fixed",
    STILL_VULN: "open",
    REGRESSED:  "open",
    ERROR:      None,
}


# ─── Core matching logic ────────────────────────────────────────────────────────

def evaluate_match(
    response_status: int,
    response_text: str,
    response_headers: dict,
    match: dict,
) -> bool:
    """Return True if the response satisfies the VULNERABLE condition in `match`.

    Every key present in `match` must hold (logical AND). Supported keys:
      status          int   — response status must equal this exactly
      body_contains   str   — substring must appear in response_text
      body_regex      str   — regex must find a match in response_text (re.search)
      header_contains dict  — each {name: value} must appear; value is a
                              case-insensitive substring of the response header,
                              header name matched case-insensitively

    An empty or non-dict `match` returns False (fail-closed): nothing to satisfy
    means we cannot assert the vulnerable condition, so the bug reads as FIXED.
    """
    if not isinstance(match, dict) or not match:
        return False

    text = response_text if isinstance(response_text, str) else ("" if response_text is None else str(response_text))
    headers = response_headers if isinstance(response_headers, dict) else {}

    if "status" in match:
        try:
            if int(response_status) != int(match["status"]):
                return False
        except (TypeError, ValueError):
            return False

    if "body_contains" in match:
        needle = match["body_contains"]
        if not isinstance(needle, str) or needle not in text:
            return False

    if "body_regex" in match:
        pattern = match["body_regex"]
        if not isinstance(pattern, str):
            return False
        try:
            if re.search(pattern, text) is None:
                return False
        except re.error:
            # An un-compilable regex cannot be satisfied -> treat as no match.
            return False

    if "header_contains" in match:
        wanted = match["header_contains"]
        if not isinstance(wanted, dict) or not wanted:
            return False
        # Build a case-insensitive view of response headers.
        lowered = {}
        for k, v in headers.items():
            try:
                lowered[str(k).lower()] = str(v)
            except Exception:
                continue
        for name, value in wanted.items():
            actual = lowered.get(str(name).lower())
            if actual is None:
                return False
            if str(value).lower() not in actual.lower():
                return False

    return True


def decide_verdict(matched: bool, previous_status: str | None) -> str:
    """Map (match-satisfied?, previous_status) to a regression verdict.

    matched=True  + previous_status=="FIXED"  -> REGRESSED (was fixed, broke again)
    matched=True  + anything else             -> STILL-VULN
    matched=False                             -> FIXED
    """
    prev = (previous_status or "").strip().upper()
    if matched:
        if prev == FIXED:
            return REGRESSED
        return STILL_VULN
    return FIXED


# ─── Helpers ────────────────────────────────────────────────────────────────────

def _finding_host(finding: dict) -> str | None:
    """Resolve the host for scope-gating: explicit `target`, else url's hostname."""
    target = finding.get("target")
    if isinstance(target, str) and target.strip():
        return target.strip()
    url = finding.get("url")
    if isinstance(url, str) and url.strip():
        normalized = url if "://" in url else f"https://{url}"
        try:
            host = urlparse(normalized).hostname
        except Exception:
            host = None
        if host:
            return host
    return None


def _resolve_scope(scope):
    """Coerce a scope argument into something with `.is_in_scope(url) -> bool`.

    Accepts: None (no gating), a ready object exposing is_in_scope, or a path
    to a scope JSON file. Returns the scope object or None. Raises ValueError
    on an unreadable/invalid scope file so the CLI can fail fast on misuse.
    """
    if scope is None:
        return None
    if hasattr(scope, "is_in_scope"):
        return scope
    if isinstance(scope, str):
        if ScopeChecker is None:
            raise ValueError(
                "scope file given but scope_checker module is unavailable"
            )
        return load_scope(scope)
    raise ValueError(f"unsupported scope argument: {type(scope).__name__}")


def load_scope(path: str):
    """Load a scope JSON file into a ScopeChecker.

    Expected JSON shape (any subset):
      {
        "domains":          ["*.target.com", "api.target.com"],
        "excluded_domains": ["blog.target.com"],
        "excluded_classes": ["dos"]
      }
    Also tolerates {"in_scope": [...], "out_of_scope": [...]} aliases and a
    bare JSON array of domain patterns.
    """
    if ScopeChecker is None:
        raise ValueError("scope_checker module is unavailable; cannot load scope")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        domains = [str(d) for d in data]
        return ScopeChecker(domains)

    if not isinstance(data, dict):
        raise ValueError(f"scope file must be a JSON object or array: {path}")

    domains = data.get("domains") or data.get("in_scope") or []
    excluded = data.get("excluded_domains") or data.get("out_of_scope") or []
    excluded_classes = data.get("excluded_classes") or []
    if not domains:
        raise ValueError(f"scope file has no in-scope domains: {path}")
    return ScopeChecker(
        [str(d) for d in domains],
        [str(d) for d in excluded],
        [str(c) for c in excluded_classes],
    )


def _make_audit_log():
    """Best-effort AuditLog factory. Returns an AuditLog or None — never raises."""
    if _AuditLog is None:
        return None
    try:
        return _AuditLog(_DEFAULT_AUDIT_PATH)
    except Exception:
        return None


def _audit(audit_log, *, url, method, scope_check, response_status=None,
           finding_id=None, error=None):
    """Log one outbound request, best-effort. Absence/failure never propagates."""
    if audit_log is None:
        return
    try:
        fid = None if finding_id is None else str(finding_id)
        audit_log.log_request(
            url=url,
            method=(method or "GET").upper(),
            scope_check=scope_check,
            response_status=response_status,
            finding_id=fid,
            error=error,
        )
    except Exception:
        # Audit is observational; swallow everything (bad method, schema, IO).
        pass


def load_findings(path: str) -> list:
    """Load PoC specs from a JSON file.

    Accepts a JSON array of specs, a single spec object, or an object wrapping
    the list under "findings" / "results". Always returns a list of dicts.
    Raises ValueError on unreadable/invalid JSON or unexpected shape.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise ValueError(f"findings file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"findings file is not valid JSON: {path}: {exc}") from exc

    if isinstance(data, dict):
        if isinstance(data.get("findings"), list):
            data = data["findings"]
        elif isinstance(data.get("results"), list):
            data = data["results"]
        else:
            data = [data]

    if not isinstance(data, list):
        raise ValueError(f"findings file must be a JSON array or object: {path}")

    findings = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"finding #{i} is not an object: {type(item).__name__}")
        findings.append(item)
    return findings


def _load_database_module():
    """Import dashboard.database defensively (repo path already on sys.path).

    Returns the module or raises ValueError with a friendly message so the CLI
    can fail fast on a clearly DB-dependent request rather than blowing up with
    a raw ImportError. Importing retest.py never pulls this in — it is only
    called by the --from-db code path.

    Note: `dashboard/` is a namespace package (no __init__.py) and `tools/`
    ships an unrelated `dashboard.py` (the TUI) that shadows it whenever
    tools/ is on sys.path — which it is when retest.py runs as a script. So we
    load dashboard/database.py from its known path under _REPO *first*, and
    only fall back to plain package/module imports.
    """
    if _REPO not in sys.path:
        sys.path.insert(0, _REPO)

    db_path = os.path.join(_REPO, "dashboard", "database.py")
    if os.path.isfile(db_path):
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("dashboard_database", db_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[union-attr]
            return module
        except Exception:
            pass  # fall through to the import-based attempts

    try:
        from dashboard import database  # type: ignore[no-redef]
        return database
    except Exception:
        try:
            import database  # type: ignore[no-redef]
            return database
        except Exception as exc:
            raise ValueError(
                f"dashboard.database module unavailable (needed for --from-db): {exc}"
            ) from exc


def write_back_verdicts(database, report: dict) -> dict:
    """Persist retest verdicts back into the findings DB via set_finding_status.

    Maps each result's verdict through _VERDICT_TO_DB_STATUS and, when that
    yields a concrete status, calls database.set_finding_status(id, status).
    ERROR verdicts (status None) are skipped — an inconclusive retest never
    overwrites a stored status. Results without an integer-coercible id are
    skipped too. Best-effort and total: a per-row failure never aborts the rest.

    Returns a summary dict {updated, skipped, not_found, failed}.
    """
    out = {"updated": 0, "skipped": 0, "not_found": 0, "failed": 0}
    for r in report.get("results", []):
        verdict = r.get("verdict")
        new_status = _VERDICT_TO_DB_STATUS.get(verdict)
        if new_status is None:
            out["skipped"] += 1
            continue
        finding_id = r.get("id")
        if finding_id is None:
            out["skipped"] += 1
            continue
        try:
            ok = database.set_finding_status(finding_id, new_status)
        except Exception:
            out["failed"] += 1
            continue
        if ok:
            out["updated"] += 1
        else:
            out["not_found"] += 1
    return out


def _result(finding_id, verdict, detail, status, url):
    """Build the canonical per-finding result record."""
    return {
        "id": finding_id,
        "verdict": verdict,
        "detail": detail,
        "status": status,
        "url": url,
    }


# ─── Single retest ──────────────────────────────────────────────────────────────

def retest_one(
    finding: dict,
    *,
    scope=None,
    timeout: int = 15,
    verify_tls: bool = True,
    session=None,
    audit_log=None,
) -> dict:
    """Replay one PoC and return a verdict record.

    Returns {id, verdict, detail, status, url}. Never raises on request or
    spec errors — those surface as an ERROR verdict so a batch never aborts.

    Scope gating is fail-closed: if `scope` is provided and the finding's host
    is out of scope, the request is NOT sent and the verdict is ERROR with
    detail 'out-of-scope'.
    """
    if not isinstance(finding, dict):
        return _result(None, ERROR, f"finding must be an object, got {type(finding).__name__}", None, None)

    finding_id = finding.get("id")
    url = finding.get("url")
    method = (finding.get("method") or "GET").upper()
    match = finding.get("match") or {}
    previous_status = finding.get("previous_status")

    if not isinstance(url, str) or not url.strip():
        return _result(finding_id, ERROR, "missing 'url' in PoC spec", None, None)

    scope_obj = scope  # already-resolved object expected from batch; resolve if path
    try:
        if scope_obj is not None and not hasattr(scope_obj, "is_in_scope"):
            scope_obj = _resolve_scope(scope_obj)
    except ValueError as exc:
        return _result(finding_id, ERROR, f"scope error: {exc}", None, url)

    # ── Scope gate (fail-closed) — before any network activity ──
    if scope_obj is not None:
        host = _finding_host(finding)
        check_target = host or url
        in_scope = False
        try:
            in_scope = bool(scope_obj.is_in_scope(check_target))
        except Exception as exc:
            _audit(audit_log, url=url, method=method, scope_check="fail",
                   error=f"scope check raised: {exc}")
            return _result(finding_id, ERROR, f"scope check failed: {exc}", None, url)
        if not in_scope:
            _audit(audit_log, url=url, method=method, scope_check="fail",
                   finding_id=finding_id, error="out-of-scope")
            return _result(finding_id, ERROR, "out-of-scope", None, url)
        scope_check_label = "pass"
    else:
        scope_check_label = "skip"

    if requests is None:
        return _result(
            finding_id, ERROR,
            "requests library not installed (python3 -m pip install requests)",
            None, url,
        )

    # ── Prepare request kwargs ──
    headers = finding.get("headers")
    if headers is not None and not isinstance(headers, dict):
        return _result(finding_id, ERROR, "'headers' must be an object", None, url)

    req_kwargs = {"timeout": timeout, "verify": verify_tls, "allow_redirects": True}
    if headers:
        req_kwargs["headers"] = headers
    body = finding.get("body")
    if body is not None:
        if isinstance(body, (dict, list)):
            req_kwargs["data"] = body if isinstance(body, dict) else body
        else:
            req_kwargs["data"] = str(body).encode("utf-8") if not isinstance(body, bytes) else body

    requester = session if session is not None else requests

    # ── Send ──
    try:
        resp = requester.request(method, url, **req_kwargs)
    except Exception as exc:  # requests.RequestException + anything the transport throws
        detail = f"request failed: {type(exc).__name__}: {exc}"
        _audit(audit_log, url=url, method=method, scope_check=scope_check_label,
               finding_id=finding_id, error=detail)
        return _result(finding_id, ERROR, detail, None, url)

    status = getattr(resp, "status_code", None)
    text = getattr(resp, "text", "") or ""
    resp_headers = {}
    try:
        resp_headers = dict(getattr(resp, "headers", {}) or {})
    except Exception:
        resp_headers = {}

    _audit(audit_log, url=url, method=method, scope_check=scope_check_label,
           finding_id=finding_id, response_status=status if isinstance(status, int) else None)

    # ── Evaluate ──
    try:
        matched = evaluate_match(status, text, resp_headers, match)
    except Exception as exc:  # never let a bad spec abort the batch
        return _result(finding_id, ERROR, f"match evaluation failed: {exc}", status, url)

    verdict = decide_verdict(matched, previous_status)
    if verdict in (STILL_VULN, REGRESSED):
        detail = "vulnerable condition still satisfied"
        if verdict == REGRESSED:
            detail = "previously FIXED but vulnerable condition satisfied again"
    else:
        detail = "vulnerable condition no longer satisfied"
    return _result(finding_id, verdict, detail, status, url)


# ─── Batch retest ─────────────────────────────────────────────────────────────

def retest_batch(
    findings: list,
    *,
    scope=None,
    timeout: int = 15,
    verify_tls: bool = True,
    session=None,
    rps: float | None = None,
    audit_log=None,
) -> dict:
    """Retest a list of PoC specs.

    Returns {results: [...], summary: {still_vuln, fixed, regressed, error}}.
    Robust by construction: each finding is retested independently and a failure
    in one never aborts the batch.

    rps, if given (>0), enforces a simple per-host minimum interval between
    outbound requests (best-effort throttling for lab/staging targets).
    """
    if not isinstance(findings, list):
        raise ValueError(f"findings must be a list, got {type(findings).__name__}")

    # Resolve scope once (path -> object) so every finding shares one checker.
    try:
        scope_obj = _resolve_scope(scope)
    except ValueError:
        # Defer the error to per-finding handling so the batch still returns a
        # structured report (every finding becomes ERROR: scope error).
        scope_obj = scope

    if audit_log is None:
        audit_log = _make_audit_log()

    owns_session = False
    if session is None and requests is not None:
        try:
            session = requests.Session()
            owns_session = True
        except Exception:
            session = None

    min_interval = (1.0 / rps) if (rps and rps > 0) else 0.0
    last_seen: dict[str, float] = {}

    results = []
    summary = {"still_vuln": 0, "fixed": 0, "regressed": 0, "error": 0}
    try:
        for finding in findings:
            # ── Per-host throttle (only meaningful when we will actually send) ──
            if min_interval > 0 and isinstance(finding, dict):
                host = _finding_host(finding) or ""
                now = time.monotonic()
                last = last_seen.get(host, 0.0)
                wait = min_interval - (now - last)
                if wait > 0:
                    time.sleep(wait)
                last_seen[host] = time.monotonic()

            result = retest_one(
                finding,
                scope=scope_obj,
                timeout=timeout,
                verify_tls=verify_tls,
                session=session,
                audit_log=audit_log,
            )
            results.append(result)

            verdict = result.get("verdict")
            if verdict == STILL_VULN:
                summary["still_vuln"] += 1
            elif verdict == FIXED:
                summary["fixed"] += 1
            elif verdict == REGRESSED:
                summary["regressed"] += 1
            else:
                summary["error"] += 1
    finally:
        if owns_session and session is not None:
            try:
                session.close()
            except Exception:
                pass

    return {"results": results, "summary": summary}


# ─── Human-readable rendering ───────────────────────────────────────────────────

def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if _supports_color() else text


def print_summary(report: dict) -> None:
    """Print a colored human summary of a retest_batch report to stdout."""
    results = report.get("results", [])
    summary = report.get("summary", {})

    print(_c("Retest results", BOLD))
    for r in results:
        verdict = r.get("verdict", ERROR)
        color = _VERDICT_COLOR.get(verdict, YELLOW)
        fid = r.get("id")
        fid_str = "<no-id>" if fid is None else str(fid)
        status = r.get("status")
        status_str = "" if status is None else f" [{status}]"
        url = r.get("url") or ""
        detail = r.get("detail") or ""
        print(
            f"  {_c(verdict.ljust(10), color)} "
            f"{_c(fid_str, CYAN)}{status_str}  {url}"
        )
        if detail:
            print(f"             {_c(detail, DIM)}")

    print()
    sv = summary.get("still_vuln", 0)
    fx = summary.get("fixed", 0)
    rg = summary.get("regressed", 0)
    er = summary.get("error", 0)
    print(_c("Summary", BOLD))
    print(f"  {_c('STILL-VULN', RED)}: {sv}    "
          f"{_c('FIXED', GREEN)}: {fx}    "
          f"{_c('REGRESSED', RED)}: {rg}    "
          f"{_c('ERROR', YELLOW)}: {er}")
    if rg:
        print(_c(f"  ⚠ {rg} regression(s) detected — previously-fixed bugs are vulnerable again.", RED))


# ─── CLI ────────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scope-safe PoC-replay + regression-verdict engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--finding", help="Path to a single PoC spec JSON file")
    src.add_argument("--batch", help="Path to a JSON array of PoC specs")
    src.add_argument("--from-db", action="store_true",
                     help="Pull all findings carrying a poc_spec from the dashboard DB")

    parser.add_argument("--id", dest="ids", action="append", type=int, default=None,
                        help="Restrict --from-db to these finding ids (repeatable)")
    parser.add_argument("--target-id", dest="target_id", type=int, default=None,
                        help="Restrict --from-db to a single target id")
    parser.add_argument("--write-back", action="store_true",
                        help="After retesting --from-db, write verdicts back via "
                             "set_finding_status (FIXED->'fixed', STILL-VULN/REGRESSED->'open', "
                             "ERROR->skip)")

    parser.add_argument("--scope", help="Scope JSON file (fail-closed scope gating)")
    parser.add_argument("--out", help="Write the JSON report to this path")
    parser.add_argument("--timeout", type=int, default=15, help="Per-request timeout in seconds (default: 15)")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification (lab targets only)")
    parser.add_argument("--rps", type=float, default=None,
                        help="Throttle: max requests per second per host (e.g. 2.0)")
    parser.add_argument("--json", action="store_true",
                        help="Print the JSON report to stdout instead of the colored summary")
    args = parser.parse_args(argv)

    # ── --write-back / filters only apply to the DB source ──
    database = None
    if args.from_db:
        try:
            database = _load_database_module()
        except ValueError as exc:
            parser.error(str(exc))
    else:
        if args.write_back:
            parser.error("--write-back requires --from-db")
        if args.ids:
            parser.error("--id requires --from-db")
        if args.target_id is not None:
            parser.error("--target-id requires --from-db")

    # ── Load findings ──
    try:
        if args.from_db:
            findings = database.get_retest_specs(target_id=args.target_id, ids=args.ids)
        elif args.finding:
            findings = load_findings(args.finding)
        else:
            findings = load_findings(args.batch)
    except ValueError as exc:
        parser.error(str(exc))

    # ── Load scope (fail fast on a bad/unreadable scope file) ──
    scope_obj = None
    if args.scope:
        if ScopeChecker is None:
            parser.error("scope_checker module unavailable; cannot honor --scope")
        try:
            scope_obj = load_scope(args.scope)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"could not load scope file: {exc}")

    report = retest_batch(
        findings,
        scope=scope_obj,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        rps=args.rps,
    )

    # ── Write verdicts back to the DB (only with --from-db --write-back) ──
    if args.from_db and args.write_back:
        report["write_back"] = write_back_verdicts(database, report)

    # ── Output ──
    if args.out:
        out_dir = os.path.dirname(os.path.abspath(args.out)) or "."
        try:
            os.makedirs(out_dir, exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, sort_keys=True)
                f.write("\n")
        except OSError as exc:
            parser.error(f"could not write report to {args.out}: {exc}")

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_summary(report)
        wb = report.get("write_back")
        if wb is not None:
            print(f"\n{_c('Write-back', BOLD)}  "
                  f"updated: {wb.get('updated', 0)}    "
                  f"skipped: {wb.get('skipped', 0)}    "
                  f"not-found: {wb.get('not_found', 0)}    "
                  f"failed: {wb.get('failed', 0)}")
        if args.out:
            print(f"\n{_c('Report written:', BOLD)} {args.out}")

    # Verdicts are data, not failure — always exit 0 when retests ran.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
