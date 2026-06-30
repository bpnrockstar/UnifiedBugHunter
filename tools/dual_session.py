#!/usr/bin/env python3
"""
dual_session.py — Two-identity attacker/victim harness for clean access-control testing.

The #1 reason IDOR/BOLA/privesc findings get marked N/A is that the tester only
ever read their *own* data — there is no proof a *different* user's resource was
exposed. This harness encodes the two-identity model: every probe first fetches
the target resource AS the victim (baseline — the marker must be present) and
then AS the attacker (the actual test). The verdict is decided by comparing the
two responses, not by eyeballing a single one.

  - VULNERABLE: the attacker's response also contains the victim's marker /
                returns the victim's object → broken access control proven.
  - SAFE:       the attacker is denied (401/403) or gets an empty/marker-free
                body → access control is enforced.
  - ERROR:      a request failed, the baseline was wrong, or the URL is
                out-of-scope (fail-closed — never reported as SAFE).

Everything is importable as top-level functions / a DualSession class. No real
network call happens at import time or in tests; `requests` is imported
defensively and `request_as` can be monkeypatched (or fed a fake transport) so
the verdict logic is unit-testable offline.

Usage:
  python3 tools/dual_session.py --config dual.json --idor https://t.co/api/orders/1042 --victim-marker "victim@example.com"
  python3 tools/dual_session.py --config dual.json --idor https://t.co/api/orders/1042 --victim-marker "ORD-1042" --method GET --json
  python3 tools/dual_session.py --config dual.json --privesc https://t.co/api/admin/users --admin-marker "role:admin"
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import json
import os
import sys
from datetime import datetime

# Repo layout: this file lives in <repo>/tools/. Make the repo importable so the
# deterministic scope checker and audit log resolve the same way the other tools
# resolve them (see tools/validate.py).
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# ─── Defensive optional dependencies ──────────────────────────────────────────
# requests is the only third-party dep and is only needed when a real request is
# actually sent. Import it lazily/defensively so the module imports (and tests
# run) on a box without it installed.
try:  # pragma: no cover - trivial import guard
    import requests
except ImportError:  # pragma: no cover - exercised by CLI smoke checks
    requests = None

# Scope checker is fail-closed: if a scope is configured but the checker can't be
# imported, we must NOT silently allow requests. Import defensively and remember
# whether it was available so request_as can refuse rather than bypass scope.
try:  # pragma: no cover - trivial import guard
    from tools.scope_checker import ScopeChecker
except Exception:  # noqa: BLE001 - any import failure → no checker available
    ScopeChecker = None  # type: ignore[assignment]

# Audit logging is best-effort: a missing audit module must never block a probe.
try:  # pragma: no cover - trivial import guard
    from memory.audit_log import AuditLog
except Exception:  # noqa: BLE001
    AuditLog = None  # type: ignore[assignment]


ROLES = ("attacker", "victim")
_DEFAULT_TIMEOUT = 15
# Status codes that, on their own, prove the attacker was denied → SAFE.
_DENIED_STATUSES = frozenset({401, 403})
# Body size we keep in the response summary. Enough to eyeball the proof in the
# verdict JSON without dumping a multi-megabyte page into the audit trail.
_BODY_SNIPPET_LEN = 2000


# ─── Identity / config helpers ────────────────────────────────────────────────

def _build_request_kwargs(identity: dict) -> dict:
    """Translate an identity dict into requests/transport kwargs.

    An identity may carry any combination of:
        headers -> dict           (merged verbatim)
        cookies -> dict           (merged verbatim)
        token   -> str            (sent as 'Authorization: Bearer <token>'
                                   unless an Authorization header is already set)
        label   -> str            (human name; not sent on the wire)

    Returns a dict with 'headers' and 'cookies' keys suitable for spreading into
    a requests call. Never mutates the input identity.
    """
    identity = identity or {}
    headers = dict(identity.get("headers") or {})
    cookies = dict(identity.get("cookies") or {})

    token = identity.get("token")
    if token and not any(k.lower() == "authorization" for k in headers):
        headers["Authorization"] = f"Bearer {token}"

    return {"headers": headers, "cookies": cookies}


def load_config(path: str) -> dict:
    """Load a dual.json config from disk.

    Schema (see module docstring / CLI --help):
        {
          "attacker": {"label": str, "headers": {...}, "cookies": {...}, "token": str},
          "victim":   {"label": str, "headers": {...}, "cookies": {...}, "token": str},
          "scope": {                                  # optional — omit to disable gating
            "domains":           ["*.target.com", "api.target.com"],
            "excluded_domains":  ["blog.target.com"],
            "excluded_classes":  ["dos"]
          }
        }

    Raises FileNotFoundError if the path is missing and ValueError if the JSON is
    malformed or the required identities are absent.
    """
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level config must be a JSON object")
    for role in ROLES:
        if not isinstance(data.get(role), dict):
            raise ValueError(f"{path}: missing required '{role}' identity object")
    return data


def _make_scope_checker(scope: dict | None):
    """Build a ScopeChecker from a scope config block, or return None.

    Fail-closed contract: when a scope block is given but ScopeChecker could not
    be imported, this raises RuntimeError rather than returning None — a caller
    that asked for scope gating must never silently run ungated.
    """
    if not scope:
        return None
    if ScopeChecker is None:
        raise RuntimeError(
            "scope configured but tools.scope_checker is unavailable — refusing "
            "to run ungated (fail-closed)"
        )
    return ScopeChecker(
        domains=scope.get("domains") or [],
        excluded_domains=scope.get("excluded_domains"),
        excluded_classes=scope.get("excluded_classes"),
    )


# ─── Response summarisation + verdict logic ───────────────────────────────────

def summarize_response(response, role: str, url: str, method: str) -> dict:
    """Reduce a requests.Response-like object to a plain, JSON-safe summary dict.

    Works with the real requests.Response or any duck-typed stand-in exposing
    status_code, headers, and text — which is what makes the verdict logic
    testable without a network. Body is truncated to _BODY_SNIPPET_LEN chars.
    """
    status = getattr(response, "status_code", None)
    try:
        body = response.text if response is not None else ""
    except Exception:  # noqa: BLE001 - some bodies aren't decodable as text
        body = ""
    body = body or ""
    truncated = len(body) > _BODY_SNIPPET_LEN

    headers = {}
    try:
        headers = {str(k): str(v) for k, v in dict(getattr(response, "headers", {})).items()}
    except Exception:  # noqa: BLE001
        headers = {}

    return {
        "role": role,
        "method": method.upper(),
        "url": url,
        "status": status,
        "ok": bool(status is not None and 200 <= status < 300),
        "body_len": len(body),
        "body_snippet": body[:_BODY_SNIPPET_LEN],
        "body_truncated": truncated,
        "content_type": headers.get("Content-Type") or headers.get("content-type", ""),
        "error": None,
    }


def _error_summary(role: str, url: str, method: str, error: str) -> dict:
    """A response summary representing a failed/blocked request (no wire hit)."""
    return {
        "role": role,
        "method": method.upper(),
        "url": url,
        "status": None,
        "ok": False,
        "body_len": 0,
        "body_snippet": "",
        "body_truncated": False,
        "content_type": "",
        "error": error,
    }


def marker_present(summary: dict, marker: str) -> bool:
    """True if the (case-sensitive) marker string appears in the response body.

    Returns False for error summaries (no body) and empty markers — a missing
    marker can never count as a positive hit.
    """
    if not marker or not summary or summary.get("error"):
        return False
    return marker in (summary.get("body_snippet") or "")


def decide_verdict(
    baseline: dict,
    attacker: dict,
    marker: str,
) -> tuple[str, str]:
    """Core access-control decision. Pure function — no I/O, fully testable.

    Args:
        baseline: victim's response summary (the marker SHOULD be present here).
        attacker: attacker's response summary for the same resource.
        marker:   the victim/admin-owned string that proves cross-account access.

    Returns (verdict, reason) where verdict ∈ {VULNERABLE, SAFE, ERROR}:
      ERROR      — either request errored, or the baseline does not contain the
                   marker (we can't trust a probe whose baseline is wrong).
      VULNERABLE — attacker request succeeded AND the victim's marker appears in
                   the attacker's body.
      SAFE       — attacker was denied (401/403) or got no marker / empty body.
    """
    if baseline.get("error"):
        return "ERROR", f"baseline (victim) request failed: {baseline['error']}"
    if attacker.get("error"):
        return "ERROR", f"attacker request failed: {attacker['error']}"

    # The baseline must actually contain the marker, otherwise the marker is
    # wrong and any attacker comparison is meaningless. Fail to ERROR, not SAFE.
    if not marker_present(baseline, marker):
        return (
            "ERROR",
            "victim baseline does not contain the marker — wrong marker or the "
            "victim identity cannot see this resource; verdict not trustworthy",
        )

    # Explicit denial is the clearest SAFE signal.
    if attacker.get("status") in _DENIED_STATUSES:
        return "SAFE", f"attacker denied (HTTP {attacker['status']})"

    # The actual test: the victim's marker leaking into the attacker's response.
    if marker_present(attacker, marker):
        return (
            "VULNERABLE",
            f"attacker (HTTP {attacker['status']}) received the victim marker — "
            "cross-account access confirmed",
        )

    return (
        "SAFE",
        f"attacker (HTTP {attacker['status']}) did not receive the victim marker",
    )


# ─── DualSession ──────────────────────────────────────────────────────────────

class DualSession:
    """Two-identity harness for IDOR / BOLA / privesc testing.

    Holds an attacker and a victim identity and runs comparative probes. Scope
    gating is fail-closed: when `scope` is given, every URL is checked before a
    request leaves and an out-of-scope URL is refused (never reported SAFE).
    Audit logging is best-effort and never blocks a probe.
    """

    def __init__(
        self,
        attacker: dict,
        victim: dict,
        scope: dict | None = None,
        *,
        audit_log_path: str | None = None,
        timeout: int = _DEFAULT_TIMEOUT,
        transport=None,
    ):
        """
        Args:
            attacker: identity dict {label?, headers?, cookies?, token?}.
            victim:   identity dict {label?, headers?, cookies?, token?}.
            scope:    optional scope block {domains, excluded_domains,
                      excluded_classes}. When set, scope gating is enforced
                      fail-closed.
            audit_log_path: optional path for a best-effort JSONL audit log.
            timeout:  per-request timeout in seconds.
            transport: optional callable(method, url, **kw) -> response, used to
                      inject a fake/offline transport in tests. Defaults to the
                      real `requests` request function.
        """
        self.attacker = attacker or {}
        self.victim = victim or {}
        self.timeout = timeout
        self._scope_cfg = scope
        self._scope = _make_scope_checker(scope)  # may raise (fail-closed)
        self._transport = transport

        self._audit = None
        if audit_log_path and AuditLog is not None:
            try:  # best-effort — a broken audit log must not break probing
                self._audit = AuditLog(audit_log_path)
            except Exception:  # noqa: BLE001
                self._audit = None

    # -- identity lookup -------------------------------------------------------

    def _identity(self, role: str) -> dict:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}, got {role!r}")
        return self.attacker if role == "attacker" else self.victim

    def label(self, role: str) -> str:
        """Human label for a role, defaulting to the role name."""
        return self._identity(role).get("label") or role

    # -- scope + audit ---------------------------------------------------------

    def _scope_ok(self, url: str) -> bool:
        """True if the URL may be requested. Fail-closed when scope is set."""
        if self._scope is None:
            return True
        try:
            return bool(self._scope.is_in_scope(url))
        except Exception:  # noqa: BLE001 - a checker error must not allow the request
            return False

    def _audit_request(self, url: str, method: str, scope_check: str, summary: dict) -> None:
        if self._audit is None:
            return
        try:  # best-effort only
            self._audit.log_request(
                url=url,
                method=method.upper(),
                scope_check=scope_check,
                response_status=summary.get("status"),
                error=summary.get("error"),
            )
        except Exception:  # noqa: BLE001
            pass

    # -- the one network primitive --------------------------------------------

    def request_as(self, role: str, method: str, url: str, **kw) -> dict:
        """Send one request as `role` and return a response-summary dict.

        Scope is checked first (fail-closed). On out-of-scope, missing
        dependency, or transport error, an error summary is returned — the
        caller never gets a SAFE-looking dict for a request that did not happen.

        Extra **kw (json=, data=, params=, headers=, ...) are passed through to
        the transport; identity headers/cookies are merged in, with explicit
        per-call headers/cookies taking precedence.
        """
        identity = self._identity(role)
        method = method.upper()

        # 1. Scope gate (fail-closed).
        if not self._scope_ok(url):
            summary = _error_summary(role, url, method, "out_of_scope")
            self._audit_request(url, method, "fail", summary)
            return summary

        # 2. Transport availability.
        send = self._transport or (requests.request if requests is not None else None)
        if send is None:
            summary = _error_summary(
                role, url, method,
                "requests not installed: python3 -m pip install requests",
            )
            self._audit_request(url, method, "pass", summary)
            return summary

        # 3. Merge identity headers/cookies; per-call kw wins.
        id_kw = _build_request_kwargs(identity)
        headers = {**id_kw["headers"], **(kw.pop("headers", None) or {})}
        cookies = {**id_kw["cookies"], **(kw.pop("cookies", None) or {})}
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", False)

        # 4. Send.
        try:
            response = send(method, url, headers=headers, cookies=cookies, **kw)
        except Exception as exc:  # noqa: BLE001 - normalise every transport error
            summary = _error_summary(role, url, method, f"{type(exc).__name__}: {exc}")
            self._audit_request(url, method, "pass", summary)
            return summary

        summary = summarize_response(response, role, url, method)
        self._audit_request(url, method, "pass", summary)
        return summary

    # -- comparative probes ----------------------------------------------------

    def _probe(
        self,
        url: str,
        marker: str,
        *,
        method: str,
        vuln_class: str,
        marker_kind: str,
    ) -> dict:
        """Shared IDOR/privesc engine: baseline as victim, then test as attacker."""
        method = (method or "GET").upper()

        # Honour program-excluded vuln classes when a scope checker is present.
        if self._scope is not None:
            try:
                if not self._scope.is_vuln_class_allowed(vuln_class):
                    return {
                        "verdict": "ERROR",
                        "reason": f"vulnerability class '{vuln_class}' is excluded by program scope",
                        "vuln_class": vuln_class,
                        "url": url,
                        "method": method,
                        marker_kind: marker,
                        "baseline": None,
                        "attacker": None,
                        "checked_at": datetime.now().isoformat(timespec="seconds"),
                    }
            except Exception:  # noqa: BLE001 - checker error → fall through, request still scope-gated
                pass

        baseline = self.request_as("victim", method, url)
        attacker = self.request_as("attacker", method, url)
        verdict, reason = decide_verdict(baseline, attacker, marker)

        return {
            "verdict": verdict,
            "reason": reason,
            "vuln_class": vuln_class,
            "url": url,
            "method": method,
            marker_kind: marker,
            "victim_label": self.label("victim"),
            "attacker_label": self.label("attacker"),
            "baseline": baseline,
            "attacker": attacker,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
        }

    def idor_probe(self, url: str, *, victim_marker: str, method: str = "GET") -> dict:
        """Probe one URL for IDOR/BOLA against the victim's resource.

        Fetches `url` as the victim (baseline — `victim_marker` must appear) and
        as the attacker. Returns a verdict dict:
            {verdict: VULNERABLE|SAFE|ERROR, reason, vuln_class:'idor', url,
             method, victim_marker, victim_label, attacker_label,
             baseline:<summary>, attacker:<summary>, checked_at}
        """
        return self._probe(
            url,
            victim_marker,
            method=method,
            vuln_class="idor",
            marker_kind="victim_marker",
        )

    def privesc_probe(self, url: str, *, admin_marker: str, method: str = "GET") -> dict:
        """Probe one URL for privilege escalation against an admin-only resource.

        Same shape as idor_probe. The 'victim' identity here is the privileged
        (admin) account that legitimately sees `admin_marker`; the attacker is
        the low-privilege account that must NOT. Returns vuln_class='privesc'.
        """
        return self._probe(
            url,
            admin_marker,
            method=method,
            vuln_class="privesc",
            marker_kind="admin_marker",
        )


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _print_human(result: dict) -> None:
    verdict = result.get("verdict", "ERROR")
    print(f"Verdict:   {verdict}")
    print(f"Reason:    {result.get('reason', '')}")
    print(f"Class:     {result.get('vuln_class', '')}")
    print(f"Target:    {result.get('method', '')} {result.get('url', '')}")
    baseline = result.get("baseline") or {}
    attacker = result.get("attacker") or {}
    print(
        f"Victim   ({result.get('victim_label', 'victim')}):  "
        f"HTTP {baseline.get('status')}  ({baseline.get('body_len', 0)} bytes)"
        + (f"  error={baseline.get('error')}" if baseline.get("error") else "")
    )
    print(
        f"Attacker ({result.get('attacker_label', 'attacker')}): "
        f"HTTP {attacker.get('status')}  ({attacker.get('body_len', 0)} bytes)"
        + (f"  error={attacker.get('error')}" if attacker.get("error") else "")
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Two-identity attacker/victim harness for IDOR/BOLA/privesc testing."
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to dual.json (attacker + victim identities, optional scope).",
    )
    parser.add_argument("--idor", metavar="URL", help="Run an IDOR/BOLA probe against this URL.")
    parser.add_argument(
        "--victim-marker",
        default="",
        help="String only the victim's resource contains (required with --idor).",
    )
    parser.add_argument("--privesc", metavar="URL", help="Run a privesc probe against this URL.")
    parser.add_argument(
        "--admin-marker",
        default="",
        help="String only the admin resource contains (required with --privesc).",
    )
    parser.add_argument("--method", default="GET", help="HTTP method for the probe (default GET).")
    parser.add_argument(
        "--audit-log",
        default="",
        help="Optional path for a best-effort JSONL audit log of requests sent.",
    )
    parser.add_argument("--json", action="store_true", help="Print the verdict dict as JSON.")
    args = parser.parse_args(argv)

    if not args.idor and not args.privesc:
        parser.error("provide --idor <url> or --privesc <url>")
    if args.idor and not args.victim_marker:
        parser.error("--idor requires --victim-marker")
    if args.privesc and not args.admin_marker:
        parser.error("--privesc requires --admin-marker")

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        session = DualSession(
            attacker=config["attacker"],
            victim=config["victim"],
            scope=config.get("scope"),
            audit_log_path=args.audit_log or None,
        )
    except RuntimeError as exc:  # fail-closed scope construction
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.idor:
        result = session.idor_probe(
            args.idor, victim_marker=args.victim_marker, method=args.method
        )
    else:
        result = session.privesc_probe(
            args.privesc, admin_marker=args.admin_marker, method=args.method
        )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_human(result)

    # Exit code: 0 SAFE, 2 VULNERABLE (finding!), 1 ERROR.
    verdict = result.get("verdict")
    if verdict == "VULNERABLE":
        return 2
    if verdict == "ERROR":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
