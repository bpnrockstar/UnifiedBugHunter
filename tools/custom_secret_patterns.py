#!/usr/bin/env python3
"""
custom_secret_patterns.py — org-specific secret regexes for secret_validate.scan_custom().

WHY THIS EXISTS:
  trufflehog / gitleaks / noseyparker ship hundreds of patterns for *public*
  providers (AWS, GitHub, Slack, Stripe, ...), but they know nothing about an
  organisation's OWN internal token formats — the `lk_live_...` prefix your
  payment service mints, the `valyoo_...` internal service tokens, the issuer
  string baked into your internal JWTs. Those never trip a public scanner, so a
  leaked internal token sails straight through a secrets scan. This file is the
  one place to teach the hunter your org's shapes. `secret_validate.scan_custom()`
  walks every pattern here over a blob of text and reports the matches.

╔══════════════════════════════════════════════════════════════════════════════╗
║  EDIT THESE for your org.                                                      ║
║                                                                                ║
║  Everything in CUSTOM_PATTERNS below is a PLACEHOLDER EXAMPLE modelled on      ║
║  Lenskart / Valyoo naming, NOT a real production token format. Before relying  ║
║  on this in a real engagement:                                                 ║
║    1. Replace the example regexes with your real internal token prefixes /     ║
║       formats (ask the platform / DevSecOps team for the canonical shapes).    ║
║    2. Delete any example that does not apply to your org.                      ║
║    3. Keep the entropy / length floors high enough to avoid matching obvious   ║
║       placeholders (`lk_live_xxxxxxxx`, `changeme`, ...).                      ║
║    4. NEVER commit a real secret into this file as a "test" — use a fake that  ║
║       matches the *shape* only (see the test fixtures).                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

PATTERN FORMAT:
  CUSTOM_PATTERNS is a list of dicts. Each dict (a "pattern spec") has:

    {
        "name":     str   short stable id for the detector, e.g.
                          "lenskart_api_key". Surfaces as the `detector` of a
                          scan_custom() hit. Use lower_snake_case.
        "regex":    str   a Python `re` pattern (raw string). The substring it
                          matches is treated as the candidate secret. Prefer an
                          anchored prefix + a length/charset floor so you match
                          the token, not the words around it. Compiled with
                          re.MULTILINE; add (?i) inline if you need it.
        "severity": str   one of "critical" | "high" | "medium" | "low". Rough
                          blast radius of a leak of this token type.
        "description": str  one human line: what the token is + what to do
                          (rotate / revoke / where it lives). Shown to triage.
    }

  Optional keys honoured by scan_custom():
    "group":   int   if set, the capturing group whose span is the secret
                     (default 0 == the whole match). Use when the regex needs
                     context around the token but only one group IS the token.

  scan_custom() compiles each "regex" once. A spec whose regex fails to compile
  is skipped with a warning rather than crashing the scan — a typo in one custom
  pattern must never take down the whole secret pass.

These shapes intentionally OVERLAP with nothing the public scanners catch; that
is the point — they are the gap trufflehog/gitleaks leave for your org.
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

# ─────────────────────────────────────────────────────────────────────────────
#  EDIT THESE for your org  (placeholder Lenskart / Valyoo examples below)
# ─────────────────────────────────────────────────────────────────────────────
CUSTOM_PATTERNS: list[dict] = [
    {
        # EXAMPLE — replace with your real public-facing API key prefix.
        # Models a Stripe-style "lk_live_ / lk_test_" key the payment edge mints.
        "name": "lenskart_api_key",
        "regex": r"\blk_(?:live|test)_[A-Za-z0-9]{24,}\b",
        "severity": "high",
        "description": (
            "Lenskart-style API key (lk_live_/lk_test_ prefix). EXAMPLE PATTERN — "
            "replace with your real key shape. A live key here is a full API "
            "credential; rotate it in the key console and purge from history."
        ),
    },
    {
        # EXAMPLE — internal service-to-service token. valyoo_<svc>_<random>.
        "name": "valyoo_internal_token",
        "regex": r"\bvalyoo_[a-z]+_[A-Za-z0-9]{20,}\b",
        "severity": "high",
        "description": (
            "Valyoo internal service token (valyoo_<service>_<random>). EXAMPLE "
            "PATTERN — replace with your real internal token format. Grants "
            "service-to-service access; revoke via the internal auth service."
        ),
    },
    {
        # EXAMPLE — internal JWT identified by its issuer claim, not its shape.
        # NOTE: a real JWT is already caught generically by trufflehog/redact;
        # this catches the ISSUER STRING so you can tell an INTERNAL token leak
        # apart from a third-party one. Tune the issuer host to your IdP.
        "name": "valyoo_internal_jwt_issuer",
        "regex": r"\"iss\"\s*:\s*\"https://auth\.(?:lenskart|valyoo)\.(?:com|internal)[^\"]*\"",
        "severity": "medium",
        "description": (
            "Internal JWT issuer claim (iss = auth.lenskart/valyoo). EXAMPLE "
            "PATTERN — set this to your real internal IdP issuer URL. Flags JWTs "
            "minted by the INTERNAL identity provider so an internal-token leak "
            "is not mistaken for a harmless third-party one."
        ),
    },
    {
        # EXAMPLE — legacy basic-auth style internal credential in a URL/conn str.
        "name": "lenskart_internal_db_dsn",
        "regex": r"\b(?:postgres|mysql|mongodb)(?:\+srv)?://[A-Za-z0-9_]+:[^@\s/]{8,}@[A-Za-z0-9.\-]+\.(?:lenskart|valyoo)\.(?:com|internal)\b",
        "severity": "critical",
        "description": (
            "Internal database DSN with embedded credentials pointing at a "
            "lenskart/valyoo host. EXAMPLE PATTERN — tune the host suffix. A live "
            "DSN is direct datastore access; rotate the DB user immediately."
        ),
    },
]


def patterns() -> list[dict]:
    """Return the org-specific pattern specs.

    A thin accessor so callers (and tests) can pull the list without reaching
    into the module global directly — and so a future loader (YAML/env override)
    can slot in here without changing scan_custom().
    """
    return list(CUSTOM_PATTERNS)


if __name__ == "__main__":
    # Tiny self-check so `python3 tools/custom_secret_patterns.py` confirms every
    # pattern compiles — handy after editing the list for your org.
    import re
    import sys

    bad = 0
    for spec in CUSTOM_PATTERNS:
        name = spec.get("name", "<unnamed>")
        try:
            re.compile(spec["regex"], re.MULTILINE)
            print(f"[ok]  {name}")
        except (re.error, KeyError, TypeError) as exc:
            bad += 1
            print(f"[BAD] {name}: {exc}", file=sys.stderr)
    print(f"\n{len(CUSTOM_PATTERNS)} pattern(s), {bad} invalid.")
    sys.exit(1 if bad else 0)
