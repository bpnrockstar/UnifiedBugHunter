#!/usr/bin/env python3
"""
redact.py — Automatic evidence-hygiene / PII + secret redaction.

Applied to findings before they reach the dashboard or generated reports so
that pasted PoCs, HTTP captures, and scanner output don't leak the hunter's
(or the target's) own credentials, cookies, tokens, keys, or PII.

Deterministic, regex-based — no network or LLM calls. Every match is replaced
with a typed placeholder like ``[REDACTED:JWT]`` so reviewers can still see
*what kind* of secret was present without seeing the value.

Usage:
  python3 tools/redact.py --in finding.txt
  python3 tools/redact.py --in - < capture.http
  python3 tools/redact.py --in validation.json --json
  python3 tools/redact.py --in finding.txt --keep-ips

Importable API (tests import these directly):
  redact_text(s: str) -> str
  redact_finding(finding: dict) -> dict        # deep-redact, never mutates input
  redaction_report(s: str) -> dict             # {category: count}

Categories redacted (placeholder shown):
  - Authorization/Bearer header values  -> [REDACTED:AUTH]
  - Cookie / Set-Cookie header values   -> [REDACTED:COOKIE]
  - JWTs (eyJ....eyJ....sig)             -> [REDACTED:JWT]
  - AWS access keys (AKIA/ASIA...)       -> [REDACTED:AWS_KEY]
  - GitHub tokens (ghp_/gho_/ghs_/...)   -> [REDACTED:GITHUB_TOKEN]
  - Google API keys (AIza...)            -> [REDACTED:GOOGLE_API_KEY]
  - Slack tokens (xox[baprs]-...)        -> [REDACTED:SLACK_TOKEN]
  - OpenAI-style keys (sk-...)           -> [REDACTED:OPENAI_KEY]
  - Private-key PEM blocks               -> [REDACTED:PRIVATE_KEY]
  - Generic api_key/secret/password/token (JSON or header)
                                         -> [REDACTED:SECRET]
  - Email addresses                      -> [REDACTED:EMAIL]
  - IPv4 addresses (suppress --keep-ips) -> [REDACTED:IP]
"""

from __future__ import annotations  # PEP 604 union syntax on older Python

import argparse
import json
import re
import sys

# ─── Placeholders ──────────────────────────────────────────────────────────────

PLACEHOLDERS: dict[str, str] = {
    "private_key": "[REDACTED:PRIVATE_KEY]",
    "jwt":         "[REDACTED:JWT]",
    "aws_key":     "[REDACTED:AWS_KEY]",
    "github_token":"[REDACTED:GITHUB_TOKEN]",
    "google_api_key": "[REDACTED:GOOGLE_API_KEY]",
    "slack_token": "[REDACTED:SLACK_TOKEN]",
    "openai_key":  "[REDACTED:OPENAI_KEY]",
    "authorization": "[REDACTED:AUTH]",
    "cookie":      "[REDACTED:COOKIE]",
    "secret":      "[REDACTED:SECRET]",
    "email":       "[REDACTED:EMAIL]",
    "ip":          "[REDACTED:IP]",
}

# All category keys, in the order they are applied. Order matters: structural
# secrets (PEM blocks, headers) run before the narrower token patterns so a
# secret embedded in a header isn't half-replaced by two rules.
CATEGORIES: list[str] = [
    "private_key",
    "authorization",
    "cookie",
    "secret",
    "jwt",
    "aws_key",
    "github_token",
    "google_api_key",
    "slack_token",
    "openai_key",
    "email",
    "ip",
]

# ─── Allowlist of obvious non-secrets ───────────────────────────────────────────
# Substrings that, if present in a candidate match, mean "this is documentation
# / a placeholder, not a live secret" — so we leave it untouched. Compared
# case-insensitively. AWS publishes AKIAIOSFODNN7EXAMPLE as the canonical fake
# key; loopback/unspecified IPs are not PII.

_ALLOWLIST_SUBSTRINGS: tuple[str, ...] = (
    "example",
    "akiaiosfodnn7example",
    "redacted",
    "xxxxxxxx",
    "<token>",
    "your_",
    "placeholder",
    "changeme",
    "dummy",
    "test_token",
)

_ALLOWLIST_EXACT: frozenset[str] = frozenset({
    "127.0.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "<...>",
    "redacted",
})


def _is_allowlisted(value: str) -> bool:
    """True if a candidate match is an obvious non-secret we should keep."""
    v = value.strip()
    if v in _ALLOWLIST_EXACT:
        return True
    low = v.lower()
    if low in _ALLOWLIST_EXACT:
        return True
    return any(token in low for token in _ALLOWLIST_SUBSTRINGS)


# ─── Patterns ────────────────────────────────────────────────────────────────
# Each entry is (category, compiled_regex, replacer). The replacer receives the
# match object and returns the replacement string. Patterns that capture a
# label/prefix (e.g. ``Authorization:``) preserve it and only swap the value so
# the structure of the evidence stays readable.

# A PEM private-key block, header to footer (any key type), DOTALL.
_RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
    r".*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)

# Authorization / Bearer. Matches both header form ("Authorization: Bearer x")
# and a bare "Bearer x" token. Group 1 = the label/scheme to preserve.
_RE_AUTHORIZATION = re.compile(
    r"(Authorization\s*:\s*(?:Bearer\s+|Basic\s+|Token\s+)?|Bearer\s+|Basic\s+)"
    r"[A-Za-z0-9\-._~+/=]{6,}",
    re.IGNORECASE,
)

# Cookie / Set-Cookie header value (rest of the line).
_RE_COOKIE = re.compile(
    r"((?:Set-)?Cookie\s*:\s*)[^\r\n]+",
    re.IGNORECASE,
)

# JWT: three base64url segments separated by dots, first segment starts eyJ.
_RE_JWT = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
)

# AWS access key id (AKIA/ASIA/AGPA/AIDA/AROA + 16 uppercase alnum).
_RE_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b")

# GitHub tokens: ghp_/gho_/ghu_/ghs_/ghr_ + 36+ base62, or fine-grained github_pat_.
_RE_GITHUB_TOKEN = re.compile(
    r"\b(?:gh[poasur]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"
)

# Google API keys: AIza + 35 chars.
_RE_GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")

# Slack tokens: xox[baprs]- followed by token segments.
_RE_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")

# OpenAI-style secret keys: sk- (optionally sk-proj- / sk-ant-) + 20+ chars.
_RE_OPENAI_KEY = re.compile(r"\bsk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{20,}\b")

# Generic api_key / apikey / secret / password / token as a JSON field or
# header value. Group 1 = key + separator (quote/colon/equals) to preserve.
_RE_SECRET_KV = re.compile(
    r"""(["']?(?:api[_-]?key|apikey|secret|secret[_-]?key|password|passwd|pwd|token|access[_-]?token|auth[_-]?token|client[_-]?secret|phpsessid|jsessionid|asp\.net[_-]?sessionid|sessionid|session[_-]?id|session|sid|cookie|csrf[_-]?token|xsrf[_-]?token|connect\.sid)["']?\s*[:=]\s*["']?)"""
    r"""([^"'\s,}&]{4,})""",
    re.IGNORECASE,
)

# Email address.
_RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# IPv4 address (each octet 0-255).
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
)


def _simple_replacer(category: str):
    """Replacer for patterns where the whole match is the secret."""
    placeholder = PLACEHOLDERS[category]

    def repl(m: "re.Match[str]") -> str:
        if _is_allowlisted(m.group(0)):
            return m.group(0)
        return placeholder

    return repl


def _prefixed_replacer(category: str):
    """Replacer for patterns where group(1) is a label to preserve."""
    placeholder = PLACEHOLDERS[category]

    def repl(m: "re.Match[str]") -> str:
        # The secret is everything after the preserved prefix.
        secret = m.group(0)[len(m.group(1)):]
        if _is_allowlisted(secret):
            return m.group(0)
        return m.group(1) + placeholder

    return repl


# (category, regex, replacer) applied in CATEGORIES order.
_RULES: dict[str, tuple["re.Pattern[str]", object]] = {
    "private_key":    (_RE_PRIVATE_KEY,    _simple_replacer("private_key")),
    "authorization":  (_RE_AUTHORIZATION,  _prefixed_replacer("authorization")),
    "cookie":         (_RE_COOKIE,         _prefixed_replacer("cookie")),
    "secret":         (_RE_SECRET_KV,      _prefixed_replacer("secret")),
    "jwt":            (_RE_JWT,            _simple_replacer("jwt")),
    "aws_key":        (_RE_AWS_KEY,        _simple_replacer("aws_key")),
    "github_token":   (_RE_GITHUB_TOKEN,   _simple_replacer("github_token")),
    "google_api_key": (_RE_GOOGLE_API_KEY, _simple_replacer("google_api_key")),
    "slack_token":    (_RE_SLACK_TOKEN,    _simple_replacer("slack_token")),
    "openai_key":     (_RE_OPENAI_KEY,     _simple_replacer("openai_key")),
    "email":          (_RE_EMAIL,          _simple_replacer("email")),
    "ip":             (_RE_IPV4,           _simple_replacer("ip")),
}


# ─── Core API ────────────────────────────────────────────────────────────────

def redact_text(s: str, keep_ips: bool = False) -> str:
    """Redact all known secret/PII categories from a string.

    Args:
        s: Input text (any non-str input is returned unchanged).
        keep_ips: If True, leave IPv4 addresses in place.

    Returns:
        The text with secrets replaced by typed ``[REDACTED:...]`` placeholders.
        Allowlisted obvious non-secrets (EXAMPLE keys, loopback IPs, ``<...>``)
        are left untouched.
    """
    if not isinstance(s, str) or not s:
        return s

    out = s
    for category in CATEGORIES:
        if category == "ip" and keep_ips:
            continue
        pattern, replacer = _RULES[category]
        out = pattern.sub(replacer, out)
    return out


def redaction_report(s: str, keep_ips: bool = False) -> dict[str, int]:
    """Count how many redactions each category would make in ``s``.

    Counts only matches that are NOT allowlisted, so the totals reflect actual
    redactions performed by :func:`redact_text`. The returned dict contains an
    entry for every category (zero when nothing matched).

    Args:
        s: Input text.
        keep_ips: If True, the ``ip`` category is reported as 0 (it is skipped
            during redaction).
    """
    counts: dict[str, int] = {cat: 0 for cat in CATEGORIES}
    if not isinstance(s, str) or not s:
        return counts

    for category in CATEGORIES:
        if category == "ip" and keep_ips:
            continue
        pattern, _ = _RULES[category]
        n = 0
        for m in pattern.finditer(s):
            # Mirror the replacer's allowlist decision so counts match output.
            value = m.group(0)
            if category in ("authorization", "cookie", "secret"):
                value = m.group(0)[len(m.group(1)):]
            if _is_allowlisted(value):
                continue
            n += 1
        counts[category] = n
    return counts


def redact_finding(finding: dict, keep_ips: bool = False) -> dict:
    """Deep-redact every string value in a finding dict.

    Recurses through nested dicts, lists, and tuples. Dict *keys* are left
    untouched (they're field names, not evidence). Never mutates the input —
    returns a fresh, fully redacted copy.

    Args:
        finding: A finding dict (e.g. validation.json payload).
        keep_ips: If True, IPv4 addresses are preserved.

    Returns:
        A deep copy with all string values redacted.
    """
    return _redact_value(finding, keep_ips)


def _redact_value(value, keep_ips: bool):
    """Recursively redact a JSON-like value, returning a copy."""
    if isinstance(value, str):
        return redact_text(value, keep_ips=keep_ips)
    if isinstance(value, dict):
        return {k: _redact_value(v, keep_ips) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v, keep_ips) for v in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(v, keep_ips) for v in value)
    # int / float / bool / None / other — immutable, return as-is.
    return value


# ─── CLI ───────────────────────────────────────────────────────────────────────

def _read_input(path: str) -> str:
    """Read the whole input from a file path or '-' for stdin."""
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Redact secrets and PII from findings before reports/dashboard."
    )
    parser.add_argument(
        "--in",
        dest="input",
        required=True,
        help="Input file path, or '-' to read from stdin.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Treat input as a JSON finding and deep-redact all string values.",
    )
    parser.add_argument(
        "--keep-ips",
        action="store_true",
        help="Do not redact IPv4 addresses (they are not always sensitive).",
    )
    args = parser.parse_args(argv)

    try:
        raw = _read_input(args.input)
    except OSError as exc:
        parser.error(str(exc))

    if args.json:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"ERROR: --json given but input is not valid JSON: {exc}", file=sys.stderr)
            return 1
        redacted = redact_finding(data, keep_ips=args.keep_ips)
        print(json.dumps(redacted, indent=2, sort_keys=True))
        # Report counts from the serialized JSON so nested values are included.
        counts = redaction_report(raw, keep_ips=args.keep_ips)
    else:
        print(redact_text(raw, keep_ips=args.keep_ips))
        counts = redaction_report(raw, keep_ips=args.keep_ips)

    total = sum(counts.values())
    print(f"redaction summary: {total} value(s) redacted", file=sys.stderr)
    for category in CATEGORIES:
        if counts[category]:
            print(f"  {PLACEHOLDERS[category]:<28} {counts[category]}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
