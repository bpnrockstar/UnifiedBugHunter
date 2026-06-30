#!/usr/bin/env python3
"""
secret_validate.py — cross-engine secret RECONCILIATION + liveness VALIDATION + org regexes.

The gap this closes:
  UBH already FINDS secrets three ways (tools/secrets_hunter.sh wraps trufflehog,
  gitleaks and noseyparker; tools/secrets_ingest.py normalises their output into
  the DB). But two things were missing:
    1. RECONCILIATION — when more than one scanner runs, the same leaked key shows
       up two or three times in slightly different shapes. Nothing merged those,
       so the dashboard/dedup pipeline saw duplicates and a hit "verified" by
       trufflehog wasn't credited to the gitleaks/noseyparker copy.
    2. CROSS-ENGINE VALIDATION — only trufflehog actually checks a key against the
       issuer API. gitleaks and noseyparker never verify, and a regex/custom hit
       is never verified at all. There was no keyhacks-style liveness check we
       could run on ANY hit regardless of which engine produced it.
  And separately, no engine knew the ORG's own internal token formats (handled in
  tools/custom_secret_patterns.py).

This module supplies all three as importable, deterministic functions.

GRACEFUL DEGRADATION (mirrors tools/sast_runner.py + tools/secrets_hunter.sh):
  - Absence of `requests` is a normal state, not an error: validate() simply can
    only return "unknown" without it (it never imports requests at module load).
  - validate() makes a NETWORK CALL ONLY when network=True is passed EXPLICITLY.
    The default is network=False -> always returns "unknown" and never touches the
    wire. This is what keeps imports and tests offline: importing this module, and
    every default-arg call, is pure-local. Tests pass network=False (or mock the
    HTTP layer) and never hit a real issuer API.
  - No scanner binary is ever invoked here — reconcile() works purely on already-
    parsed hit lists handed in by the caller (e.g. tools/secrets_ingest.py's
    parsers), so reconcile is engine-agnostic and needs nothing installed.

Importable surface (all logic in top-level functions; tests import them):
    reconcile(hits_lists) -> list[dict]
        Merge + dedup trufflehog/gitleaks/noseyparker hit lists by
        (file, line, normalized_value). Unions the per-engine detector labels,
        and prefers verified=True (a verified copy wins over an unverified one).

    validate(provider, value, *, network=False) -> str
        keyhacks-style liveness check for common providers (aws/github/slack/
        google/stripe). Returns "verified" | "invalid" | "unknown". With the
        default network=False it ALWAYS returns "unknown" and makes no request.

    scan_custom(text) -> list[dict]
        Run the org regexes from tools/custom_secret_patterns.py over `text` and
        return normalized hits (same shape reconcile() consumes).

Normalized hit schema (what reconcile / scan_custom emit and reconcile consumes):
    detectors  list[str]  engine/detector labels, unioned across merged copies
                          (reconcile). scan_custom emits a single-element list.
    provider   str        canonical provider slug for validate() ("aws"/"github"/
                          "slack"/"google"/"stripe"/"" if unknown), inferred from
                          the detector when possible.
    file       str|None   file path the secret was found in.
    line       int|None   1-based line number (None when unknown).
    value      str        the matched secret AS GIVEN (may already be redacted by
                          the upstream parser — see the redaction note below).
    verified   bool       True if ANY merged copy was live-verified.
    severity   str        "critical"|"high"|"medium"|"low" (scan_custom sets it
                          from the pattern; reconcile keeps the max it sees).
    description str        human context line.

REDACTION NOTE:
  This module does NOT redact — it reconciles/validates whatever it is handed and
  the DB layer (tools/redact.py via dashboard.database._scrub) redacts on write,
  exactly like secrets_ingest.py. The dedup key uses a NORMALIZED value (case +
  surrounding quotes/whitespace stripped) so trufflehog's "Raw" and gitleaks'
  "Secret" forms of the same key collapse together. When values are already
  redacted to the same placeholder, file+line still keys them correctly.

CLI:
    python3 tools/secret_validate.py --reconcile <dir>
        Parse trufflehog.jsonl / gitleaks.json / noseyparker.jsonl in <dir>
        (whatever is present), reconcile them, print the merged hits.
    python3 tools/secret_validate.py --scan-custom <file>
        Run the org regexes over <file> and print hits.
    python3 tools/secret_validate.py --validate <provider> <value> [--network]
        keyhacks-style liveness check. Without --network: prints "unknown".

Python 3, stdlib only at import time. `requests` is imported lazily inside the
network branch of validate() and ONLY when network=True, so the module imports
and runs fully offline.
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import json
import os
import re
import sys
from pathlib import Path

# ─── Repo path bootstrap so sibling tools import cleanly under any cwd ──────────
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_TOOLS_DIR)
for _p in (_REPO, _TOOLS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Output filenames written by tools/secrets_hunter.sh (kept in sync with
# tools/secrets_ingest.py so --reconcile reads the same scan-output dir).
TRUFFLEHOG_FILE = "trufflehog.jsonl"
GITLEAKS_FILE = "gitleaks.json"
NOSEYPARKER_FILE = "noseyparker.jsonl"

# Validation verdicts.
VERIFIED = "verified"
INVALID = "invalid"
UNKNOWN = "unknown"

# Providers validate() knows a liveness check for. Anything else -> "unknown".
KNOWN_PROVIDERS = ("aws", "github", "slack", "google", "stripe")

# Severity ranking so reconcile() can keep the worst severity across merged copies.
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ─── Provider inference ─────────────────────────────────────────────────────────

# Detector-label substring -> canonical provider slug. Detector strings differ per
# engine ("AWS", "aws-access-key-id", "AKIA...") so we match case-insensitively on
# substrings. First match wins; ordering puts more specific tokens first.
_PROVIDER_HINTS: list[tuple[str, str]] = [
    ("aws", "aws"),
    ("amazon", "aws"),
    ("akia", "aws"),
    ("github", "github"),
    ("ghp_", "github"),
    ("gho_", "github"),
    ("ghs_", "github"),
    ("slack", "slack"),
    ("xox", "slack"),
    ("stripe", "stripe"),
    ("sk_live", "stripe"),
    ("sk_test", "stripe"),
    ("rk_live", "stripe"),
    ("google", "google"),
    ("gcp", "google"),
    ("aiza", "google"),
]


def infer_provider(detector: str, value: str = "") -> str:
    """Map a detector label (and optionally the value) to a canonical provider slug.

    Args:
        detector: the engine's detector / rule name (e.g. "AWS", "Stripe").
        value: the matched secret; used as a secondary signal (e.g. an "AKIA"
            prefix) when the detector label is generic.

    Returns:
        One of KNOWN_PROVIDERS, or "" when nothing matches.
    """
    haystack = f"{detector or ''} {value or ''}".lower()
    for token, slug in _PROVIDER_HINTS:
        if token in haystack:
            return slug
    return ""


# ─── Value normalization for dedup ──────────────────────────────────────────────

# A value that is just a redaction placeholder (e.g. "[REDACTED:SLACK_TOKEN]")
# carries no comparable secret bytes. One parser may redact (secrets_ingest's
# trufflehog/gitleaks parsers redact at parse time) while another does not (the
# local noseyparker parser keeps the raw snippet), so a redacted copy must NOT be
# treated as a different secret from the raw copy at the same file+line.
_REDACTED_RE = re.compile(r"^\[redacted(?::[a-z0-9_]+)?\]$")


def _is_uncomparable_value(norm_value: str) -> bool:
    """True if a normalized value can't be compared byte-for-byte (redacted/empty)."""
    return not norm_value or bool(_REDACTED_RE.match(norm_value))


def _normalize_value(value) -> str:
    """Normalize a secret string for dedup keying.

    trufflehog ("Raw"), gitleaks ("Secret") and noseyparker ("snippet") report the
    same key in slightly different shapes — surrounding quotes, whitespace, case on
    a hex-ish blob. We strip wrapping quotes/whitespace and lowercase so the three
    copies collapse to one dedup key. Empty / non-str -> "".
    """
    if not isinstance(value, str):
        return ""
    v = value.strip()
    # Strip a single layer of wrapping quotes if present.
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"', "`"):
        v = v[1:-1].strip()
    return v.lower()


def _worst_severity(a: str, b: str) -> str:
    """Return the more severe of two severity labels."""
    if _SEVERITY_ORDER.get(a, 99) <= _SEVERITY_ORDER.get(b, 99):
        return a or b or "medium"
    return b or a or "medium"


# ─── Reconciliation ─────────────────────────────────────────────────────────────

def reconcile(hits_lists) -> list[dict]:
    """Merge + dedup hits from multiple secret scanners into one canonical list.

    Each input list is a sequence of hit dicts (any mix of the shapes produced by
    trufflehog / gitleaks / noseyparker parsers, or this module's scan_custom).
    A hit may use whatever key names its parser emits; the fields we read are:
        detector / detectors / DetectorName / RuleID  -> detector label(s)
        file / File / path                            -> file
        line / Line / StartLine                       -> line
        value / match / Raw / Secret / snippet         -> the secret value
        verified / Verified                           -> liveness flag
        severity                                      -> severity (optional)
        description                                   -> context (optional)

    Dedup identity is (file, line, normalized_value). When two hits share that
    identity they are merged into ONE result:
        - detectors: the UNION of all merged copies' detector labels (sorted).
        - verified:  True if ANY copy was verified (verified wins).
        - severity:  the worst severity seen across copies.
        - provider:  inferred from the first non-empty detector/value.
        - file/line/value/description: taken from the first copy, but a verified
          copy is preferred as the representative so its (often un-redacted-by-
          the-verifier) value/description survives.

    Args:
        hits_lists: an iterable of hit lists (e.g.
            [trufflehog_hits, gitleaks_hits, noseyparker_hits]). A single flat
            list of hits is also accepted and treated as one engine's output.

    Returns:
        A list of merged normalized hit dicts (schema in the module docstring),
        order stable (first-seen dedup key first).
    """
    # Accept either a list-of-lists or a single flat hit list.
    if isinstance(hits_lists, dict):
        hits_lists = [[hits_lists]]
    elif _looks_like_flat_hit_list(hits_lists):
        hits_lists = [hits_lists]

    merged: dict[tuple, dict] = {}
    order: list[tuple] = []
    # Secondary index: (file, line) -> existing dedup keys at that location. Used
    # to reconcile a redacted/empty-valued copy with a raw-valued copy of the same
    # secret (different engines redact differently) when file+line agree.
    by_loc: dict[tuple, list[tuple]] = {}

    for hit_list in hits_lists or []:
        if not hit_list:
            continue
        for raw in hit_list:
            if not isinstance(raw, dict):
                continue
            norm = _coerce_hit(raw)
            nval = _normalize_value(norm["value"])
            key = (norm["file"], norm["line"], nval)

            # If this value is uncomparable (redacted/empty), try to fold it into
            # an existing hit at the same file+line rather than spawning a dup.
            # Likewise, if an existing hit at this file+line is uncomparable, fold
            # this (comparable) one into it. Only collapse when file+line are known.
            if key not in merged and norm["file"] is not None and norm["line"] is not None:
                loc = (norm["file"], norm["line"])
                for existing_key in by_loc.get(loc, []):
                    existing_val = existing_key[2]
                    if _is_uncomparable_value(nval) or _is_uncomparable_value(existing_val):
                        key = existing_key
                        break

            if key not in merged:
                merged[key] = {
                    "detectors": list(norm["detectors"]),
                    "provider": norm["provider"],
                    "file": norm["file"],
                    "line": norm["line"],
                    "value": norm["value"],
                    "verified": norm["verified"],
                    "severity": norm["severity"],
                    "description": norm["description"],
                }
                order.append(key)
                if norm["file"] is not None and norm["line"] is not None:
                    by_loc.setdefault((norm["file"], norm["line"]), []).append(key)
                continue

            cur = merged[key]
            # Union detector labels.
            for d in norm["detectors"]:
                if d not in cur["detectors"]:
                    cur["detectors"].append(d)
            # Worst severity wins.
            cur["severity"] = _worst_severity(cur["severity"], norm["severity"])
            # A verified copy is the better representative: prefer verified=True
            # and adopt that copy's value/description/provider when the current
            # representative was not verified.
            if norm["verified"] and not cur["verified"]:
                cur["verified"] = True
                cur["value"] = norm["value"]
                cur["description"] = norm["description"] or cur["description"]
                cur["provider"] = norm["provider"] or cur["provider"]
            elif norm["verified"]:
                cur["verified"] = True
            # Prefer a comparable (non-redacted) value as the representative so a
            # raw copy's value survives over a redacted one merged into it.
            if _is_uncomparable_value(_normalize_value(cur["value"])) and not _is_uncomparable_value(nval):
                cur["value"] = norm["value"]
            # Backfill provider/description if we still lack them.
            if not cur["provider"] and norm["provider"]:
                cur["provider"] = norm["provider"]
            if not cur["description"] and norm["description"]:
                cur["description"] = norm["description"]

    out = []
    for key in order:
        item = merged[key]
        item["detectors"] = sorted(item["detectors"])
        out.append(item)
    return out


def _looks_like_flat_hit_list(obj) -> bool:
    """True if obj is a flat list of hit dicts (not a list of hit lists)."""
    if not isinstance(obj, (list, tuple)):
        return False
    return any(isinstance(el, dict) for el in obj)


def _coerce_hit(raw: dict) -> dict:
    """Coerce one parser hit dict (any engine's shape) to the normalized schema."""
    # Detector label(s): accept a pre-built list or a single label under several keys.
    detectors_raw = raw.get("detectors")
    if isinstance(detectors_raw, (list, tuple)) and detectors_raw:
        detectors = [str(d) for d in detectors_raw if d]
    else:
        label = (
            raw.get("detector")
            or raw.get("DetectorName")
            or raw.get("DetectorType")
            or raw.get("RuleID")
            or raw.get("Rule")
            or raw.get("rule_id")
            or "secret"
        )
        detectors = [str(label)]

    file = raw.get("file") or raw.get("File") or raw.get("path") or None
    if file is not None:
        file = str(file)

    line = raw.get("line")
    if line is None:
        line = raw.get("Line", raw.get("StartLine"))
    try:
        line = int(line) if line not in (None, "") else None
    except (TypeError, ValueError):
        line = None

    value = (
        raw.get("value")
        or raw.get("match")
        or raw.get("Raw")
        or raw.get("RawV2")
        or raw.get("Secret")
        or raw.get("Match")
        or raw.get("snippet")
        or ""
    )
    value = str(value)

    verified = bool(raw.get("verified", raw.get("Verified", False)))
    severity = str(raw.get("severity") or ("high" if verified else "medium")).lower()
    description = str(raw.get("description") or "")

    provider = infer_provider(detectors[0] if detectors else "", value)

    return {
        "detectors": detectors,
        "provider": provider,
        "file": file,
        "line": line,
        "value": value,
        "verified": verified,
        "severity": severity,
        "description": description,
    }


# ─── Scanner-output parsers (for the --reconcile CLI path) ──────────────────────
# We reuse secrets_ingest's trufflehog/gitleaks parsers when importable (single
# source of truth), and add a noseyparker parser here. Each returns hit dicts in a
# shape reconcile() understands.

def _load_ingest_parsers():
    """Best-effort import of secrets_ingest's parsers; (None, None) if unavailable."""
    try:
        import secrets_ingest  # type: ignore

        return secrets_ingest.parse_trufflehog, secrets_ingest.parse_gitleaks
    except Exception:  # noqa: BLE001 - never let a sibling import break reconcile
        return None, None


def parse_noseyparker(path) -> list[dict]:
    """Parse noseyparker `report --format jsonl` output into normalized hits.

    noseyparker emits one JSON object per line; each has a `rule_name` and a
    `matches` array, where each match carries a `provenance`/`location` block with
    the file path + line and a `snippet` (with a `matching` field). noseyparker
    does NOT live-verify, so `verified` is always False here. Shapes vary across
    versions, so we read defensively and skip anything malformed.
    """
    hits: list[dict] = []
    p = Path(path)
    if not p.is_file():
        return hits
    try:
        text = p.read_text(errors="replace")
    except OSError:
        return hits

    for raw_line in text.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            obj = json.loads(raw_line)
        except (TypeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue

        detector = obj.get("rule_name") or obj.get("rule") or "noseyparker"
        matches = obj.get("matches")
        if not isinstance(matches, list) or not matches:
            # Some report shapes put location/snippet at the top level.
            matches = [obj]

        for m in matches:
            if not isinstance(m, dict):
                continue
            file, line = _noseyparker_location(m)
            value = _noseyparker_snippet(m)
            hits.append(
                {
                    "detector": str(detector),
                    "file": file,
                    "line": line,
                    "value": value,
                    "verified": False,
                }
            )
    return hits


def _noseyparker_location(m: dict):
    """Pull (file, line) out of a noseyparker match block, tolerating shape drift."""
    file = None
    line = None
    # provenance can be a dict or a list of dicts.
    prov = m.get("provenance")
    if isinstance(prov, list):
        prov = prov[0] if prov else None
    if isinstance(prov, dict):
        file = prov.get("path") or prov.get("file") or prov.get("repo_path")
    loc = m.get("location")
    if isinstance(loc, dict):
        file = file or loc.get("path") or loc.get("file")
        src = loc.get("source_span") or loc.get("span") or {}
        if isinstance(src, dict):
            start = src.get("start")
            if isinstance(start, dict):
                line = start.get("line")
            else:
                line = src.get("line")
    file = file or m.get("path") or m.get("file")
    if line is None:
        line = m.get("line")
    try:
        line = int(line) if line not in (None, "") else None
    except (TypeError, ValueError):
        line = None
    return (str(file) if file else None), line


def _noseyparker_snippet(m: dict) -> str:
    """Pull the matched text out of a noseyparker match block."""
    snip = m.get("snippet")
    if isinstance(snip, dict):
        return str(snip.get("matching") or snip.get("text") or snip.get("before") or "")
    if isinstance(snip, str):
        return snip
    return str(m.get("matching") or m.get("match") or "")


def parse_scan_dir(results_dir) -> list[list[dict]]:
    """Parse every scanner-output file present in `results_dir` for reconcile().

    Reads trufflehog.jsonl / gitleaks.json / noseyparker.jsonl (whichever exist)
    using the shared secrets_ingest parsers where available and the local
    noseyparker parser. Missing files yield empty lists, never errors.

    Returns:
        A list of per-engine hit lists, suitable to hand straight to reconcile().
    """
    results_dir = Path(results_dir)
    parse_trufflehog, parse_gitleaks = _load_ingest_parsers()

    th_hits: list[dict] = []
    gl_hits: list[dict] = []
    if parse_trufflehog is not None:
        th_hits = parse_trufflehog(results_dir / TRUFFLEHOG_FILE)
    if parse_gitleaks is not None:
        gl_hits = parse_gitleaks(results_dir / GITLEAKS_FILE)
    np_hits = parse_noseyparker(results_dir / NOSEYPARKER_FILE)

    return [th_hits, gl_hits, np_hits]


# ─── Custom org-pattern scan ──────────────────────────────────────────────────

def _load_custom_patterns() -> list[dict]:
    """Best-effort load of the org pattern specs; [] if the module is unavailable."""
    try:
        import custom_secret_patterns  # type: ignore

        getter = getattr(custom_secret_patterns, "patterns", None)
        if callable(getter):
            specs = getter()
        else:
            specs = getattr(custom_secret_patterns, "CUSTOM_PATTERNS", [])
        return list(specs) if specs else []
    except Exception:  # noqa: BLE001 - missing/broken pattern file must not crash scans
        return []


def scan_custom(text: str) -> list[dict]:
    """Scan `text` for org-specific secrets using tools/custom_secret_patterns.py.

    Compiles each pattern spec's regex (MULTILINE) and reports every match as a
    normalized hit. A spec whose regex fails to compile is skipped (with a stderr
    warning) so one bad custom pattern never sinks the scan. `line` is the 1-based
    line number of the match within `text`.

    Args:
        text: a blob of source / config / response body to scan.

    Returns:
        A list of normalized hit dicts (schema in the module docstring), each with
        a single-element `detectors` list, the matched substring as `value`, and
        the spec's severity/description. verified is always False (this is a
        pattern match, not a liveness check — feed it to validate() for that).
    """
    hits: list[dict] = []
    if not isinstance(text, str) or not text:
        return hits

    for spec in _load_custom_patterns():
        if not isinstance(spec, dict):
            continue
        pattern = spec.get("regex")
        name = str(spec.get("name") or "custom-secret")
        if not pattern:
            continue
        try:
            compiled = re.compile(pattern, re.MULTILINE)
        except re.error as exc:
            print(
                f"WARNING: custom secret pattern '{name}' failed to compile: {exc}",
                file=sys.stderr,
            )
            continue

        group = spec.get("group", 0)
        severity = str(spec.get("severity") or "medium").lower()
        description = str(spec.get("description") or "")

        for match in compiled.finditer(text):
            try:
                value = match.group(group)
            except (IndexError, re.error):
                value = match.group(0)
            if value is None:
                value = match.group(0)
            # 1-based line number of the match start.
            line = text.count("\n", 0, match.start()) + 1
            hits.append(
                {
                    "detectors": [name],
                    "detector": name,
                    "provider": infer_provider(name, value),
                    "file": None,
                    "line": line,
                    "value": value,
                    "verified": False,
                    "severity": severity,
                    "description": description,
                }
            )
    return hits


# ─── keyhacks-style liveness validation ────────────────────────────────────────

# Per-provider liveness probes. Each entry maps a provider slug to a function
# (value) -> (method, url, headers, ok_predicate). The probe is a SINGLE harmless
# read-only request to the issuer's identity/echo endpoint — the same approach
# keyhacks uses. These are only ever called from the network=True branch.
def _probe_aws(value):
    # AWS access key validation requires SigV4 signing of an STS GetCallerIdentity
    # call, which needs the SECRET too — not just the access key id. Without the
    # paired secret we cannot perform a real liveness check, so this is left as a
    # documented stub that the network path treats as "unknown".
    return None


def _probe_github(value):
    return (
        "GET",
        "https://api.github.com/user",
        {"Authorization": f"Bearer {value}", "Accept": "application/vnd.github+json"},
        lambda r: r.status_code == 200,
    )


def _probe_slack(value):
    # Slack auth.test echoes whether the token is live; {"ok": true} == valid.
    return (
        "POST",
        "https://slack.com/api/auth.test",
        {"Authorization": f"Bearer {value}"},
        lambda r: r.status_code == 200 and _json_ok(r),
    )


def _probe_google(value):
    # Google API key liveness via a cheap, key-authenticated endpoint. A 200 means
    # the key is live (even a quota/permission error returns 4xx with a body that
    # is NOT a hard "invalid key", so we treat only 200 as verified).
    return (
        "GET",
        "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + str(value),
        {},
        lambda r: r.status_code == 200,
    )


def _probe_stripe(value):
    # Stripe: a HEAD/GET against the API authenticated with the secret key. 200 =>
    # live key; 401 => revoked/invalid.
    return (
        "GET",
        "https://api.stripe.com/v1/charges?limit=1",
        {"Authorization": f"Bearer {value}"},
        lambda r: r.status_code == 200,
    )


_PROBES = {
    "aws": _probe_aws,
    "github": _probe_github,
    "slack": _probe_slack,
    "google": _probe_google,
    "stripe": _probe_stripe,
}


def _json_ok(resp) -> bool:
    """True if a JSON response body has {"ok": true} (Slack-style)."""
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        return False
    return isinstance(data, dict) and data.get("ok") is True


def validate(provider: str, value: str, *, network: bool = False) -> str:
    """keyhacks-style liveness check for a candidate secret.

    Args:
        provider: provider slug; one of KNOWN_PROVIDERS (case-insensitive). A
            label like "AWS" or "Stripe" is also accepted (lowercased / inferred).
        value: the candidate secret to test.
        network: when False (DEFAULT), NO request is made and the result is always
            "unknown" — this is what keeps imports and tests offline. Set True only
            in an authorized live engagement to actually probe the issuer API.

    Returns:
        "verified" — the issuer API confirmed the key is live.
        "invalid"  — the issuer API rejected the key (e.g. 401/403).
        "unknown"  — not checked: network=False (default), provider unsupported,
                     empty value, no probe available (e.g. AWS without its secret),
                     `requests` not installed, or any network error. NEVER raises.
    """
    slug = (provider or "").strip().lower()
    if slug not in KNOWN_PROVIDERS:
        slug = infer_provider(provider or "", value or "")
    if not slug or slug not in KNOWN_PROVIDERS:
        return UNKNOWN
    if not value or not isinstance(value, str):
        return UNKNOWN

    # Default, import-time, and test path: never touch the network.
    if not network:
        return UNKNOWN

    probe_fn = _PROBES.get(slug)
    if probe_fn is None:
        return UNKNOWN
    probe = probe_fn(value)
    if probe is None:
        # e.g. AWS without the paired secret — can't do a real liveness check.
        return UNKNOWN

    # Lazy import: requests is OPTIONAL and only needed on the live path.
    try:
        import requests  # type: ignore
    except Exception:  # noqa: BLE001 - requests absent => cannot verify
        return UNKNOWN

    method, url, headers, ok_pred = probe
    try:
        resp = requests.request(method, url, headers=headers, timeout=8)
    except Exception:  # noqa: BLE001 - any network failure => unknown, never raise
        return UNKNOWN

    try:
        if ok_pred(resp):
            return VERIFIED
        # A clear auth rejection means the key is dead; other statuses are
        # ambiguous (rate limit, quota, server error) -> unknown rather than a
        # false "invalid".
        if resp.status_code in (401, 403):
            return INVALID
        return UNKNOWN
    except Exception:  # noqa: BLE001
        return UNKNOWN


# ─── Human-readable rendering ───────────────────────────────────────────────────

def _render_hits(hits: list[dict], header: str) -> str:
    lines = ["=" * 60, f"  {header}", "=" * 60, f"Total: {len(hits)}"]
    if hits:
        lines.append("")
        for h in hits:
            loc = h.get("file") or "<unknown>"
            if h.get("line"):
                loc = f"{loc}:{h['line']}"
            dets = ",".join(h.get("detectors") or [h.get("detector", "secret")])
            ver = "VERIFIED" if h.get("verified") else "unverified"
            prov = h.get("provider") or "-"
            lines.append(
                f"  [{h.get('severity', 'medium'):<8}] {ver:<10} provider={prov:<8} "
                f"{loc}  ({dets})"
            )
    return "\n".join(lines)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Cross-engine secret reconciliation, keyhacks-style liveness "
            "validation, and org-specific custom-pattern scanning."
        )
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--reconcile",
        metavar="DIR",
        help="Reconcile trufflehog/gitleaks/noseyparker output in a scan-output dir.",
    )
    group.add_argument(
        "--scan-custom",
        metavar="FILE",
        help="Scan a file with the org regexes in tools/custom_secret_patterns.py.",
    )
    group.add_argument(
        "--validate",
        nargs=2,
        metavar=("PROVIDER", "VALUE"),
        help="keyhacks-style liveness check for PROVIDER (aws/github/slack/google/stripe).",
    )
    parser.add_argument(
        "--network",
        action="store_true",
        help="Allow --validate to make a live request. Without it, validate is offline.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of a human-readable summary.",
    )
    args = parser.parse_args(argv)

    if args.reconcile:
        if not os.path.isdir(args.reconcile):
            print(f"ERROR: not a directory: {args.reconcile}", file=sys.stderr)
            return 2
        hits = reconcile(parse_scan_dir(args.reconcile))
        if args.json:
            print(json.dumps(hits, indent=2, sort_keys=True))
        else:
            print(_render_hits(hits, f"Reconciled secrets · {args.reconcile}"))
        return 0

    if args.scan_custom:
        if not os.path.isfile(args.scan_custom):
            print(f"ERROR: not a file: {args.scan_custom}", file=sys.stderr)
            return 2
        try:
            text = Path(args.scan_custom).read_text(errors="replace")
        except OSError as exc:
            print(f"ERROR: cannot read {args.scan_custom}: {exc}", file=sys.stderr)
            return 2
        hits = scan_custom(text)
        if args.json:
            print(json.dumps(hits, indent=2, sort_keys=True))
        else:
            print(_render_hits(hits, f"Custom org-pattern scan · {args.scan_custom}"))
        return 0

    if args.validate:
        provider, value = args.validate
        verdict = validate(provider, value, network=args.network)
        if args.json:
            print(
                json.dumps(
                    {
                        "provider": provider,
                        "verdict": verdict,
                        "network": bool(args.network),
                    }
                )
            )
        else:
            note = "" if args.network else "  (offline — pass --network for a live check)"
            print(f"{verdict}{note}")
        # Verdict is informational; the scan completed, so exit 0.
        return 0

    return 0  # pragma: no cover - argparse requires one of the group


if __name__ == "__main__":
    sys.exit(main())
