#!/usr/bin/env python3
"""
disclosure_miner.py — Ground and evolve the hunt-* skills from REAL disclosed
bug-bounty reports (HackerOne / HuggingFace-style public disclosures).

This is the MECHANISM, not the editor. It reads a disclosure export, classifies
each report into a vuln class, maps that class onto the best-matching hunt-*
skill, extracts cheap signals (techniques, payloads, endpoints) from the report
text, and emits *reviewed proposals* — suggested additions a human (or an
/evolve-skills pass) can fold into a skill. It NEVER auto-edits a SKILL.md;
nothing here writes into skills/. The output is a proposals JSON for review.

It pairs with hunt-memory: hunt-memory captures what we learned hunting our own
targets, while this tool captures what the wider community has already disclosed.
A periodic `/evolve-skills` run feeds fresh disclosures through here so the
hunt-* skills keep absorbing live, real-world technique drift instead of going
stale. The proposals are the diff queue an operator reviews before any skill
text changes.

No network and no LLM calls happen at import time or in tests. The only
filesystem reads are the disclosure file you point it at and the skills/<name>/
SKILL.md frontmatter used for mapping (same minimal stdlib parser style as
skill_router.py).

Usage:
  python3 tools/disclosure_miner.py --input reports.json --out proposals.json
  python3 tools/disclosure_miner.py --input reports.jsonl --out proposals.json --skills-dir skills

Accepted report record schema (flexible — common H1 / HuggingFace disclosure
export fields; all optional except a title or summary to read from):
  {
    "id":        "12345",                 # report id / handle (any scalar)
    "title":     "IDOR on /api/orders",   # report title
    "weakness":  "Insecure Direct Object Reference",  # or "vuln_class"
    "vuln_class":"idor",                  # alternative to "weakness"
    "severity":  "high",                  # critical/high/medium/low/none
    "substate":  "resolved",              # H1 substate (resolved/duplicate/...)
    "summary":   "...",                   # or "description"
    "description":"...",                  # alternative to "summary"
    "endpoint":  "/api/orders/{id}",      # optional
    "payload":   "id=1' OR '1'='1"        # optional
  }
Input may be a JSON array of such records, or JSONL (one record per line).
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import json
import os
import re
import sys

# Repo layout: this file lives in <repo>/tools/, skills live in <repo>/skills/.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_SKILLS_DIR = os.path.join(_REPO, "skills")

# ─── Vuln-class normalization ────────────────────────────────────────────────
# Map a noisy weakness/title string onto one of our canonical classes. The class
# tokens line up with the hunt-* skill family so mapping is a near-direct hop.
# Order matters: more specific patterns are checked before broad fallbacks.
# Each entry: canonical_class -> list of regex-ish substrings (already lowered).
_CLASS_PATTERNS: list[tuple[str, list[str]]] = [
    ("sqli", ["sql injection", "sqli", "blind sql", "sql inject"]),
    ("nosqli", ["nosql", "mongo injection", "nosql injection"]),
    ("xxe", ["xxe", "xml external entity", "xml entity"]),
    ("ssti", ["ssti", "server-side template", "server side template", "template injection"]),
    ("ssrf", ["ssrf", "server-side request forgery", "server side request forgery"]),
    ("rce", ["rce", "remote code execution", "command injection", "os command",
             "code execution", "arbitrary code"]),
    ("deserialization", ["deserialization", "deserialisation", "insecure deserialization",
                         "unsafe deserialization", "object injection"]),
    ("lfi", ["lfi", "local file inclusion", "path traversal", "directory traversal",
             "arbitrary file read", "file inclusion"]),
    ("idor", ["idor", "insecure direct object", "bola", "broken object level",
              "object-level authorization", "object level authorization"]),
    ("xss", ["xss", "cross-site scripting", "cross site scripting",
             "stored xss", "reflected xss", "dom xss", "dom-based"]),
    ("csrf", ["csrf", "cross-site request forgery", "cross site request forgery",
              "xsrf"]),
    ("cors", ["cors", "cross-origin resource sharing", "cross origin resource sharing"]),
    ("open-redirect", ["open redirect", "open-redirect", "unvalidated redirect"]),
    ("ssti", ["ssti"]),
    ("oauth", ["oauth", "openid", "oidc"]),
    ("saml", ["saml"]),
    ("auth-bypass", ["auth bypass", "authentication bypass", "authorization bypass",
                     "broken authentication", "access control", "broken access control",
                     "privilege escalation", "privesc", "bola"]),
    ("ato", ["account takeover", "ato", "account hijack"]),
    ("mfa-bypass", ["mfa bypass", "2fa bypass", "two-factor bypass", "otp bypass"]),
    ("brute-force", ["brute force", "brute-force", "rate limit", "rate-limit",
                     "no rate limiting"]),
    ("race-condition", ["race condition", "race-condition", "toctou"]),
    ("business-logic", ["business logic", "business-logic", "logic flaw",
                        "logic error", "workflow"]),
    ("http-smuggling", ["request smuggling", "http smuggling", "desync",
                        "http desync"]),
    ("cache-poison", ["cache poisoning", "cache-poisoning", "web cache",
                      "cache deception"]),
    ("host-header", ["host header", "host-header"]),
    ("graphql", ["graphql", "introspection", "graphql injection"]),
    ("grpc", ["grpc", "protobuf"]),
    ("websocket", ["websocket", "web socket", "ws://", "wss://"]),
    ("subdomain", ["subdomain takeover", "subdomain-takeover", "dangling dns",
                   "dangling cname"]),
    ("file-upload", ["file upload", "unrestricted upload", "arbitrary file upload",
                     "malicious upload"]),
    ("source-leak", ["source code leak", "source leak", "exposed source",
                     ".git exposure", "git exposure", "information disclosure",
                     "info disclosure", "sensitive data exposure"]),
    ("ldap", ["ldap injection", "ldap"]),
    ("session", ["session fixation", "session hijack", "weak session",
                 "session management"]),
    ("api-misconfig", ["api misconfiguration", "api misconfig", "broken api",
                       "exposed api", "swagger", "api key exposure"]),
    ("cloud-misconfig", ["s3 bucket", "open bucket", "misconfigured bucket",
                         "cloud misconfig", "gcp bucket", "azure blob",
                         "iam misconfig"]),
    ("cicd", ["ci/cd", "cicd", "github actions", "pipeline injection",
              "workflow injection"]),
    ("k8s", ["kubernetes", "k8s", "kubelet", "container escape"]),
    ("llm-ai", ["prompt injection", "llm", "jailbreak", "model extraction",
                "ai safety", "agentic"]),
    ("tls-network", ["tls", "ssl", "weak cipher", "certificate", "heartbleed"]),
    ("ntlm-info", ["ntlm", "smb", "net-ntlm"]),
]

# Canonical class -> default hunt-* skill, used when the keyword scan over
# skills/ comes up empty (e.g. skills dir missing in a test). The keyword scan
# in map_to_skill() takes precedence when it finds a confident hit.
_CLASS_TO_SKILL: dict[str, str] = {
    "sqli": "hunt-sqli",
    "nosqli": "hunt-nosqli",
    "xxe": "hunt-xxe",
    "ssti": "hunt-ssti",
    "ssrf": "hunt-ssrf",
    "rce": "hunt-rce",
    "deserialization": "hunt-deserialization",
    "lfi": "hunt-lfi",
    "idor": "hunt-idor",
    "xss": "hunt-xss",
    "csrf": "hunt-csrf",
    "cors": "hunt-cors",
    "open-redirect": "hunt-open-redirect",
    "oauth": "hunt-oauth",
    "saml": "hunt-saml",
    "auth-bypass": "hunt-auth-bypass",
    "ato": "hunt-ato",
    "mfa-bypass": "hunt-mfa-bypass",
    "brute-force": "hunt-brute-force",
    "race-condition": "hunt-race-condition",
    "business-logic": "hunt-business-logic",
    "http-smuggling": "hunt-http-smuggling",
    "cache-poison": "hunt-cache-poison",
    "host-header": "hunt-host-header",
    "graphql": "hunt-graphql",
    "grpc": "hunt-grpc",
    "websocket": "hunt-websocket",
    "subdomain": "hunt-subdomain",
    "file-upload": "hunt-file-upload",
    "source-leak": "hunt-source-leak",
    "ldap": "hunt-ldap",
    "session": "hunt-session",
    "api-misconfig": "hunt-api-misconfig",
    "cloud-misconfig": "hunt-cloud-misconfig",
    "cicd": "hunt-cicd",
    "k8s": "hunt-k8s",
    "llm-ai": "hunt-llm-ai",
    "tls-network": "hunt-tls-network",
    "ntlm-info": "hunt-ntlm-info",
}

# When nothing matches, propose against the catch-all skill.
_FALLBACK_CLASS = "unknown"
_FALLBACK_SKILL = "hunt-misc"

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with",
    "use", "when", "any", "via", "from", "this", "that", "is", "are", "be",
    "it", "as", "at", "by", "if", "all", "can", "you", "your", "not",
}


def _tokenize(text: str) -> list[str]:
    """Lowercase, split on non-alphanumerics, drop stopwords and 1-char noise."""
    if not text:
        return []
    return [
        tok
        for tok in _TOKEN_RE.findall(text.lower())
        if len(tok) > 1 and tok not in _STOPWORDS
    ]


def _report_text(report: dict) -> str:
    """Concatenate the human-readable fields of a report into one lowercase blob."""
    parts: list[str] = []
    for field in ("title", "weakness", "vuln_class", "summary", "description",
                  "endpoint", "payload"):
        value = report.get(field)
        if value:
            parts.append(str(value))
    return " ".join(parts).lower()


# ─── Loading ──────────────────────────────────────────────────────────────────

def load_reports(path: str) -> list[dict]:
    """Load disclosure reports from a JSON array file or a JSONL file.

    Detection is content-based, not extension-based: the file is parsed as a
    JSON array first; if that fails it falls back to line-by-line JSONL. A JSON
    object at top level is wrapped into a single-element list. Non-dict entries
    and unparseable JSONL lines are skipped silently (counted by mine()'s
    caller via the records it actually receives).

    Args:
        path: Path to a .json (array) or .jsonl (one record per line) file.

    Returns:
        A list of dict records. Returns [] for an empty or unreadable file.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return []

    stripped = raw.strip()
    if not stripped:
        return []

    # Try whole-file JSON first (array or single object).
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        parsed = None

    if parsed is not None:
        if isinstance(parsed, list):
            return [r for r in parsed if isinstance(r, dict)]
        if isinstance(parsed, dict):
            return [parsed]
        return []

    # Fall back to JSONL: parse each non-empty line independently.
    records: list[dict] = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


# ─── Classification ─────────────────────────────────────────────────────────

def classify_report(report: dict) -> str:
    """Normalize a report's weakness/title into a canonical vuln class.

    Checks an explicit ``vuln_class`` first (if it already names one of our
    canonical classes), then scans the ``weakness`` field, then the title and
    summary text, against the ordered pattern table. Returns the first match.

    Args:
        report: A disclosure record (see module docstring schema).

    Returns:
        A canonical class token (e.g. "sqli", "idor", "ssrf") or "unknown"
        when nothing matches. Returns "unknown" for a non-dict / empty record.
    """
    if not isinstance(report, dict) or not report:
        return _FALLBACK_CLASS

    # 1. Honor an explicit vuln_class if it's already canonical.
    explicit = str(report.get("vuln_class", "") or "").strip().lower()
    if explicit:
        # Normalize a couple of common synonyms/separators.
        normalized = explicit.replace("_", "-").replace(" ", "-")
        if normalized in _CLASS_TO_SKILL:
            return normalized
        if explicit in _CLASS_TO_SKILL:
            return explicit

    # 2. Scan weakness field first (most reliable), then full text blob.
    weakness = str(report.get("weakness", "") or "").lower()
    blob = _report_text(report)

    for haystack in (weakness, blob):
        if not haystack:
            continue
        for cls, patterns in _CLASS_PATTERNS:
            for pat in patterns:
                if pat in haystack:
                    return cls

    return _FALLBACK_CLASS


# ─── Skill mapping (keyword scan over skills/, like skill_router) ─────────────

def _parse_frontmatter(text: str) -> dict[str, str]:
    """Parse the leading --- ... --- frontmatter block (top-level keys only).

    Minimal, stdlib-only: handles `key: value` and `key: "quoted value"` on a
    single line, the format every SKILL.md in this repo uses. Returns {} when no
    frontmatter block is present. Mirrors skill_router._parse_frontmatter.
    """
    stripped = text.lstrip()
    if not stripped.startswith("---"):
        return {}

    lines = stripped.splitlines()
    body: list[str] = []
    for line in lines[1:]:
        if line.strip() == "---":
            break
        body.append(line)
    else:
        return {}

    result: dict[str, str] = {}
    for line in body:
        if ":" not in line:
            continue
        if line[:1] in (" ", "\t"):
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            result[key] = value
    return result


def _load_skill_names(skills_dir: str) -> dict[str, dict]:
    """Build {skill_name: {description, keywords}} from skills/<name>/SKILL.md.

    Skills with no readable SKILL.md still register (so a name like hunt-sqli is
    matchable) using just the directory name as the keyword source.
    """
    out: dict[str, dict] = {}
    if not os.path.isdir(skills_dir):
        return out

    for entry in sorted(os.listdir(skills_dir)):
        skill_path = os.path.join(skills_dir, entry)
        if not os.path.isdir(skill_path):
            continue

        name = entry
        description = ""
        md_path = os.path.join(skill_path, "SKILL.md")
        if os.path.isfile(md_path):
            try:
                with open(md_path, "r", encoding="utf-8") as fh:
                    fm = _parse_frontmatter(fh.read())
                name = fm.get("name", "").strip() or entry
                description = fm.get("description", "").strip()
            except OSError:
                name = entry

        keyword_set: set[str] = set()
        keyword_set.update(_tokenize(name))
        keyword_set.update(_tokenize(name.replace("-", " ")))
        keyword_set.update(_tokenize(description))
        out[name] = {"description": description, "keywords": keyword_set}
    return out


def map_to_skill(vuln_class: str, skills_dir: str | None = None) -> str:
    """Map a canonical vuln class onto the best-matching hunt-* skill name.

    Strategy, in order:
      1. If the static _CLASS_TO_SKILL target exists under skills_dir, use it
         (the common, fast path — classes are named to line up with hunt-*).
      2. Otherwise run a keyword scan over the skills index (like skill_router):
         score each skill by class-token overlap with its name/keywords and take
         the best hit.
      3. Fall back to the static target, then to hunt-misc.

    Args:
        vuln_class: Canonical class token from classify_report().
        skills_dir: Directory of skills/<name>/SKILL.md. Defaults to <repo>/skills.
            When the directory is missing, returns the static class->skill target
            (no filesystem dependency in tests).

    Returns:
        A hunt-* skill name (e.g. "hunt-sqli"), or "hunt-misc" as last resort.
    """
    cls = (vuln_class or "").strip().lower() or _FALLBACK_CLASS
    static_target = _CLASS_TO_SKILL.get(cls, _FALLBACK_SKILL)

    base = skills_dir or _DEFAULT_SKILLS_DIR
    skills = _load_skill_names(base)
    if not skills:
        # No index available (e.g. test env) — trust the static map.
        return static_target

    # 1. Fast path: the static target exists on disk.
    if static_target in skills:
        return static_target

    # 2. Keyword scan. Match the class token (and its split parts) against each
    #    skill name and keyword set.
    class_tokens = set(_tokenize(cls) + _tokenize(cls.replace("-", " ")))
    if cls and cls not in class_tokens:
        class_tokens.add(cls)

    best_name = ""
    best_score = 0.0
    for name, meta in skills.items():
        name_lower = name.lower()
        name_tokens = set(_tokenize(name) + _tokenize(name.replace("-", " ")))
        keyword_set = meta.get("keywords") or set()
        score = 0.0
        for tok in class_tokens:
            if tok in name_tokens or tok in name_lower:
                score += 5.0
            elif tok in keyword_set:
                score += 2.0
        # Deterministic tie-break: prefer the lexicographically smaller name.
        if score > best_score or (score == best_score and score > 0 and
                                  (not best_name or name < best_name)):
            best_score = score
            best_name = name

    if best_score > 0 and best_name:
        return best_name

    # 3. Fall back to the static target if it exists, else hunt-misc.
    if static_target in skills:
        return static_target
    if _FALLBACK_SKILL in skills:
        return _FALLBACK_SKILL
    return static_target


# ─── Signal extraction ────────────────────────────────────────────────────────

# Cheap heuristics — substring/regex scans, no parsing of report HTML/markdown.
_ENDPOINT_RE = re.compile(
    r"(?:https?://[^\s\"'<>]+|/[A-Za-z0-9_\-./{}]+(?:/[A-Za-z0-9_\-./{}]+)*)"
)
_TECHNIQUE_HINTS: list[tuple[str, str]] = [
    ("blind", "blind/inference-based exploitation"),
    ("time-based", "time-based detection"),
    ("time based", "time-based detection"),
    ("out-of-band", "out-of-band (OOB) interaction"),
    ("oob", "out-of-band (OOB) interaction"),
    ("oast", "OAST callback"),
    ("collaborator", "Burp Collaborator OOB"),
    ("polyglot", "polyglot payload"),
    ("waf bypass", "WAF bypass"),
    ("bypass", "filter/control bypass"),
    ("chained", "chained with another bug"),
    ("chain", "chained with another bug"),
    ("second-order", "second-order / stored trigger"),
    ("stored", "stored / persistent vector"),
    ("dom", "DOM sink"),
    ("parameter pollution", "HTTP parameter pollution"),
    ("mass assignment", "mass assignment"),
    ("idor", "object-reference substitution"),
    ("race", "race condition / parallel requests"),
    ("uuid", "predictable/guessable identifier"),
    ("sequential id", "sequential identifier enumeration"),
    ("encoding", "encoding/obfuscation"),
    ("unicode", "unicode normalization trick"),
    ("graphql alias", "GraphQL alias batching"),
    ("introspection", "GraphQL introspection"),
]
# Lightweight payload sniffers — markers that strongly suggest exploit syntax.
_PAYLOAD_MARKERS = [
    "<script", "onerror=", "onload=", "javascript:", "alert(", "${", "{{",
    "../", "..%2f", "' or '", "\" or \"", "union select", "; drop", "&&", "||",
    "$(", "`", "<?", "<%", "<!entity", "<!doctype", "file://", "gopher://",
    "dict://", "http://169.254.169.254", "/etc/passwd", "%0d%0a", "%00",
]


def _dedupe_keep_order(items: list[str], limit: int) -> list[str]:
    """Dedupe (case-insensitive) preserving first-seen order, cap at limit."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item.strip())
        if len(out) >= limit:
            break
    return out


def extract_signals(report: dict) -> dict:
    """Pull cheap, reviewable signals out of a report's text.

    Heuristic only — no HTML parsing, no network, no LLM. Designed to surface
    *candidate* techniques/payloads/endpoints for human review, deliberately
    erring toward recall over precision (the operator prunes during review).

    Args:
        report: A disclosure record.

    Returns:
        {"techniques": [...], "payloads": [...], "endpoints": [...]}
        — each a deduped, order-preserving, length-capped list. Empty lists for
        a non-dict / empty record.
    """
    empty = {"techniques": [], "payloads": [], "endpoints": []}
    if not isinstance(report, dict) or not report:
        return empty

    blob = _report_text(report)

    # Techniques: phrase hints in the combined text.
    techniques: list[str] = []
    for needle, label in _TECHNIQUE_HINTS:
        if needle in blob:
            techniques.append(label)

    # Payloads: prefer an explicit payload field, then sniff exploit markers
    # out of summary/description sentences.
    payloads: list[str] = []
    explicit_payload = report.get("payload")
    if explicit_payload:
        payloads.append(str(explicit_payload).strip())

    text_for_payloads = " ".join(
        str(report.get(f, "") or "") for f in ("summary", "description", "title")
    )
    lower_text = text_for_payloads.lower()
    for marker in _PAYLOAD_MARKERS:
        idx = lower_text.find(marker)
        if idx == -1:
            continue
        # Grab a short window around the marker as the candidate payload snippet.
        start = max(0, idx - 10)
        end = min(len(text_for_payloads), idx + 60)
        snippet = text_for_payloads[start:end].strip()
        if snippet:
            payloads.append(snippet)

    # Endpoints: explicit field first, then URL/path-shaped tokens in text.
    endpoints: list[str] = []
    explicit_endpoint = report.get("endpoint")
    if explicit_endpoint:
        endpoints.append(str(explicit_endpoint).strip())
    for field in ("summary", "description", "title"):
        value = str(report.get(field, "") or "")
        if not value:
            continue
        for match in _ENDPOINT_RE.findall(value):
            # Filter trivial single-slash and bare-dot noise.
            if len(match) > 3 and match not in ("...", "../"):
                endpoints.append(match)

    return {
        "techniques": _dedupe_keep_order(techniques, 20),
        "payloads": _dedupe_keep_order(payloads, 15),
        "endpoints": _dedupe_keep_order(endpoints, 15),
    }


# ─── Mining (proposal generation) ─────────────────────────────────────────────

def _suggested_note(report: dict, vuln_class: str, signals: dict) -> str:
    """Compose a short, human-readable proposed note for a skill.

    Reviewed, not authoritative — this is the text an operator weighs before
    folding anything into a SKILL.md.
    """
    source_id = report.get("id")
    title = str(report.get("title", "") or "").strip()
    severity = str(report.get("severity", "") or "").strip().lower()

    head_parts: list[str] = []
    if severity:
        head_parts.append(f"[{severity}]")
    head_parts.append(f"{vuln_class}")
    if title:
        head_parts.append(f"— {title}")
    head = " ".join(head_parts)

    detail_parts: list[str] = []
    techniques = signals.get("techniques") or []
    endpoints = signals.get("endpoints") or []
    if techniques:
        detail_parts.append("techniques: " + ", ".join(techniques[:4]))
    if endpoints:
        detail_parts.append("seen at: " + ", ".join(endpoints[:2]))

    detail = "; ".join(detail_parts)
    src = f" (disclosure {source_id})" if source_id is not None else ""

    if detail:
        return f"{head}: {detail}.{src}"
    return f"{head}.{src}"


def mine(reports: list, skills_dir: str | None = None) -> list[dict]:
    """Turn a list of disclosure reports into reviewed skill proposals.

    Each well-formed report becomes one proposal pairing it with a hunt-* skill
    and the signals worth folding in. Malformed / empty records (non-dict, or no
    title/weakness/summary to read) are skipped — they simply don't produce a
    proposal. No skill files are modified here; this is the proposal queue an
    operator (or /evolve-skills) reviews.

    Args:
        reports: List of disclosure records (typically from load_reports()).
        skills_dir: Optional override for the skills directory.

    Returns:
        A list of proposals, each:
          {
            "skill":         "hunt-idor",
            "vuln_class":    "idor",
            "source_id":     "12345",        # report id, or None
            "signals":       {techniques, payloads, endpoints},
            "suggested_note":"[high] idor — ...",
          }
    """
    proposals: list[dict] = []
    if not reports:
        return proposals

    for report in reports:
        # Skip records that carry nothing readable.
        if not isinstance(report, dict) or not report:
            continue
        if not _report_text(report):
            continue

        vuln_class = classify_report(report)
        skill = map_to_skill(vuln_class, skills_dir)
        signals = extract_signals(report)
        proposals.append(
            {
                "skill": skill,
                "vuln_class": vuln_class,
                "source_id": report.get("id"),
                "signals": signals,
                "suggested_note": _suggested_note(report, vuln_class, signals),
            }
        )

    return proposals


# ─── CLI ────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Mine disclosed bug-bounty reports into reviewed hunt-* skill "
            "proposals (proposes; never auto-edits skills)."
        )
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Disclosure reports file: JSON array or JSONL (one record per line).",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Where to write the proposals JSON.",
    )
    parser.add_argument(
        "--skills-dir",
        default=None,
        help="Override the skills directory (default: <repo>/skills).",
    )
    args = parser.parse_args(argv)

    reports = load_reports(args.input)
    if not reports:
        print(
            f"WARNING: no readable reports in {args.input}",
            file=sys.stderr,
        )

    proposals = mine(reports, skills_dir=args.skills_dir)

    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(proposals, fh, indent=2, sort_keys=True)
            fh.write("\n")
    except OSError as exc:
        parser.error(str(exc))

    # Count how many input records were skipped as malformed/empty.
    skipped = len(reports) - len(proposals)
    skills_touched = sorted({p["skill"] for p in proposals})

    print(
        f"{len(reports)} reports -> {len(proposals)} proposals "
        f"across {len(skills_touched)} skills"
        + (f" ({skipped} skipped)" if skipped else "")
    )
    if skills_touched:
        print("Skills: " + ", ".join(skills_touched))
    print(f"Wrote {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
