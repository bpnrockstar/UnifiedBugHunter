#!/usr/bin/env python3
"""
sast_runner.py — the real SAST engine wiring UBH was missing.

Until now SAST in UBH was two half-measures: `install_tools.sh` only *hinted* that
semgrep should be installed, and `/code-audit` was model-driven (the LLM read the
source and reasoned about it). Neither actually ran a static analyzer. This module
is the missing engine: it shells out to a real SAST tool (semgrep first, with a
detection pass for bandit / njsscan / gosec), parses its JSON, and normalizes every
hit into one finding schema with a stable fingerprint for dedup/baseline.

MODEL-AS-TRIAGE (read this before wiring an LLM in front of it):
  This tool is the ANALYZER, not the triager. The engine (semgrep / the regex
  fallback) produces raw findings; the LLM layer downstream is responsible for
  triage — clustering, deduping against the baseline, confirming exploitability,
  and killing false positives. Do NOT ask the model to *be* the static analyzer;
  ask it to reason over the findings this tool emits. Keeping the analyzer
  deterministic (real tool output + stable fingerprints) is what makes the model's
  triage reproducible and auditable.

GRACEFUL DEGRADATION (mirrors tools/secrets_hunter.sh + tools/cicd_scanner.sh):
  No scanner binary on PATH is a normal, supported state — not an error. When
  semgrep is absent, run_sast() falls back to a small built-in regex pass over
  *.py / *.js / *.go, tags every hit tool='regex-fallback', clearly labels the
  result (summary.engine_used == 'regex-fallback'), and still exits 0. Tests never
  require semgrep / osv-scanner to be installed: they drive the parser off the
  committed fixture (tools/fixtures/semgrep_sample.json) and exercise the fallback
  path directly. semgrep / osv-scanner stay OPTIONAL.

Importable surface (all logic lives in top-level functions; tests import them):
    detect_engines() -> dict[str, bool]
    run_semgrep(path, config='auto', diff_base=None) -> list[dict]
    normalize(raw_semgrep_results) -> list[dict]
    map_rule_to_class(rule_id, message) -> str
    fingerprint(finding) -> str
    regex_fallback(path) -> list[dict]
    run_sast(path, *, engines=None, diff_base=None, out_dir=None) -> dict

Normalized finding schema (every finding — semgrep or regex-fallback — has these):
    tool         str   producing engine: 'semgrep' | 'regex-fallback' (| future)
    rule_id      str   scanner rule / check id (regex-fallback synthesizes one)
    path         str   file path, relative to the scanned root when possible
    line         int   1-based start line (0 when unknown)
    severity     str   normalized: 'critical' | 'high' | 'medium' | 'low' | 'info'
    vuln_class   str   one of VULN_CLASSES (see map_rule_to_class)
    message      str   human-readable description from the engine
    fingerprint  str   stable 12-hex dedup/baseline key (see fingerprint())

Fingerprint scheme:
    fingerprint = sha256("{path}|{rule_id}|{line}").hexdigest()[:12]
  Path + rule + line is intentionally stable across runs and machines: it does NOT
  include severity, message, or a timestamp, so re-scanning the same code yields the
  same id (good for baselining / "is this finding new?"). Two genuinely distinct
  hits of the same rule in one file are kept apart by their line numbers.

CLI:
    python3 tools/sast_runner.py --path <dir> [--engine semgrep|auto]
        [--config <ruleset>] [--diff <git-base>] [--out <dir>] [--json]
  Prints a human-readable summary and, with --out, writes the full result JSON to
  <out>/findings/sast/<timestamp>/sast.json. Always exits 0 when the scan completes
  (including the fallback path); non-zero only on usage / unexpected errors.

Python 3, stdlib only (subprocess + json + argparse + hashlib + re). No third-party
imports anywhere — semgrep is invoked as an external binary, never imported.
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# Engines this module knows how to detect. Only semgrep is wired for execution today;
# the rest are detection-only so detect_engines() can report the host's SAST posture
# (and so a future run_<engine>() can slot in without changing the public surface).
KNOWN_ENGINES = ("semgrep", "bandit", "njsscan", "gosec")

# Canonical vulnerability classes map_rule_to_class() routes to. 'other' is the
# catch-all; every finding carries exactly one of these.
VULN_CLASSES = (
    "sqli",
    "xss",
    "ssrf",
    "cmd-injection",
    "path-traversal",
    "deserialization",
    "ssti",
    "crypto",
    "secret",
    "idor",
    "other",
)

# semgrep severities -> our normalized scale. semgrep emits ERROR/WARNING/INFO; some
# rulesets also carry a CRITICAL. Anything unknown degrades to 'info'.
_SEMGREP_SEVERITY = {
    "CRITICAL": "critical",
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

# Severity ordering for summary sorting / "worst first" display.
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Bundled offline fixture: real `semgrep --json` output, used by tests so the parser
# is exercised without semgrep installed.
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
BUNDLED_SEMGREP_SAMPLE = os.path.join(_TOOLS_DIR, "fixtures", "semgrep_sample.json")


# ─── Engine detection ───────────────────────────────────────────────────────────

def detect_engines() -> dict:
    """Report which known SAST engines are available on PATH.

    Pure PATH probe (shutil.which) — never executes anything. This is the
    detect-step of the graceful-degrade pattern: callers branch on the result
    rather than assuming any binary is present.

    Returns:
        dict mapping each name in KNOWN_ENGINES to a bool, e.g.
        {"semgrep": True, "bandit": False, "njsscan": False, "gosec": False}.
    """
    return {name: shutil.which(name) is not None for name in KNOWN_ENGINES}


# ─── Rule → vuln-class routing ────────────────────────────────────────────────

# Ordered (vuln_class, [substrings]) rules. The haystack is the lowercased
# "rule_id + ' ' + message". First class with any matching substring wins, so more
# specific signals are listed before generic ones. CWE numbers are matched too,
# since semgrep metadata frequently surfaces them in the rule id / message.
_CLASS_RULES: list[tuple[str, list[str]]] = [
    ("sqli", ["sql-injection", "sqli", "sql injection", "rawsql", "raw-query", "cwe-89"]),
    (
        "cmd-injection",
        [
            "command-injection", "command injection", "os command", "os-command",
            "shell=true", "subprocess", "dangerous-subprocess", "os.system",
            "exec(", "child_process", "cwe-78",
        ],
    ),
    (
        "xss",
        [
            "xss", "cross-site-scripting", "cross site scripting",
            "dangerouslysetinnerhtml", "innerhtml", "direct-response-write", "cwe-79",
        ],
    ),
    (
        "ssrf",
        ["ssrf", "server-side-request-forgery", "server-side request forgery", "cwe-918"],
    ),
    (
        "path-traversal",
        [
            "path-traversal", "path traversal", "directory-traversal",
            "directory traversal", "lfi", "file-read", "tainted-path",
            "cwe-22", "cwe-23", "cwe-98",
        ],
    ),
    (
        "deserialization",
        [
            "deserial", "pickle", "unpickle", "yaml.load", "marshal",
            "objectinputstream", "unserialize", "insecure-deserialization", "cwe-502",
        ],
    ),
    (
        "ssti",
        [
            "ssti", "server-side-template", "server side template",
            "template-injection", "template injection", "jinja", "cwe-1336",
        ],
    ),
    (
        "crypto",
        [
            "crypto", "weak-hash", "weak hash", "insecure-hash", "md5", "sha1",
            "des", "ecb", "weak-cipher", "weak-ssl", "insecure-cipher",
            "hardcoded-iv", "static-iv", "cwe-327", "cwe-326", "cwe-328", "cwe-330",
        ],
    ),
    (
        "secret",
        [
            "secret", "hardcoded-credential", "hardcoded credentials",
            "hard-coded", "api-key", "api key", "generic-api-key", "private-key",
            "aws-access", "credentials", "cwe-798", "cwe-259",
        ],
    ),
    (
        "idor",
        ["idor", "insecure-direct-object", "broken-object-level", "bola", "cwe-639"],
    ),
]


def map_rule_to_class(rule_id: str, message: str) -> str:
    """Route a SAST rule id + message to one canonical vuln class.

    Args:
        rule_id: scanner rule / check id (e.g. a semgrep check_id).
        message: the rule's human-readable message.

    Returns:
        One of VULN_CLASSES. 'other' when nothing matches.
    """
    haystack = f"{rule_id or ''} {message or ''}".lower()
    for vuln_class, triggers in _CLASS_RULES:
        if any(trigger in haystack for trigger in triggers):
            return vuln_class
    return "other"


# ─── Fingerprinting ─────────────────────────────────────────────────────────────

def fingerprint(finding: dict) -> str:
    """Stable dedup/baseline key for a finding.

    Hashes "{path}|{rule_id}|{line}" — intentionally NOT severity/message/timestamp,
    so re-scanning unchanged code yields the same id (baseline diffing) while two
    distinct hits of one rule in a file stay separate via their line numbers.

    Returns:
        First 12 hex chars of the SHA-256 digest.
    """
    path = str(finding.get("path", ""))
    rule_id = str(finding.get("rule_id", ""))
    line = finding.get("line", 0)
    key = f"{path}|{rule_id}|{line}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


# ─── semgrep ──────────────────────────────────────────────────────────────────

def run_semgrep(path: str, config: str = "auto", diff_base: str | None = None) -> list[dict]:
    """Run semgrep over `path` and return normalized findings.

    Invokes `semgrep --json` as a subprocess (semgrep is never imported). When
    diff_base is set, scopes the scan to changes since that git ref via semgrep's
    `--baseline-commit`, so CI can surface only newly introduced findings.

    semgrep exits non-zero (1) when it finds something — that is success, not
    failure, so the return code is not treated as an error. A genuinely broken
    invocation (unparseable JSON, missing binary) raises.

    Args:
        path: directory or file to scan.
        config: semgrep ruleset (e.g. 'auto', 'p/owasp-top-ten', or a path).
        diff_base: optional git ref; only findings new since it are returned.

    Returns:
        Normalized findings (see normalize() / the module schema).

    Raises:
        RuntimeError: semgrep is not on PATH, or its output could not be parsed.
    """
    if shutil.which("semgrep") is None:
        raise RuntimeError("semgrep is not installed (not on PATH)")

    cmd = ["semgrep", "--json", "--quiet", "--config", config]
    if diff_base:
        cmd += ["--baseline-commit", diff_base]
    cmd.append(path)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,  # exit 1 == "findings present", handled below
        )
    except OSError as exc:  # pragma: no cover - exercised only with semgrep installed
        raise RuntimeError(f"failed to execute semgrep: {exc}") from exc

    if not proc.stdout.strip():
        # No JSON at all means the run itself failed (bad config, crash, etc.).
        detail = proc.stderr.strip() or f"exit code {proc.returncode}"
        raise RuntimeError(f"semgrep produced no JSON output: {detail}")

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - malformed only on tool bug
        raise RuntimeError(f"could not parse semgrep JSON: {exc}") from exc

    return normalize(raw)


def normalize(raw_semgrep_results: dict | list) -> list[dict]:
    """Normalize raw semgrep `--json` output into the unified finding schema.

    Accepts either the full semgrep envelope ({"results": [...]}) or a bare list of
    result dicts. Each result becomes one finding with every schema field populated
    and a fingerprint attached. Malformed individual results are skipped, not fatal.

    Returns:
        A list of normalized finding dicts (schema in the module docstring).
    """
    if isinstance(raw_semgrep_results, dict):
        results = raw_semgrep_results.get("results", [])
    elif isinstance(raw_semgrep_results, list):
        results = raw_semgrep_results
    else:
        results = []

    findings: list[dict] = []
    for res in results:
        if not isinstance(res, dict):
            continue
        rule_id = str(res.get("check_id", "") or "")
        path = str(res.get("path", "") or "")

        start = res.get("start") or {}
        try:
            line = int(start.get("line", 0) or 0)
        except (TypeError, ValueError):
            line = 0

        extra = res.get("extra") or {}
        message = str(extra.get("message", "") or "").strip()
        sev_raw = str(extra.get("severity", "") or "").upper()
        severity = _SEMGREP_SEVERITY.get(sev_raw, "info")

        finding = {
            "tool": "semgrep",
            "rule_id": rule_id,
            "path": path,
            "line": line,
            "severity": severity,
            "vuln_class": map_rule_to_class(rule_id, message),
            "message": message,
        }
        finding["fingerprint"] = fingerprint(finding)
        findings.append(finding)

    return findings


# ─── Regex fallback (no engine present) ──────────────────────────────────────────

# Built-in sink patterns for when NO scanner binary is installed. Deliberately small
# and high-signal — this is a safety net, not a replacement for semgrep. Each entry:
# (vuln_class, severity, compiled-regex, human message). Matched line-by-line over
# the source files in _FALLBACK_EXTENSIONS.
_FALLBACK_EXTENSIONS = (".py", ".js", ".go")

_FALLBACK_PATTERNS: list[tuple[str, str, "re.Pattern[str]", str]] = [
    (
        "cmd-injection",
        "high",
        re.compile(r"\b(os\.system|subprocess\.(?:call|run|Popen)|exec\.Command|child_process\.exec)\s*\("),
        "Possible OS command execution sink — verify the argument is not attacker-controlled.",
    ),
    (
        "cmd-injection",
        "high",
        re.compile(r"shell\s*=\s*True"),
        "subprocess called with shell=True — command injection risk if input is untrusted.",
    ),
    (
        "deserialization",
        "high",
        re.compile(r"\b(pickle\.loads?|yaml\.load(?!_safe)|marshal\.loads)\s*\("),
        "Unsafe deserialization sink — deserializing untrusted data can lead to RCE.",
    ),
    (
        "sqli",
        "high",
        re.compile(r"(execute|query|raw)\s*\(\s*[\"'].*?(%s|%d|\"\s*\+|'\s*\+|\$\{|f[\"'])"),
        "String-built SQL query — possible SQL injection; use parameterized queries.",
    ),
    (
        "xss",
        "medium",
        re.compile(r"\b(innerHTML|dangerouslySetInnerHTML|document\.write)\b"),
        "Direct HTML sink — possible DOM/reflected XSS if value is user-controlled.",
    ),
    (
        "ssrf",
        "medium",
        re.compile(r"\b(requests\.(?:get|post)|urllib\.request\.urlopen|http\.(?:Get|Post)|fetch)\s*\("),
        "Outbound HTTP call — possible SSRF if the URL is attacker-controlled.",
    ),
    (
        "secret",
        "high",
        re.compile(
            r"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|secret[_-]?key|password|aws_secret_access_key)"
            r"\s*[:=]\s*[\"'][A-Za-z0-9/\+=_\-]{12,}[\"']"
        ),
        "Possible hardcoded secret — move to a secrets manager / env var and rotate it.",
    ),
    (
        "crypto",
        "low",
        re.compile(r"(?i)\b(md5|sha1)\s*\(|hashlib\.(?:md5|sha1)\b|DES\.new\b"),
        "Weak cryptographic primitive — MD5/SHA1/DES are not collision/brute resistant.",
    ),
]


def regex_fallback(path: str) -> list[dict]:
    """Built-in regex sink pass for when NO SAST engine is installed.

    Walks `path` (or scans it directly if it is a single file), matching a small set
    of high-signal sink patterns against *.py / *.js / *.go lines. Every finding is
    tagged tool='regex-fallback' so downstream consumers (and the model triager)
    know this is the degraded path, not a real analyzer. Unreadable files are
    skipped silently.

    Returns:
        Normalized findings (same schema as normalize()), each tool='regex-fallback'.
    """
    findings: list[dict] = []

    if os.path.isfile(path):
        files = [path]
        root_for_rel = os.path.dirname(path) or "."
    else:
        files = []
        root_for_rel = path
        for dirpath, dirnames, filenames in os.walk(path):
            # Skip noise dirs that bloat output and contain vendored code.
            dirnames[:] = [
                d for d in dirnames
                if d not in (".git", "node_modules", "venv", ".venv", "__pycache__", "vendor", "dist", "build")
            ]
            for name in filenames:
                if name.endswith(_FALLBACK_EXTENSIONS):
                    files.append(os.path.join(dirpath, name))

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue

        try:
            rel = os.path.relpath(filepath, root_for_rel)
        except ValueError:  # pragma: no cover - cross-drive paths on Windows
            rel = filepath

        for lineno, text in enumerate(lines, start=1):
            for vuln_class, severity, pattern, message in _FALLBACK_PATTERNS:
                if pattern.search(text):
                    rule_id = f"regex-fallback.{vuln_class}"
                    finding = {
                        "tool": "regex-fallback",
                        "rule_id": rule_id,
                        "path": rel,
                        "line": lineno,
                        "severity": severity,
                        "vuln_class": vuln_class,
                        "message": message,
                    }
                    finding["fingerprint"] = fingerprint(finding)
                    findings.append(finding)

    return findings


# ─── Summary + orchestration ──────────────────────────────────────────────────

def _summarize(findings: list[dict], engine_used: str) -> dict:
    """Roll findings up into the summary block of a run_sast() result."""
    by_severity: dict[str, int] = {}
    by_class: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        cls = f.get("vuln_class", "other")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_class[cls] = by_class.get(cls, 0) + 1
    return {
        "by_severity": by_severity,
        "by_class": by_class,
        "total": len(findings),
        "engine_used": engine_used,
    }


def run_sast(
    path: str,
    *,
    engines: dict | None = None,
    diff_base: str | None = None,
    out_dir: str | None = None,
) -> dict:
    """Run SAST over `path`, degrading gracefully when no engine is installed.

    Uses semgrep when available; otherwise falls back to regex_fallback() and labels
    the result accordingly (summary.engine_used == 'regex-fallback'). Either way the
    call succeeds — absence of a scanner is a supported state, not an error.

    Args:
        path: directory or file to scan.
        engines: optional pre-computed detect_engines() result (injectable for tests
            so they can force the fallback path without touching PATH). When None,
            detect_engines() is called.
        diff_base: optional git ref; passed through to semgrep's baseline diff. The
            regex fallback ignores it (no git awareness) but still scans the path.
        out_dir: when set, the full result is written to
            <out_dir>/findings/sast/<timestamp>/sast.json.

    Returns:
        {"summary": {"by_severity", "by_class", "total", "engine_used"},
         "findings": [ ...normalized findings... ]}
    """
    available = engines if engines is not None else detect_engines()

    findings: list[dict]
    if available.get("semgrep"):
        try:
            findings = run_semgrep(path, diff_base=diff_base)
            engine_used = "semgrep"
        except RuntimeError as exc:
            # semgrep was on PATH but the run itself failed — degrade rather than
            # crash, exactly like the shell wrappers do on tool error.
            print(f"WARNING: semgrep run failed, falling back to regex: {exc}", file=sys.stderr)
            findings = regex_fallback(path)
            engine_used = "regex-fallback"
    else:
        findings = regex_fallback(path)
        engine_used = "regex-fallback"

    # Worst severity first, then by path/line for stable ordering.
    findings.sort(
        key=lambda f: (
            _SEVERITY_ORDER.get(f.get("severity", "info"), 99),
            f.get("path", ""),
            f.get("line", 0),
        )
    )

    result = {"summary": _summarize(findings, engine_used), "findings": findings}

    if out_dir:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        dest_dir = os.path.join(out_dir, "findings", "sast", ts)
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, "sast.json")
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, sort_keys=True)
            fh.write("\n")
        result["out_path"] = dest

    return result


# ─── Human-readable rendering ───────────────────────────────────────────────────

def _render_summary(result: dict, path: str) -> str:
    """Render a run_sast() result as a short human-readable summary block."""
    summary = result["summary"]
    engine = summary["engine_used"]
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("  SAST scan")
    lines.append(f"  Target: {path}")
    lines.append(f"  Engine: {engine}")
    if engine == "regex-fallback":
        lines.append("  [!] No SAST engine installed — built-in regex fallback used.")
        lines.append("      Install semgrep for real coverage: pip install semgrep")
    lines.append("=" * 60)
    lines.append(f"Total findings: {summary['total']}")

    if summary["by_severity"]:
        lines.append("")
        lines.append("--- By severity ---")
        for sev in sorted(summary["by_severity"], key=lambda s: _SEVERITY_ORDER.get(s, 99)):
            lines.append(f"  {sev:<9} {summary['by_severity'][sev]}")

    if summary["by_class"]:
        lines.append("")
        lines.append("--- By class ---")
        for cls, count in sorted(summary["by_class"].items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"  {cls:<18} {count}")

    if result.get("findings"):
        lines.append("")
        lines.append("--- Findings (worst first) ---")
        for f in result["findings"]:
            loc = f"{f['path']}:{f['line']}" if f.get("line") else f["path"]
            lines.append(
                f"  [{f['severity']:<8}] {f['vuln_class']:<16} {loc}  ({f['rule_id']})"
            )

    note = (
        "\nNote: this is the analyzer output. The LLM layer triages, dedupes (by "
        "fingerprint), and confirms exploitability — it is not the analyzer."
    )
    lines.append(note)
    return "\n".join(lines)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run SAST over a source tree. Uses semgrep when installed; degrades to a "
            "built-in regex fallback (clearly labeled) when no engine is present."
        )
    )
    parser.add_argument("--path", required=True, help="Directory or file to scan.")
    parser.add_argument(
        "--engine",
        choices=("semgrep", "auto"),
        default="auto",
        help=(
            "Engine selection. 'auto' (default) uses semgrep if installed else the "
            "regex fallback. 'semgrep' forces semgrep and errors if it is absent."
        ),
    )
    parser.add_argument(
        "--config",
        default="auto",
        help="semgrep ruleset (e.g. 'auto', 'p/owasp-top-ten', or a path). Ignored by the fallback.",
    )
    parser.add_argument(
        "--diff",
        dest="diff_base",
        default=None,
        help="Git ref to baseline against; only findings new since it are reported (semgrep only).",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output root; writes <out>/findings/sast/<ts>/sast.json.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full result as JSON instead of a human-readable summary.",
    )
    args = parser.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"ERROR: path does not exist: {args.path}", file=sys.stderr)
        return 2

    detected = detect_engines()

    # --engine semgrep is the one place absence IS an error (the user demanded it).
    if args.engine == "semgrep" and not detected.get("semgrep"):
        print(
            "ERROR: --engine semgrep requested but semgrep is not installed "
            "(pip install semgrep). Use --engine auto for the regex fallback.",
            file=sys.stderr,
        )
        return 1

    # When --config is non-default and semgrep is available, route through run_semgrep
    # with that config; otherwise the standard run_sast path (auto config) applies.
    if detected.get("semgrep") and args.config != "auto":
        try:
            findings = run_semgrep(args.path, config=args.config, diff_base=args.diff_base)
            findings.sort(
                key=lambda f: (
                    _SEVERITY_ORDER.get(f.get("severity", "info"), 99),
                    f.get("path", ""),
                    f.get("line", 0),
                )
            )
            result = {"summary": _summarize(findings, "semgrep"), "findings": findings}
            if args.out:
                ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                dest_dir = os.path.join(args.out, "findings", "sast", ts)
                os.makedirs(dest_dir, exist_ok=True)
                dest = os.path.join(dest_dir, "sast.json")
                with open(dest, "w", encoding="utf-8") as fh:
                    json.dump(result, fh, indent=2, sort_keys=True)
                    fh.write("\n")
                result["out_path"] = dest
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
    else:
        result = run_sast(args.path, engines=detected, diff_base=args.diff_base, out_dir=args.out)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_render_summary(result, args.path))
        if result.get("out_path"):
            print(f"\nWrote full result -> {result['out_path']}")

    # Scan completed: exit 0 even with findings and even on the fallback path.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
