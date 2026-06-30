#!/usr/bin/env python3
"""
pr_diff_review.py — review ONLY a PR's diff, not the whole repo.

Running a full-tree SAST pass on every PR drowns the author in pre-existing debt:
the scanner re-reports the same hundred legacy findings on every push, the *new*
bug introduced by the diff is buried, and reviewers learn to ignore the bot. This
module flips that around. It asks one question — "what did THIS pull request add or
change, and is any of it dangerous?" — by intersecting the analyzer's findings with
the lines the diff actually touched.

ENGINE-AS-ANALYZER, MODEL-AS-TRIAGE (same split as tools/sast_runner.py):
  This tool is deterministic plumbing. It computes the changed line ranges from
  `git diff`, runs the existing SAST engine over the changed files, and partitions
  the resulting findings into NEW (lands on an added/changed line) vs PRE-EXISTING
  (real, but not introduced by this diff). It does NOT decide exploitability — the
  LLM layer downstream (the diff-aware-pr-reviewer agent / `/pr-review`) triages the
  NEW set, confirms reachability, kills false positives, and posts inline comments.
  Keeping the partition deterministic is what makes the review reproducible.

GRACEFUL DEGRADATION (mirrors tools/sast_runner.py + tools/secrets_hunter.sh):
  Every external dependency is optional and detected before use, never assumed:
    * git absent / not a repo / bad ref  -> functions return empty/typed-empty
      results and the CLI prints a clear label and exits 0. A PR review with no git
      is simply "nothing to review", not a crash.
    * tools/sast_runner is imported DEFENSIVELY (importlib, best-effort). If it (or
      its engine) is unavailable, the SAST pass yields zero findings and the result
      is labeled sast_engine == 'unavailable'. semgrep itself is never required:
      sast_runner already degrades to its own regex fallback, and we surface
      whatever engine it reports.
    * the added-line secret pass is a small built-in regex scan over the diff's
      added lines — pure stdlib, no network, no binary, always available.
  Tests never need semgrep / network / a real remote: they drive the diff parser off
  fixture text and small temp git repos, and force the SAST layer absent.

Importable surface (all logic lives in top-level functions; tests import them):
    changed_files(base_ref, path='.') -> list[str]
        Files changed vs base_ref (git diff --name-only base...HEAD).
    changed_line_ranges(base_ref, path='.') -> dict[str, list[tuple[int, int]]]
        {file: [(start, end), ...]} of ADDED line ranges, parsed from unified hunks.
    filter_to_diff(findings, ranges) -> list[dict]
        Keep only findings whose (path, line) falls inside a changed range.
    scan_added_secrets(base_ref, path='.') -> list[dict]
        Built-in secret regex pass over the diff's ADDED lines only.
    review_pr(base_ref, path='.') -> dict
        {new_findings, preexisting_count, files_changed, ...} — full review.

Helpers that are also importable / unit-testable:
    parse_unified_diff(diff_text) -> dict[str, list[tuple[int, int]]]
    line_in_ranges(line, ranges) -> bool
    is_git_repo(path) -> bool

Normalized finding schema: identical to tools/sast_runner.py (tool, rule_id, path,
line, severity, vuln_class, message, fingerprint). Secret findings from the
added-line pass carry tool='diff-secret-regex' and an `added_line` source marker.

CLI:
    python3 tools/pr_diff_review.py --base <ref> [--path .] [--json]
  --base is the target branch / merge base (e.g. origin/main). Prints a human
  summary (NEW findings first, pre-existing count noted) or, with --json, the raw
  result. Always exits 0 when the review completes — including when git is absent,
  the ref is bad, or no engine is installed.

Python 3, stdlib only (subprocess + re + argparse + json + importlib). semgrep,
playwright, and the network are NEVER required.
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys

# ─── Defensive SAST engine import (best-effort, never fatal) ─────────────────────
# tools/sast_runner.py is the real analyzer. We import it the same defensive way
# dashboard/database.py imports tools/redact.py and secrets_ingest.py imports the
# DB: try the package path, fall back to loading the file directly, and on ANY
# failure degrade to a no-engine stub so this module stays importable and the diff
# parser keeps working. We NEVER import semgrep ourselves — sast_runner shells out
# to it (or uses its own regex fallback) and reports which engine it used.
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_TOOLS_DIR)

_sast = None  # type: ignore[assignment]
try:  # pragma: no cover - exercised indirectly / depends on host layout
    if _TOOLS_DIR not in sys.path:
        sys.path.insert(0, _TOOLS_DIR)
    import sast_runner as _sast  # type: ignore
except Exception:  # noqa: BLE001 - never let an import failure break diff parsing
    try:
        _sast_path = os.path.join(_TOOLS_DIR, "sast_runner.py")
        if os.path.isfile(_sast_path):
            _spec = importlib.util.spec_from_file_location("_ubh_sast_runner", _sast_path)
            if _spec and _spec.loader:
                _mod = importlib.util.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                _sast = _mod
    except Exception:  # noqa: BLE001
        _sast = None


# ─── Added-line secret patterns ──────────────────────────────────────────────────
# High-signal hardcoded-secret patterns, matched ONLY against lines the diff added.
# Deliberately aligned with the secret pattern in tools/sast_runner.py and the regex
# fallback in tools/secrets_hunter.sh so the three stay consistent. This is a safety
# net for credentials a PR introduces inline; it is pure stdlib (no trufflehog, no
# network) and therefore always available.
_SECRET_PATTERNS: list[tuple[str, "re.Pattern[str]", str]] = [
    (
        "generic-credential",
        re.compile(
            r"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|secret[_-]?key|password|passwd|aws_secret_access_key)"
            r"\s*[:=]\s*[\"'][A-Za-z0-9/\+=_\-]{12,}[\"']"
        ),
        "Possible hardcoded secret introduced by this diff — move to a secrets "
        "manager / env var and rotate it.",
    ),
    (
        "aws-access-key-id",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "Possible AWS access key id added in this diff — rotate it and use a role/env var.",
    ),
    (
        "private-key-block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "Private key material added in this diff — never commit private keys; rotate it.",
    ),
    (
        "slack-token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        "Possible Slack token added in this diff — revoke and rotate it.",
    ),
    (
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "Possible Google API key added in this diff — rotate it and restrict the key.",
    ),
]


# ─── git helpers (all degrade gracefully) ────────────────────────────────────────

def _run_git(args: list[str], path: str = ".") -> "subprocess.CompletedProcess[str] | None":
    """Run `git -C <path> <args>` and return the CompletedProcess, or None on failure.

    Never raises: a missing git binary, a non-repo directory, or a non-zero exit
    return None (callers treat that as "nothing to report"). git is invoked as an
    external binary — it is never imported.
    """
    if shutil.which("git") is None:
        return None
    try:
        return subprocess.run(
            ["git", "-C", path, *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:  # pragma: no cover - git on PATH but unexecutable is rare
        return None


def is_git_repo(path: str = ".") -> bool:
    """True if `path` is inside a git work tree (and git is installed)."""
    proc = _run_git(["rev-parse", "--is-inside-work-tree"], path)
    return bool(proc and proc.returncode == 0 and proc.stdout.strip() == "true")


def _ref_exists(base_ref: str, path: str = ".") -> bool:
    """True if `base_ref` resolves to a commit in the repo at `path`."""
    if not base_ref:
        return False
    proc = _run_git(["rev-parse", "--verify", "--quiet", f"{base_ref}^{{commit}}"], path)
    return bool(proc and proc.returncode == 0 and proc.stdout.strip())


# ─── Changed files / line ranges ──────────────────────────────────────────────

def changed_files(base_ref: str, path: str = ".") -> list[str]:
    """List files changed between `base_ref` and HEAD.

    Uses `git diff --name-only base...HEAD` (three-dot: changes on HEAD's side since
    the merge base — exactly the PR's own contribution, ignoring base-branch drift).

    Degrades gracefully: returns [] when git is missing, `path` is not a repo, or
    `base_ref` does not resolve. Deleted files are excluded (nothing to review in a
    file that no longer exists).

    Returns:
        Sorted list of repo-relative file paths the PR added or modified.
    """
    if not is_git_repo(path) or not _ref_exists(base_ref, path):
        return []

    proc = _run_git(
        ["diff", "--name-only", "--diff-filter=d", f"{base_ref}...HEAD"],
        path,
    )
    if proc is None or proc.returncode != 0:
        return []

    files = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return sorted(set(files))


def parse_unified_diff(diff_text: str) -> dict:
    """Parse a unified diff into per-file ADDED line ranges.

    Walks the `+++ b/<path>` headers and `@@ -a,b +c,d @@` hunks, tracking the
    new-file line counter so each consecutive run of added (`+`) lines collapses to a
    single (start, end) range. Context and removed lines advance/skip the counter but
    are not themselves recorded — we only care about lines the diff INTRODUCED, since
    those are the ones a reviewer is accountable for.

    This is a pure text function (no git, no IO), so tests drive it off fixture diff
    strings directly.

    Args:
        diff_text: unified diff text (e.g. `git diff` output).

    Returns:
        {file_path: [(start, end), ...]} with 1-based, inclusive added-line ranges.
        Files with no added lines are omitted.
    """
    ranges: dict[str, list[tuple[int, int]]] = {}
    current_file: str | None = None
    new_lineno = 0
    run_start: int | None = None
    run_end: int | None = None

    def _flush() -> None:
        nonlocal run_start, run_end
        if current_file is not None and run_start is not None and run_end is not None:
            ranges.setdefault(current_file, []).append((run_start, run_end))
        run_start = None
        run_end = None

    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            _flush()
            target = line[4:].strip()
            # Strip the conventional b/ prefix and tab-delimited metadata.
            target = target.split("\t", 1)[0]
            if target == "/dev/null":
                current_file = None
            elif target.startswith("b/"):
                current_file = target[2:]
            else:
                current_file = target
            new_lineno = 0
            continue

        if line.startswith("--- "):
            # Old-file header; nothing to record, but it closes any open run.
            _flush()
            continue

        m = hunk_re.match(line)
        if m:
            _flush()
            new_lineno = int(m.group(1))
            continue

        if current_file is None:
            continue

        # Diff body lines. A leading '\' is the "No newline at end of file" marker.
        if line.startswith("\\"):
            continue
        if line.startswith("+"):
            if run_start is None:
                run_start = new_lineno
            run_end = new_lineno
            new_lineno += 1
        elif line.startswith("-"):
            # Removed line: does not exist in the new file, do not advance new_lineno.
            _flush()
        else:
            # Context line (leading space) or blank: advance the new-file counter.
            _flush()
            new_lineno += 1

    _flush()
    return ranges


def changed_line_ranges(base_ref: str, path: str = ".") -> dict:
    """Compute ADDED line ranges per file for the PR diff vs `base_ref`.

    Runs `git diff base...HEAD` and feeds the unified-diff text to
    parse_unified_diff(). Degrades gracefully to {} when git is missing, `path` is
    not a repo, or `base_ref` does not resolve.

    Returns:
        {file_path: [(start, end), ...]} of 1-based inclusive added-line ranges.
    """
    if not is_git_repo(path) or not _ref_exists(base_ref, path):
        return {}

    proc = _run_git(
        ["diff", "--unified=0", "--diff-filter=d", f"{base_ref}...HEAD"],
        path,
    )
    if proc is None or proc.returncode != 0 or not proc.stdout.strip():
        return {}

    return parse_unified_diff(proc.stdout)


# ─── Finding filtering ──────────────────────────────────────────────────────────

def line_in_ranges(line: int, ranges: list) -> bool:
    """True if a 1-based line number falls within any (start, end) range (inclusive).

    A line of 0 (unknown location) is never considered in range — we cannot claim an
    unlocated finding belongs to the diff.
    """
    if not line:
        return False
    for start, end in ranges:
        if start <= line <= end:
            return True
    return False


def _normalize_path(p: str) -> str:
    """Normalize a finding/diff path for comparison (posix separators, no ./ prefix)."""
    if not p:
        return ""
    p = p.replace(os.sep, "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def filter_to_diff(findings: list, ranges: dict) -> list:
    """Keep only findings whose (path, line) lands inside a changed line range.

    A finding survives iff its file appears in `ranges` AND its line falls within one
    of that file's added ranges. Paths are normalized (posix separators, no leading
    './') on both sides so a finding reported as 'app/x.py' matches a diff range keyed
    'app/x.py'. Findings outside the diff are dropped (they are pre-existing).

    Args:
        findings: normalized finding dicts (sast_runner schema; each has path + line).
        ranges: changed_line_ranges() output {file: [(start, end), ...]}.

    Returns:
        The subset of `findings` introduced by the diff (order preserved).
    """
    if not findings or not ranges:
        return []

    norm_ranges = {_normalize_path(k): v for k, v in ranges.items()}
    kept: list[dict] = []
    for f in findings:
        path = _normalize_path(str(f.get("path", "")))
        if path not in norm_ranges:
            continue
        try:
            line = int(f.get("line", 0) or 0)
        except (TypeError, ValueError):
            line = 0
        if line_in_ranges(line, norm_ranges[path]):
            kept.append(f)
    return kept


# ─── Added-line secret pass ──────────────────────────────────────────────────────

def scan_added_secrets(base_ref: str, path: str = ".") -> list:
    """Regex-scan ONLY the lines this PR added for hardcoded secrets.

    Reads `git diff base...HEAD`, pulls each added (`+`) source line, and matches the
    built-in _SECRET_PATTERNS against it. Restricting to added lines means we flag the
    secret the PR *introduced*, not credentials that were already in the file. Pure
    stdlib + regex — no trufflehog, no network — so this always runs, even when no
    SAST engine is installed.

    The matched value is NOT echoed back (we record only the rule and location), so a
    live secret is never re-emitted into review output. Degrades to [] when git is
    missing / not a repo / bad ref.

    Returns:
        Normalized findings, each tool='diff-secret-regex', vuln_class='secret',
        with a fingerprint and `added_line=True` marker.
    """
    if not is_git_repo(path) or not _ref_exists(base_ref, path):
        return []

    proc = _run_git(["diff", "--unified=0", "--diff-filter=d", f"{base_ref}...HEAD"], path)
    if proc is None or proc.returncode != 0 or not proc.stdout.strip():
        return []

    findings: list[dict] = []
    current_file: str | None = None
    new_lineno = 0
    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

    for line in proc.stdout.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip().split("\t", 1)[0]
            if target == "/dev/null":
                current_file = None
            elif target.startswith("b/"):
                current_file = target[2:]
            else:
                current_file = target
            new_lineno = 0
            continue
        if line.startswith("--- "):
            continue
        m = hunk_re.match(line)
        if m:
            new_lineno = int(m.group(1))
            continue
        if current_file is None or line.startswith("\\"):
            continue

        if line.startswith("+"):
            text = line[1:]
            for rule_suffix, pattern, message in _SECRET_PATTERNS:
                if pattern.search(text):
                    finding = {
                        "tool": "diff-secret-regex",
                        "rule_id": f"diff-secret.{rule_suffix}",
                        "path": _normalize_path(current_file),
                        "line": new_lineno,
                        "severity": "high",
                        "vuln_class": "secret",
                        "message": message,
                        "added_line": True,
                    }
                    finding["fingerprint"] = _fingerprint(finding)
                    findings.append(finding)
            new_lineno += 1
        elif line.startswith("-"):
            # Removed line: not present in the new file, do not advance the counter.
            continue
        else:
            new_lineno += 1

    return findings


def _fingerprint(finding: dict) -> str:
    """Stable dedup key for a finding.

    Delegates to sast_runner.fingerprint when the engine module is importable so PR
    findings share the SAME fingerprint scheme as a full SAST run (path|rule_id|line,
    sha256[:12]) — letting downstream dedup/baseline treat both identically. Falls
    back to a local, identical computation when sast_runner is unavailable.
    """
    if _sast is not None and hasattr(_sast, "fingerprint"):
        try:
            return _sast.fingerprint(finding)
        except Exception:  # noqa: BLE001 - fall through to the local computation
            pass
    import hashlib

    key = "{}|{}|{}".format(
        finding.get("path", ""), finding.get("rule_id", ""), finding.get("line", 0)
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


# ─── SAST over changed files (defensive) ─────────────────────────────────────────

def _run_sast_on_files(files: list, path: str = ".") -> tuple[list, str]:
    """Run the SAST engine over the changed files, degrading if it is unavailable.

    Scans only the files the PR touched (not the whole tree) for speed, then returns
    every finding plus the engine label sast_runner reported. When sast_runner could
    not be imported, returns ([], 'unavailable') — a supported state, not an error.

    Returns:
        (findings, sast_engine_label). Label is sast_runner's engine_used
        ('semgrep' | 'regex-fallback') or 'unavailable'.
    """
    if _sast is None or not hasattr(_sast, "run_sast"):
        return [], "unavailable"

    findings: list[dict] = []
    engine_label = "unavailable"
    for rel in files:
        abspath = rel if os.path.isabs(rel) else os.path.join(path, rel)
        if not os.path.isfile(abspath):
            continue
        try:
            result = _sast.run_sast(abspath)
        except Exception:  # noqa: BLE001 - one bad file must not sink the review
            continue
        engine_label = (result.get("summary") or {}).get("engine_used", engine_label)
        for f in result.get("findings", []):
            # Re-key the finding path to the repo-relative diff path so it lines up
            # with changed_line_ranges (sast_runner reports paths relative to the
            # scanned root, which for a single file is just the basename).
            f = dict(f)
            f["path"] = _normalize_path(rel)
            f["fingerprint"] = _fingerprint(f)
            findings.append(f)

    return findings, engine_label


# ─── Orchestration ──────────────────────────────────────────────────────────────

def review_pr(base_ref: str, path: str = ".") -> dict:
    """Review ONLY the PR diff (changed lines) vs `base_ref`.

    Pipeline:
      1. Resolve the changed files and their added-line ranges from `git diff`.
      2. Run the SAST engine over just those files (defensive import; may be absent).
      3. Partition SAST findings into NEW (on an added line) vs PRE-EXISTING (real,
         but not introduced here — reported only as a count so reviewers can ignore
         legacy debt).
      4. Add a built-in secret regex pass over the diff's added lines (always runs).

    Degrades gracefully end to end: no git / not a repo / bad ref yields an empty,
    clearly-labeled review (status reflects why); a missing SAST engine yields zero
    SAST findings labeled sast_engine == 'unavailable'. The call always succeeds.

    Args:
        base_ref: target branch / merge base to diff against (e.g. 'origin/main').
        path: repo path (default current directory).

    Returns:
        {
          "base_ref": str,
          "status": "ok" | "not-a-git-repo" | "bad-ref" | "git-unavailable",
          "files_changed": [str, ...],
          "new_findings": [ ...findings on added lines + added-line secrets... ],
          "preexisting_count": int,   # SAST findings in changed files but not new lines
          "sast_engine": "semgrep" | "regex-fallback" | "unavailable",
          "summary": {"new": int, "preexisting": int, "files_changed": int,
                      "by_severity": {...}, "by_class": {...}},
        }
    """
    result: dict = {
        "base_ref": base_ref,
        "status": "ok",
        "files_changed": [],
        "new_findings": [],
        "preexisting_count": 0,
        "sast_engine": "unavailable",
    }

    if shutil.which("git") is None:
        result["status"] = "git-unavailable"
        result["summary"] = _summarize([], 0, [])
        return result
    if not is_git_repo(path):
        result["status"] = "not-a-git-repo"
        result["summary"] = _summarize([], 0, [])
        return result
    if not _ref_exists(base_ref, path):
        result["status"] = "bad-ref"
        result["summary"] = _summarize([], 0, [])
        return result

    files = changed_files(base_ref, path)
    ranges = changed_line_ranges(base_ref, path)
    result["files_changed"] = files

    sast_findings, engine_label = _run_sast_on_files(files, path)
    result["sast_engine"] = engine_label

    new_sast = filter_to_diff(sast_findings, ranges)
    new_fingerprints = {f.get("fingerprint") for f in new_sast}
    preexisting = [f for f in sast_findings if f.get("fingerprint") not in new_fingerprints]

    secret_findings = scan_added_secrets(base_ref, path)

    # NEW = SAST hits on added lines + secrets introduced on added lines, deduped by
    # fingerprint so a secret also caught by the engine is not double-counted.
    new_findings: list[dict] = []
    seen: set = set()
    for f in [*new_sast, *secret_findings]:
        fp = f.get("fingerprint")
        if fp in seen:
            continue
        seen.add(fp)
        new_findings.append(f)

    new_findings.sort(key=lambda f: (_severity_rank(f.get("severity", "info")),
                                     f.get("path", ""), f.get("line", 0)))

    result["new_findings"] = new_findings
    result["preexisting_count"] = len(preexisting)
    result["summary"] = _summarize(new_findings, len(preexisting), files)
    return result


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_rank(sev: str) -> int:
    return _SEVERITY_ORDER.get(sev, 99)


def _summarize(new_findings: list, preexisting_count: int, files: list) -> dict:
    by_severity: dict[str, int] = {}
    by_class: dict[str, int] = {}
    for f in new_findings:
        sev = f.get("severity", "info")
        cls = f.get("vuln_class", "other")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_class[cls] = by_class.get(cls, 0) + 1
    return {
        "new": len(new_findings),
        "preexisting": preexisting_count,
        "files_changed": len(files),
        "by_severity": by_severity,
        "by_class": by_class,
    }


# ─── Human-readable rendering ───────────────────────────────────────────────────

def _render_summary(result: dict) -> str:
    lines: list[str] = []
    summary = result["summary"]
    lines.append("=" * 60)
    lines.append("  PR diff review")
    lines.append(f"  Base ref: {result['base_ref']}")
    lines.append(f"  Engine:   {result['sast_engine']}")
    lines.append("=" * 60)

    status = result["status"]
    if status != "ok":
        msg = {
            "git-unavailable": "git is not installed — nothing to review (install git).",
            "not-a-git-repo": "path is not a git repository — nothing to review.",
            "bad-ref": f"base ref '{result['base_ref']}' does not resolve — nothing to review.",
        }.get(status, status)
        lines.append(f"[!] {msg}")
        return "\n".join(lines)

    if result["sast_engine"] == "unavailable":
        lines.append("[!] SAST engine unavailable — only the added-line secret pass ran.")
        lines.append("    Install semgrep for full coverage: pip install semgrep")
    elif result["sast_engine"] == "regex-fallback":
        lines.append("[!] No real SAST engine — sast_runner used its regex fallback.")
        lines.append("    Install semgrep for full coverage: pip install semgrep")

    lines.append(f"Files changed:        {summary['files_changed']}")
    lines.append(f"NEW findings:         {summary['new']}  (introduced by this diff)")
    lines.append(f"Pre-existing (noted): {summary['preexisting']}  (legacy debt, not from this PR)")

    if summary["by_severity"]:
        lines.append("")
        lines.append("--- NEW by severity ---")
        for sev in sorted(summary["by_severity"], key=_severity_rank):
            lines.append(f"  {sev:<9} {summary['by_severity'][sev]}")

    if result["new_findings"]:
        lines.append("")
        lines.append("--- NEW findings (worst first) ---")
        for f in result["new_findings"]:
            loc = f"{f['path']}:{f['line']}" if f.get("line") else f["path"]
            lines.append(
                f"  [{f['severity']:<8}] {f['vuln_class']:<16} {loc}  ({f['rule_id']})"
            )
    else:
        lines.append("")
        lines.append("No new findings on the changed lines.")

    lines.append(
        "\nNote: this is the analyzer partition. The LLM layer triages the NEW set, "
        "confirms reachability, kills false positives, and posts inline comments. "
        "Pre-existing findings are counted, not surfaced, so legacy debt does not "
        "drown this PR's own risk."
    )
    return "\n".join(lines)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Review ONLY a PR's diff (changed lines + the files they live in) instead "
            "of the whole repo. Partitions SAST findings into NEW vs pre-existing and "
            "scans added lines for secrets. Degrades gracefully (no git / no engine = "
            "empty, labeled review, exit 0)."
        )
    )
    parser.add_argument(
        "--base",
        required=True,
        help="Target branch / merge base to diff against (e.g. origin/main, main, a SHA).",
    )
    parser.add_argument("--path", default=".", help="Repo path (default: current directory).")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full result as JSON instead of a human-readable summary.",
    )
    args = parser.parse_args(argv)

    result = review_pr(args.base, args.path)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_render_summary(result))

    # Review completed: exit 0 even with findings and even when git/engine are absent.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
