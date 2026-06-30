#!/usr/bin/env python3
"""
sca_audit.py — Real software-composition analysis (SCA) over dependency lockfiles.

The legacy "dependency audit" only pretty-printed package.json. This tool does
real SCA: it enumerates lockfiles across ecosystems, runs an installed scanner
(osv-scanner / pip-audit) against them, and normalizes the output into a single
advisory schema with vuln IDs (OSV/GHSA/CVE), severity, and fixed versions.

Graceful degradation (mirrors tools/secrets_hunter.sh + tools/cicd_scanner.sh):
  * If NO scanner binary is on PATH, the tool does NOT crash. It enumerates the
    lockfiles it found, emits a clearly-labelled "no scanner installed" note that
    names what to install, and still exits 0.
  * `osv-scanner` / `pip-audit` are NEVER required for tests. Tests drive the
    importable functions against a committed fixture (tools/fixtures/
    osv_scanner_sample.json) and exercise the no-scanner fallback path.

Design notes:
  * No third-party imports. stdlib + subprocess + json only.
  * All logic lives in importable top-level functions (find_lockfiles,
    detect_scanners, run_osv, normalize, run_sca) so tests can import them.
  * Scanner binaries are only invoked from run_osv()/run_pip_audit(), and only
    after detect_scanners() confirms they exist on PATH.

Lockfile ecosystems detected:
    npm        package-lock.json, yarn.lock, pnpm-lock.yaml
    PyPI       requirements.txt, poetry.lock, Pipfile.lock
    Go         go.sum
    crates.io  Cargo.lock
    RubyGems   Gemfile.lock
    Packagist  composer.lock

Advisory schema (one dict per row returned by normalize() / run_sca()["advisories"]):
    ecosystem      str   OSV ecosystem, e.g. "npm" | "PyPI" | "Go" | "crates.io"
    package        str   package name, e.g. "lodash"
    version        str   installed version from the lockfile, e.g. "4.17.4"
    vuln_id        str   advisory id — CVE preferred, else GHSA, else OSV id
    severity       str   "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"UNKNOWN"
    fixed_version  str   first fixed version if known, else ""
    summary        str   one-line human-readable description

Usage:
  # Auto-detect lockfiles + scanner under a directory, print a table:
  python3 tools/sca_audit.py --path .

  # Restrict to one lockfile, write raw + normalized JSON to a dir:
  python3 tools/sca_audit.py --path . --lockfile package-lock.json --out findings/sca

  # Machine-readable summary + advisories on stdout:
  python3 tools/sca_audit.py --path . --json
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import json
import os
import shutil
import subprocess
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))

# Committed offline fixture so the normalize/run path can be exercised without a
# scanner installed (tests load this directly):
#   tools/fixtures/osv_scanner_sample.json
BUNDLED_OSV_SAMPLE = os.path.join(_TOOLS_DIR, "fixtures", "osv_scanner_sample.json")

# ─── Color codes (respect NO_COLOR / non-TTY) ─────────────────────────────────
_NO_COLOR = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()
RED    = "" if _NO_COLOR else "\033[91m"
YELLOW = "" if _NO_COLOR else "\033[93m"
GREEN  = "" if _NO_COLOR else "\033[92m"
CYAN   = "" if _NO_COLOR else "\033[96m"
BOLD   = "" if _NO_COLOR else "\033[1m"
DIM    = "" if _NO_COLOR else "\033[2m"
RESET  = "" if _NO_COLOR else "\033[0m"

# ─── Lockfile registry ────────────────────────────────────────────────────────
# Maps a lockfile basename to the OSV ecosystem name it represents. Ordered by
# ecosystem so enumeration is deterministic. Ecosystem names match the OSV
# advisory database (https://ossf.github.io/osv-schema/#affectedpackage-field).
LOCKFILES: dict[str, str] = {
    # npm / JavaScript
    "package-lock.json": "npm",
    "yarn.lock":         "npm",
    "pnpm-lock.yaml":    "npm",
    # Python / PyPI
    "requirements.txt":  "PyPI",
    "poetry.lock":       "PyPI",
    "Pipfile.lock":      "PyPI",
    # Go
    "go.sum":            "Go",
    # Rust / crates.io
    "Cargo.lock":        "crates.io",
    # Ruby / RubyGems
    "Gemfile.lock":      "RubyGems",
    # PHP / Packagist
    "composer.lock":     "Packagist",
}

# Directories never worth descending into while hunting for lockfiles.
_SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache", "site-packages",
}

# Scanner binaries we know how to drive, keyed by tool name → ecosystems covered.
# Only osv-scanner is wired into run_sca's normalize path today; pip-audit/npm/
# govulncheck are detected so the no-scanner note can suggest the right install,
# and so callers can branch on availability.
SCANNERS: dict[str, list[str]] = {
    "osv-scanner":  ["npm", "PyPI", "Go", "crates.io", "RubyGems", "Packagist"],
    "pip-audit":    ["PyPI"],
    "npm":          ["npm"],
    "govulncheck":  ["Go"],
}

# CVSS v3 base-score → qualitative severity bands (FIRST.org).
def _band_from_cvss(score: float) -> str:
    if score <= 0.0:
        return "UNKNOWN"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


# GitHub advisory severity words → our normalized bands.
_GHSA_SEVERITY = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
}


# ─── Lockfile discovery ───────────────────────────────────────────────────────

def find_lockfiles(path: str) -> list[dict]:
    """Recursively enumerate dependency lockfiles under ``path``.

    Args:
        path: Directory to walk (a single lockfile path is also accepted).

    Returns:
        A list of ``{"ecosystem": str, "file": str}`` dicts, one per lockfile
        found, with absolute ``file`` paths, sorted by (ecosystem, file) for
        deterministic output. Vendored/cache directories are skipped. Returns
        an empty list when nothing is found or the path does not exist.
    """
    results: list[dict] = []

    if not path:
        return results

    abspath = os.path.abspath(path)

    # Allow passing a single lockfile directly.
    if os.path.isfile(abspath):
        eco = LOCKFILES.get(os.path.basename(abspath))
        if eco:
            results.append({"ecosystem": eco, "file": abspath})
        return results

    if not os.path.isdir(abspath):
        return results

    for root, dirs, files in os.walk(abspath):
        # Prune skip dirs in-place so os.walk does not descend into them.
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        for fname in files:
            eco = LOCKFILES.get(fname)
            if eco:
                results.append({"ecosystem": eco, "file": os.path.join(root, fname)})

    results.sort(key=lambda r: (r["ecosystem"], r["file"]))
    return results


# ─── Scanner detection ────────────────────────────────────────────────────────

def detect_scanners() -> dict:
    """Detect which SCA scanner binaries are available on PATH.

    Never invokes the binaries — uses ``shutil.which`` only, so this is safe to
    call in any environment (CI, tests) without side effects.

    Returns:
        A dict keyed by tool name with::

            {
              "osv-scanner": {"available": bool, "path": str|None,
                              "ecosystems": [...]},
              "pip-audit":   {...}, "npm": {...}, "govulncheck": {...},
            }
    """
    detected: dict = {}
    for tool, ecosystems in SCANNERS.items():
        binpath = shutil.which(tool)
        detected[tool] = {
            "available": binpath is not None,
            "path": binpath,
            "ecosystems": list(ecosystems),
        }
    return detected


def _preferred_scanner(scanners: dict | None = None) -> str | None:
    """Return the name of the best available scanner, or None if none present.

    osv-scanner wins because it is multi-ecosystem and has a stable JSON schema
    that normalize() understands. pip-audit is the documented PyPI-only fallback.
    """
    scanners = scanners if scanners is not None else detect_scanners()
    for tool in ("osv-scanner", "pip-audit"):
        if scanners.get(tool, {}).get("available"):
            return tool
    return None


# ─── Scanner invocation ───────────────────────────────────────────────────────

def run_osv(path: str) -> list[dict]:
    """Run ``osv-scanner`` against ``path`` and return its parsed JSON results.

    Args:
        path: A directory or a single lockfile path to scan.

    Returns:
        The list under the top-level ``results`` key of osv-scanner's JSON
        output (one entry per scanned source). Returns ``[]`` when osv-scanner
        is not installed, produces no output, exits without JSON, or errors —
        callers must treat an empty list as "ran but found nothing / could not
        run". osv-scanner exits non-zero (1) when it *finds* vulnerabilities, so
        a non-zero return code is expected and not treated as failure.
    """
    if shutil.which("osv-scanner") is None:
        return []

    abspath = os.path.abspath(path)
    if os.path.isdir(abspath):
        cmd = ["osv-scanner", "--format", "json", "--recursive", abspath]
    else:
        cmd = ["osv-scanner", "--format", "json", "--lockfile", abspath]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    out = (proc.stdout or "").strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return []
    return _extract_osv_results(data)


def _extract_osv_results(data: dict | list) -> list[dict]:
    """Pull the ``results`` list out of an osv-scanner JSON document."""
    if isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, list):
            return results
    return []


def load_osv_file(path: str) -> list[dict]:
    """Load an osv-scanner JSON file (or the bundled fixture) from disk.

    Lets callers and tests feed committed scanner output through normalize()
    without a scanner installed. Raises ValueError on malformed JSON so the
    failure is loud rather than silently empty.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid OSV JSON in {path}: {exc}") from exc
    return _extract_osv_results(data)


# ─── Normalization ────────────────────────────────────────────────────────────

def _pick_vuln_id(vuln_id: str, aliases: list[str]) -> str:
    """Prefer a CVE id, then a GHSA id, then the raw OSV id."""
    ids = [vuln_id] + [a for a in (aliases or []) if a]
    for candidate in ids:
        if candidate.upper().startswith("CVE-"):
            return candidate
    for candidate in ids:
        if candidate.upper().startswith("GHSA-"):
            return candidate
    return vuln_id


def _fixed_version(vuln: dict, package: str) -> str:
    """Extract the first 'fixed' event from a vuln's affected ranges."""
    for affected in vuln.get("affected", []) or []:
        # Prefer the range that matches this package, but accept any if the
        # affected entry has no package name.
        aff_pkg = (affected.get("package") or {}).get("name", "")
        if aff_pkg and package and aff_pkg != package:
            continue
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return ""


def _severity_for_vuln(vuln: dict, vuln_id: str, groups: list[dict]) -> str:
    """Derive a normalized severity band for one vuln.

    Resolution order:
      1. database_specific.severity (GitHub word: CRITICAL/HIGH/MODERATE/LOW)
      2. the matching osv-scanner group's max_severity (a CVSS base score)
      3. UNKNOWN
    """
    word = (vuln.get("database_specific") or {}).get("severity", "")
    if word:
        mapped = _GHSA_SEVERITY.get(word.upper())
        if mapped:
            return mapped

    # osv-scanner groups carry a max_severity CVSS score; match by id/alias.
    aliases = set(vuln.get("aliases") or [])
    aliases.add(vuln.get("id", ""))
    for group in groups or []:
        group_ids = set(group.get("ids") or []) | set(group.get("aliases") or [])
        if aliases & group_ids:
            raw = group.get("max_severity", "")
            try:
                return _band_from_cvss(float(raw))
            except (TypeError, ValueError):
                pass
    return "UNKNOWN"


def normalize(raw: list[dict]) -> list[dict]:
    """Normalize raw osv-scanner ``results`` into flat advisory rows.

    Args:
        raw: The ``results`` list as returned by run_osv() / load_osv_file().

    Returns:
        A list of advisory dicts (see module docstring for the schema). Rows are
        de-duplicated on (ecosystem, package, version, vuln_id) and sorted by
        severity (most severe first) then package name. Malformed entries are
        skipped rather than raising.
    """
    advisories: list[dict] = []
    seen: set[tuple] = set()

    for result in raw or []:
        if not isinstance(result, dict):
            continue
        for pkg_entry in result.get("packages", []) or []:
            if not isinstance(pkg_entry, dict):
                continue
            pkg = pkg_entry.get("package") or {}
            ecosystem = pkg.get("ecosystem", "") or ""
            package = pkg.get("name", "") or ""
            version = pkg.get("version", "") or ""
            groups = pkg_entry.get("groups", []) or []

            for vuln in pkg_entry.get("vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                osv_id = vuln.get("id", "") or ""
                aliases = vuln.get("aliases", []) or []
                vuln_id = _pick_vuln_id(osv_id, aliases)
                severity = _severity_for_vuln(vuln, vuln_id, groups)
                fixed = _fixed_version(vuln, package)
                summary = (vuln.get("summary") or vuln.get("details") or "").strip()
                # Keep summaries one-line and bounded.
                summary = summary.splitlines()[0][:200] if summary else ""

                key = (ecosystem, package, version, vuln_id)
                if key in seen:
                    continue
                seen.add(key)

                advisories.append({
                    "ecosystem":     ecosystem,
                    "package":       package,
                    "version":       version,
                    "vuln_id":       vuln_id,
                    "severity":      severity,
                    "fixed_version": fixed,
                    "summary":       summary,
                })

    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    advisories.sort(key=lambda a: (_SEV_ORDER.get(a["severity"], 4), a["package"], a["vuln_id"]))
    return advisories


def _summarize(advisories: list[dict]) -> dict:
    """Roll advisory rows up into a counts-by-severity summary block."""
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    packages: set[str] = set()
    for adv in advisories:
        by_severity[adv["severity"]] = by_severity.get(adv["severity"], 0) + 1
        packages.add(f"{adv['ecosystem']}:{adv['package']}")
    return {
        "total_advisories": len(advisories),
        "vulnerable_packages": len(packages),
        "by_severity": by_severity,
    }


# ─── Orchestration ────────────────────────────────────────────────────────────

def run_sca(path: str, *, out_dir: str | None = None) -> dict:
    """Run software-composition analysis under ``path``.

    Enumerates lockfiles, picks the best available scanner, runs it, and
    normalizes the output. Degrades gracefully: with no scanner installed it
    returns the lockfiles it found plus a clearly-labelled note naming what to
    install — it never raises and never requires a scanner.

    Args:
        path: Directory (or single lockfile) to analyze.
        out_dir: Optional directory to write raw + normalized JSON into. Created
            if missing. When None, nothing is written to disk.

    Returns:
        A dict::

            {
              "path": "<abspath scanned>",
              "scanner": "osv-scanner" | "pip-audit" | None,
              "scanner_available": bool,
              "lockfiles": [{"ecosystem","file"}, ...],
              "note": "<human-readable status/degradation note>",
              "summary": {"total_advisories", "vulnerable_packages",
                          "by_severity": {...}},
              "advisories": [ <advisory dict>, ... ],
            }
    """
    abspath = os.path.abspath(path) if path else os.path.abspath(".")
    lockfiles = find_lockfiles(abspath)
    scanners = detect_scanners()
    scanner = _preferred_scanner(scanners)

    advisories: list[dict] = []
    raw: list[dict] = []
    note = ""

    if scanner is None:
        # Graceful degradation: enumerate lockfiles, label clearly, exit clean.
        if lockfiles:
            ecos = sorted({lf["ecosystem"] for lf in lockfiles})
            note = (
                "no scanner installed (install osv-scanner / pip-audit) — "
                f"found {len(lockfiles)} lockfile(s) across {', '.join(ecos)}; "
                "dependency vulnerabilities were NOT checked"
            )
        else:
            note = (
                "no scanner installed (install osv-scanner / pip-audit) and no "
                "lockfiles found under the scanned path"
            )
    elif scanner == "osv-scanner":
        raw = run_osv(abspath)
        advisories = normalize(raw)
        if not lockfiles:
            note = "osv-scanner ran but no recognized lockfiles were found under the path"
        else:
            note = f"osv-scanner scanned {len(lockfiles)} lockfile(s)"
    else:
        # A scanner is present but not wired into the normalize path (e.g. only
        # pip-audit). Label it rather than silently producing nothing.
        note = (
            f"{scanner} detected but the normalized SCA path currently drives "
            "osv-scanner; install osv-scanner for normalized advisories"
        )

    summary = _summarize(advisories)
    result = {
        "path": abspath,
        "scanner": scanner,
        "scanner_available": scanner is not None,
        "lockfiles": lockfiles,
        "note": note,
        "summary": summary,
        "advisories": advisories,
    }

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        if raw:
            with open(os.path.join(out_dir, "osv_raw.json"), "w", encoding="utf-8") as fh:
                json.dump(raw, fh, indent=2)
                fh.write("\n")
        with open(os.path.join(out_dir, "sca_advisories.json"), "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, sort_keys=True)
            fh.write("\n")

    return result


# ─── Rendering ────────────────────────────────────────────────────────────────

def _sev_color(severity: str) -> str:
    if severity in ("CRITICAL", "HIGH"):
        return RED
    if severity == "MEDIUM":
        return YELLOW
    if severity == "LOW":
        return CYAN
    return DIM


def render_table(result: dict) -> str:
    """Render a run_sca() result as a human-readable text report."""
    lines: list[str] = []
    lines.append(f"{BOLD}Software Composition Analysis{RESET}")
    lines.append(f"  Path:    {result['path']}")
    scanner = result.get("scanner")
    if scanner:
        lines.append(f"  Scanner: {GREEN}{scanner}{RESET}")
    else:
        lines.append(f"  Scanner: {YELLOW}none{RESET}")

    lockfiles = result.get("lockfiles", [])
    lines.append(f"  Lockfiles found: {len(lockfiles)}")
    for lf in lockfiles:
        rel = os.path.relpath(lf["file"], result["path"]) if os.path.isdir(result["path"]) else lf["file"]
        lines.append(f"    {DIM}[{lf['ecosystem']}]{RESET} {rel}")

    note = result.get("note")
    if note:
        lines.append("")
        lines.append(f"  {YELLOW}NOTE:{RESET} {note}")

    advisories = result.get("advisories", [])
    summary = result.get("summary", {})
    lines.append("")
    if not advisories:
        if result.get("scanner_available"):
            lines.append(f"  {GREEN}No known vulnerabilities found.{RESET}")
        else:
            lines.append(f"  {DIM}No advisories — scanner was not run (see NOTE).{RESET}")
        return "\n".join(lines)

    by_sev = summary.get("by_severity", {})
    sev_bits = ", ".join(
        f"{_sev_color(s)}{s} {by_sev[s]}{RESET}"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        if by_sev.get(s)
    )
    lines.append(
        f"  {BOLD}{summary.get('total_advisories', 0)} advisorie(s){RESET} "
        f"across {summary.get('vulnerable_packages', 0)} package(s): {sev_bits}"
    )
    lines.append("")
    lines.append(f"  {BOLD}{'SEVERITY':<10} {'PACKAGE':<24} {'VERSION':<12} {'FIXED':<12} VULN ID{RESET}")
    for adv in advisories:
        color = _sev_color(adv["severity"])
        lines.append(
            f"  {color}{adv['severity']:<10}{RESET} "
            f"{adv['package']:<24} {adv['version']:<12} "
            f"{(adv['fixed_version'] or '-'):<12} {adv['vuln_id']}"
        )
        if adv["summary"]:
            lines.append(f"             {DIM}{adv['summary']}{RESET}")
    return "\n".join(lines)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Real software-composition analysis over dependency lockfiles."
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Directory (or single lockfile) to analyze. Default: current dir.",
    )
    parser.add_argument(
        "--lockfile",
        default="auto",
        help=(
            "Restrict the scan to one lockfile basename (e.g. package-lock.json). "
            "Default 'auto' enumerates every supported lockfile under --path."
        ),
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Directory to write raw + normalized JSON output into.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the machine-readable JSON result instead of a table.",
    )
    args = parser.parse_args(argv)

    # Resolve the scan target. With --lockfile <name>, narrow to that single
    # lockfile so run_sca scans exactly it (still degrades gracefully).
    scan_path = args.path
    if args.lockfile and args.lockfile != "auto":
        if os.path.isdir(args.path):
            candidate = os.path.join(args.path, args.lockfile)
        else:
            candidate = args.path
        if not os.path.isfile(candidate):
            print(
                f"{YELLOW}NOTE:{RESET} lockfile '{args.lockfile}' not found under "
                f"{os.path.abspath(args.path)} — falling back to auto-enumeration",
                file=sys.stderr,
            )
        else:
            scan_path = candidate

    result = run_sca(scan_path, out_dir=args.out)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_table(result))
        if args.out:
            print(f"\n  {DIM}JSON written to {os.path.abspath(args.out)}/{RESET}")

    # Graceful-degrade contract: always exit 0, even when no scanner is present
    # or vulnerabilities were found. SCA findings are advisory, not a build gate.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
