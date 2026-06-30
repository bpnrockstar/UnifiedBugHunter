---
description: Software-composition analysis of dependency lockfiles — runs osv-scanner/pip-audit when present, normalizes advisories to a severity-ranked table, and degrades gracefully (always exits 0) when no scanner is installed.
argument-hint: "[--path <dir-or-lockfile>] [--lockfile auto|<basename>] [--out <dir>] [--json]"
allowed-tools: Bash, Read
---

## Run This

Wrap `tools/sca_audit.py`, which enumerates dependency lockfiles under a path, runs the best available scanner against them (`osv-scanner` preferred, then `pip-audit`), and normalizes the output into a deduped, most-severe-first advisory table. It is **net-new and complementary to host-level `/scan-cves`**: `/scan-cves` probes a running host for known-CVE templates over the network, whereas `/sca` reads the lockfiles in a checked-out codebase and tells you which pinned dependency versions ship known vulnerabilities — no live target required.

Pass the user's arguments straight through. With no arguments it scans the current directory.

```bash
python3 /Users/bipin/Music/UnifiedBugHunter/tools/sca_audit.py $ARGUMENTS
```

What the flags do:

- `--path <dir-or-lockfile>` (default `.`) — directory to walk for lockfiles, or a single lockfile to analyze.
- `--lockfile auto|<basename>` (default `auto`) — restrict to one lockfile basename (e.g. `package-lock.json`, `requirements.txt`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`). If that basename is not found it warns to stderr and falls back to auto-enumeration.
- `--out <dir>` — write `osv_raw.json` (raw scanner output, when a scan ran) and `sca_advisories.json` (normalized rows) into the directory.
- `--json` — emit the machine-readable result dict instead of the rendered table.

Recognized ecosystems (by lockfile basename): npm, PyPI, Go, crates.io, RubyGems, Packagist.

## Graceful degradation

This command **never blocks** — SCA findings are advisory, not a build gate, so the tool **always exits 0**. When neither `osv-scanner` nor `pip-audit` is installed it still enumerates every lockfile it found and prints the note `no scanner installed (install osv-scanner / pip-audit)` instead of advisories. To get real findings, install a scanner:

```bash
# osv-scanner (covers all ecosystems above)
brew install osv-scanner        # or: go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# pip-audit (Python-only fallback)
pipx install pip-audit
```

## Usage

```bash
# Scan the current checkout
python3 /Users/bipin/Music/UnifiedBugHunter/tools/sca_audit.py

# Scan a specific repo and persist raw + normalized JSON
python3 /Users/bipin/Music/UnifiedBugHunter/tools/sca_audit.py --path ~/src/target-app --out findings/sca

# Just the npm lockfile, machine-readable output
python3 /Users/bipin/Music/UnifiedBugHunter/tools/sca_audit.py --path ~/src/target-app --lockfile package-lock.json --json
```

## After a run

Each advisory row carries `ecosystem`, `package`, `version` (the installed/pinned version), `vuln_id` (CVE preferred, else GHSA), `severity`, `fixed_version`, and a one-line `summary`. The `summary` block totals advisories and vulnerable packages and breaks them down by severity band.

1. Triage CRITICAL/HIGH first; an advisory with a non-empty `fixed_version` is a straight bump — propose the minimal upgrade.
2. Confirm the vulnerable code path is actually reachable before reporting; a vulnerable transitive dep that is never invoked is informational, not a finding.
3. If the note says no scanner is installed, report that as the result — list the lockfiles that *would* be scanned and tell the user which scanner to install rather than implying the codebase is clean.
