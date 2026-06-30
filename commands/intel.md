---
description: On-demand intelligence fetch for a target — CVEs, disclosed reports, new features. Wraps tools/intel_engine.py (which imports learn.py) + hunt memory context.
argument-hint: <target.com> [--tech <stack>] [--memory-dir <path>]
allowed-tools: Bash
---

# /intel

Fetch actionable intelligence for a target.

## Run This

Invoke `tools/intel_engine.py` directly — do not re-implement the intel logic.
It imports `learn.py` internally for the CVE/advisory feeds and adds the
hunt-memory cross-reference:

```bash
python3 tools/intel_engine.py --target $ARGUMENTS
```

**Pass `--memory-dir` to get the memory cross-reference.** It defaults to empty,
and when empty the "untested CVEs / last hunted / tested endpoints" memory
context is silently skipped — the headline feature does nothing without it:

```bash
python3 tools/intel_engine.py --target target.com \
  --tech "nextjs,graphql" \
  --memory-dir ~/.claude/projects/<proj>/hunt-memory
```

## What This Does

1. Runs `tools/intel_engine.py` (imports `learn.py`) for CVEs and advisories
   matching the target's tech stack
2. Fetches HackerOne Hacktivity for the target (via HackerOne MCP if available)
3. Cross-references with hunt memory (when `--memory-dir` is set) — flags
   untested CVEs and new endpoints
4. Outputs prioritized intel with hunt recommendations

## Usage

```
/intel target.com
/intel target.com --tech "nextjs,graphql" --memory-dir <hunt-memory-path>
```

## Output

```
INTEL: target.com
═══════════════════════════════════════

ALERTS:
[CRITICAL] CVE-2026-XXXX — Next.js middleware bypass (CVSS 9.1)
  target.com runs Next.js 14.2.3 (vulnerable). Patch: 14.2.4.
  → You haven't tested this endpoint yet. Hunt candidate.

[HIGH] New feature detected: /api/v3/billing/invoices
  Not in your tested_endpoints list. 3 new paths.
  → New = unreviewed. Priority hunt target.

[INFO] 2 new disclosed reports on HackerOne for target.com
  → Read for methodology insights before hunting.

MEMORY CONTEXT:
  Last hunted: 2026-03-24 (2 days ago)
  Tech stack: Next.js 14.2.3, GraphQL, PostgreSQL
  Untested CVEs: 1 critical, 0 high
```

## Data Sources

| Source | What | Auth required? |
|---|---|---|
| `learn.py` — NVD | CVEs matching tech stack | No |
| `learn.py` — GitHub Advisory | Security advisories | No |
| `learn.py` — HackerOne Hacktivity | Disclosed reports | No |
| HackerOne MCP (if connected) | Program stats, policy | No (public) |
| Hunt memory | Previously tested endpoints | Local files |
