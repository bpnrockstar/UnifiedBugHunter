# Scripts

Utility and orchestration scripts for the Unified Bug Hunter plugin — engagement
runners, installers, CI quality gates, and catalog/index generators.

## Hunt orchestration

| Script | Purpose |
|:---|:---|
| `cbh.py` | Unified Bug Hunter CLI — bridges skill content into a real runner; `recon` / `hunt` / `validate` / `report` subcommands compose the engagement loop. |
| `full_hunt.sh` | End-to-end hunt pipeline orchestrator — runs recon + vuln scan + validation in sequence (`bash full_hunt.sh target.com [OPTIONS]`). |
| `hunt.sh` | Defines a `hunt` shell function that scaffolds a per-target working folder under `~/Targets/` (CLAUDE.md, scope, submissions tracker, findings/evidence folders, notes). |
| `dork_runner.py` | Google dork automation for passive recon on a target (`python3 dork_runner.py -d target.com [-c category] [-o out.txt]`). |

## Install / setup

| Script | Purpose |
|:---|:---|
| `install.sh` | Installs the Unified Bug Hunter bundle into `~/.claude/` for Claude Code (skills, commands, agents); multi-harness aware. |
| `install-community-skills.sh` | OPTIONAL — refreshes the vendored community skills/commands snapshot from upstream. |
| `setup_harness_mcp.py` | Wires your existing Burp MCP server (read from `~/.claude.json`) into other harnesses' configs, backing up each file first. Idempotent. |

## CI / quality gates

| Script | Purpose |
|:---|:---|
| `lint_skills.py` | Quality + safety gate for skills, commands, and agents. Validates frontmatter (valid YAML, no duplicate keys, `name`↔dir match for skills, single-line `description`), checks for leaked frontmatter keys past the fence, balanced code fences, terminal newlines, a hashed client-identifier denylist, and a real-secret scan. Run with no args to lint `skills/**` + `commands/**` + `agents/**`; pass dirs to lint specific skills. Exit 0 = clean, 1 = errors; warnings never fail. Stdlib only. Driven by `.github/workflows/skill-lint.yml`. |
| `gen_skill_catalog.py` | Generates `docs/skills.md` from every skill's frontmatter so the public skill catalog stays in sync with what's on disk. Run after adding/editing skills. |
| `refresh-cve-index.py` | Pulls the CISA KEV catalog, diffs it against the repo's disclosed-reports and `hunt-*` skill content, and surfaces coverage gaps. Runs locally and via the weekly `.github/workflows/cve-refresh.yml` job. |

## Data files

| File | Purpose |
|:---|:---|
| `.identifier-denylist.sha256` | One sha256 hex digest per line (comments with `#`). Each digest is a banned client/engagement identifier shingle; `lint_skills.py` hashes every 1- and 2-word shingle of each linted file and fails on a match. Plaintext names are never stored here. Maintainers may also drop plaintext into a gitignored `.identifier-denylist.local`, which the linter hashes on the fly. |
