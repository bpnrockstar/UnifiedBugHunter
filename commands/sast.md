---
description: "Run a deterministic SAST pass over a source tree using a real static analyzer (semgrep) and emit normalized findings with stable fingerprints. This is the engine-driven half of /code-audit — the analyzer finds, the model triages. Degrades to a built-in regex fallback (clearly labeled, still exits 0) when no scanner is installed. Usage: /sast [path] [--engine semgrep|auto] [--diff <base>]"
argument-hint: "[path] [--engine semgrep|auto] [--diff <base>]"
allowed-tools: Bash, Read
---

# /sast — Static Analysis Pass

Run a real static analyzer over a codebase and normalize every hit into one
finding schema with a stable fingerprint for dedup and baselining.

## Run This

Invoke the backing tool directly — do not re-implement the scan inline. The CLI
takes the target as `--path` (the runner has no positional argument), so map the
`[path]` you were given onto `--path`:

```bash
python3 tools/sast_runner.py --path "${1:-.}" "${@:2}"
```

Pass the remaining flags through verbatim — they map straight onto the real CLI:

```bash
python3 tools/sast_runner.py --path <dir> [--engine semgrep|auto] [--config <ruleset>] [--diff <git-base>] [--out <dir>] [--json]
```

- `--engine auto` (default) — semgrep if it is on PATH, else the regex fallback. Always exits 0.
- `--engine semgrep` — forces semgrep; this is the **only** mode where a missing scanner is an error (exit 1).
- `--diff <base>` — git ref to baseline against; only findings new since that ref are reported (semgrep only).
- `--config <ruleset>` — semgrep ruleset (e.g. `auto`, `p/owasp-top-ten`, or a path); ignored by the fallback.
- `--out <dir>` — writes the full result to `<dir>/findings/sast/<timestamp>/sast.json`.
- `--json` — print the raw result JSON instead of the human summary.

A missing `--path` exits 2; a completed scan (including the fallback, including
when findings are present) exits 0.

## The deterministic pass that feeds /code-audit

`/sast` is the **engine** half of source-code auditing; `/code-audit` is the
**model** half. They are designed to run together:

- **`/sast` (this command) — the analyzer.** A real, deterministic SAST tool
  (semgrep) parses the code and produces raw findings. Same code in → same
  findings out, with the same fingerprints. This is reproducible and auditable.
- **`/code-audit` — the triager.** The model reads the source and reasons over
  the engine's output: it clusters, dedupes against the baseline (by
  fingerprint), confirms exploitability, and kills false positives.

The split matters: **the engine finds, the model triages.** Do not ask the model
to *be* the static analyzer — feed it deterministic engine output so its triage
stays reproducible. Run `/sast` first to get the deterministic find set, then
`/code-audit` to triage it into prioritized, PoC-backed findings.

## Normalized finding schema

Every finding — semgrep or regex-fallback — carries the same fields:

| Field | Meaning |
|---|---|
| `tool` | producing engine: `semgrep` or `regex-fallback` |
| `rule_id` | scanner check id (the fallback synthesizes `regex-fallback.<class>`) |
| `path` | file path, relative to the scanned root when possible |
| `line` | 1-based start line (0 when unknown) |
| `severity` | `critical` / `high` / `medium` / `low` / `info` |
| `vuln_class` | sqli, xss, ssrf, cmd-injection, path-traversal, deserialization, ssti, crypto, secret, idor, other |
| `message` | engine description |
| `fingerprint` | stable 12-hex dedup/baseline key — `sha256("{path}\|{rule_id}\|{line}")[:12]` |

The fingerprint deliberately excludes severity, message, and timestamp, so
re-scanning unchanged code yields the same id (good for answering "is this
finding new?"). Distinct hits of one rule in a file stay separate via line.

The result is `{"summary": {by_severity, by_class, total, engine_used}, "findings": [...]}`,
plus `out_path` when `--out` is given.

## Graceful degradation (no scanner installed is a supported state)

If semgrep is not on PATH, `--engine auto` falls back to a built-in regex pass
over `*.py` / `*.js` / `*.go`, tags every hit `tool='regex-fallback'`, sets
`summary.engine_used == 'regex-fallback'`, prints a "no engine installed" banner,
and still exits 0 — mirroring `secrets_hunter.sh` and `cicd_scanner.sh`. The
fallback is coarser than real SAST, so install semgrep for the full ruleset:

```bash
pip install semgrep        # or: brew install semgrep
```

semgrep is invoked as an external binary, never imported, and stays optional.

## Usage

```
/sast                                   # scan the current directory (auto engine)
/sast app/                              # scan a specific path
/sast app/ --engine semgrep             # force semgrep (errors if not installed)
/sast app/ --diff origin/main           # only findings new since origin/main
/sast app/ --config p/owasp-top-ten     # specific semgrep ruleset
/sast app/ --out runs/ --json           # write JSON to runs/findings/sast/<ts>/sast.json
```
