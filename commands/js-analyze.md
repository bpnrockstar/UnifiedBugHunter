---
description: "Recover the ORIGINAL pre-minified source from a live JS bundle and run real analysis over it. Parses the //# sourceMappingURL comment, fetches/loads the .map, extracts sourcesContent into a temp tree (or beautifies the bundle when there is no map), then runs the deterministic SAST engine + a secret-regex pass. Replaces the old curl+grep JS step. Degrades gracefully (requests->urllib, no map->beautify, no semgrep->regex fallback) and always exits 0 on a completed analysis. Usage: /js-analyze <url|file> [--out <dir>] [--json]"
argument-hint: "<url|file> [--out <dir>] [--json]"
allowed-tools: Bash
---

# /js-analyze — Live JS Bundle / Source Map Analysis

Turn a shipped, minified JavaScript bundle back into readable source and analyze
it for real. Most build pipelines ship a `//# sourceMappingURL=...` comment whose
`.map` carries the original pre-minified `sourcesContent` (the actual
TypeScript/ES6 the developers wrote — API routes, auth logic, hardcoded secrets).
This command recovers that, then runs the deterministic SAST engine and a secret
pass over the reconstructed sources. When there is no map, it beautifies the
minified bundle so it is at least analyzable.

This is the **real** replacement for the old "curl the bundle, grep for `api_key`"
step.

## Run This

Invoke the backing tool directly — do not re-implement the recovery or analysis
inline. The CLI takes the bundle as `--bundle` (URL or local file):

```bash
python3 tools/sourcemap_analyzer.py --bundle "$1" "${@:2}"
```

Full CLI:

```bash
python3 tools/sourcemap_analyzer.py --bundle <url|file> [--out <dir>] [--json]
```

- `--bundle <url|file>` (required) — the JS bundle to analyze. An `http(s)` URL is
  fetched (via `requests` if installed, else stdlib `urllib`); a local path is read
  from disk. A missing local file exits 2.
- `--out <dir>` — writes the full result to
  `<dir>/findings/js/<timestamp>/sourcemap_analysis.json`.
- `--json` — print the raw result JSON instead of the human-readable summary.

A completed analysis always exits 0 — including every fallback path and even when
findings are present. Exit is non-zero only on a usage error or when the bundle
itself could not be loaded at all.

## What it does (each step degrades gracefully)

1. Loads the bundle text (URL or file).
2. Finds the `sourceMappingURL` annotation; if present, loads the `.map` and
   extracts `sourcesContent` into a temp source tree
   (`sources_recovered == 'sourcemap'`).
3. If there is no usable map, beautifies the minified bundle and analyzes that
   (`sources_recovered == 'beautified'`) — a real beautifier (`jsbeautifier`) when
   installed, else a built-in line-splitter.
4. Runs `tools/sast_runner.run_sast()` over the recovered tree (which itself
   degrades to its regex fallback when semgrep is absent).
5. Runs a secret-regex pass over the recovered text (AWS / Google / Slack / GitHub
   / Stripe keys, JWTs, private-key blocks, generic assigned secrets; matches are
   redacted).

## Result schema

`analyze_bundle()` returns:

| Field | Meaning |
|---|---|
| `source` | the bundle analyzed (url or file) |
| `sources_recovered` | `sourcemap` / `beautified` / `raw` |
| `sourcemap_url` | resolved `.map` location, when one was found |
| `recovered_count` | number of original source files recovered |
| `sources_dir` | temp tree the sources were written to |
| `sast_findings` | `tools/sast_runner` findings over the tree |
| `sast_engine` | run_sast's `engine_used` (`semgrep` / `regex-fallback` / `unavailable`) |
| `secret_hits` | secret-regex hits: `{type, severity, path, line, match}` (redacted) |
| `out_path` | set when `--out` was given |

## Graceful degradation (every external dependency is optional)

- `requests` absent → stdlib `urllib.request` is used (no third-party import is
  ever required, and no network happens at import time).
- No source map → the bundle is beautified and analyzed instead, clearly labeled.
- semgrep absent → `run_sast()` uses its regex fallback (`engine_used ==
  'regex-fallback'`); install semgrep for full coverage: `pip install semgrep`.
- `jsbeautifier` absent → built-in line-splitter is used; install for real
  beautification: `pip install jsbeautifier`.

This mirrors `tools/sast_runner.py` and `tools/secrets_hunter.sh`: a missing
external engine is a supported state, never an error.

## Importable surface (tests import these directly)

```text
find_sourcemap_url(js_text) -> str | None
load_sourcemap(path_or_url) -> dict
extract_sources(sourcemap) -> dict{path: content}
beautify_js(js_text) -> str
secret_scan(text, path='') -> list[dict]
analyze_bundle(js_path_or_url, out_dir=None) -> dict
```

## Usage

```
/js-analyze https://target.com/static/js/main.abc123.js     # fetch + recover + analyze
/js-analyze https://target.com/static/js/main.js --json     # raw JSON result
/js-analyze ./recon/target/js/app.js --out runs/            # local file, persist result
```

## Where this fits

`/js-analyze` is the recover-and-analyze step for a single bundle; chain it with
`/secrets-hunt --js-bundle <recon-dir>` (trufflehog/noseyparker over many bundles)
and `/code-audit` (model triage of the SAST findings). The engine recovers and
finds; the model triages — confirm whether a recovered "secret" is live and
whether a flagged sink is actually reachable.
