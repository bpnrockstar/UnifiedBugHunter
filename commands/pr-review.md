---
description: "Review ONLY a pull/merge request's diff (the lines it changed, plus the files they live in) instead of the whole repo, so the bug this PR introduced is not buried under pre-existing legacy debt. Runs tools/pr_diff_review.py to partition findings into NEW (on added lines) vs pre-existing, scans added lines for secrets, then triages the NEW set and posts inline comments via code-review --comment. Degrades gracefully (no git / bad ref / no engine = empty, labeled review, exit 0). Usage: /pr-review --base <target-branch> [--path .] [--json]"
argument-hint: "--base <target-branch> [--path .] [--json]"
allowed-tools: Bash, Read
---

# /pr-review — Diff-Scoped PR Security Review

Review a pull/merge request by its **diff**, not the whole repository. The question
is narrow on purpose: *what did THIS PR add or change, and is any of it dangerous?*
A full-tree scan re-reports the same legacy findings on every push and buries the
one real bug the diff introduced — this command does the opposite.

## Run This

Invoke the backing tool directly — do not re-implement the diff/scan inline. `--base`
is the PR's target branch / merge base (e.g. `origin/main`, `main`, or a SHA):

```bash
python3 tools/pr_diff_review.py --base "${1:-origin/main}" "${@:2}"
```

Full CLI (flags map straight onto the tool):

```bash
python3 tools/pr_diff_review.py --base <target-branch> [--path .] [--json]
```

- `--base <ref>` (required) — target branch / merge base to diff against.
- `--path .` — repo path (default: current directory).
- `--json` — print the full result JSON instead of the human-readable summary.

A completed review always exits 0 — including when git is missing, the base ref does
not resolve, or no SAST engine is installed.

## What it computes (the deterministic partition)

`/pr-review` is the **engine** half; the model is the **triage** half — the same
split as `/sast` ↔ `/code-audit`. The tool:

1. Resolves changed files + added-line ranges from `git diff <base>...HEAD`
   (three-dot: HEAD's own contribution, ignoring base-branch drift).
2. Runs `tools/sast_runner` over **just the changed files** (defensive import; the
   engine is optional).
3. Partitions SAST findings into **NEW** (on an added/changed line) vs
   **pre-existing** (real, but not introduced by this PR — reported only as a count).
4. Adds a built-in **secret regex pass over the added lines** (pure stdlib, always
   runs).

Result shape:

```json
{
  "base_ref": "...", "status": "ok",
  "files_changed": ["..."],
  "new_findings": [ /* SAST hits on added lines + added-line secrets */ ],
  "preexisting_count": 0,
  "sast_engine": "semgrep | regex-fallback | unavailable",
  "summary": { "new": 0, "preexisting": 0, "files_changed": 0,
               "by_severity": {}, "by_class": {} }
}
```

`new_findings` use the same normalized schema as `/sast` (tool, rule_id, path, line,
severity, vuln_class, message, fingerprint), so they dedup/baseline identically.
Added-line secrets carry `tool='diff-secret-regex'` and never echo the secret value.

## After the scan — triage and comment

Then reason over the NEW set (this is the model's job, not the analyzer's):

- Open each `new_findings` entry at `path:line`, confirm the changed line is a real,
  reachable source→sink path, and **kill false positives**. Do not pad the review
  with pattern matches on constants or test fixtures.
- Treat any `diff-secret-regex` hit as high priority: remove it from the diff and
  rotate the credential. Reference it by `file:line` only.
- Keep `preexisting_count` out of the verdict — mention it so the author knows legacy
  debt exists, but judge the PR on what it changed. For a full audit, use `/code-audit`.
- Post the triaged findings as inline PR comments through the existing path:

```bash
/code-review --comment
```

For a hands-off pass, hand the whole job to the `diff-aware-pr-reviewer` agent, which
runs this tool, triages the NEW set, and posts inline comments.

## Graceful degradation (every dependency is optional)

Mirrors `sast_runner.py` and `secrets_hunter.sh` — absence is a supported state, not
an error:

- **git missing / not a repo / bad base ref** → empty, clearly-labeled review
  (`status` says why), exit 0.
- **SAST engine unavailable** → `sast_engine == 'unavailable'`; only the added-line
  secret pass runs (it is pure stdlib). semgrep is invoked by `sast_runner` as an
  external binary, never imported, and stays optional — install it for deeper
  coverage:

```bash
pip install semgrep        # or: brew install semgrep
```

No network and no live targets are ever used — this is source-only review.

## Usage

```
/pr-review --base origin/main                 # review this branch's diff vs origin/main
/pr-review --base main --path ../service       # review a repo checked out elsewhere
/pr-review --base 1a2b3c4 --json               # diff vs a merge-base SHA, raw JSON
```
