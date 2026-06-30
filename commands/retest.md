---
description: Re-run a stored PoC against a target and decide FIXED / STILL-VULN / REGRESSED. Scope-safe, fail-closed closed-loop verification of previously-reported findings (e.g. a Jira security export).
argument-hint: "(--finding <poc.json> | --batch <findings.json>) [--scope <scope.json>] [--out <report.json>] [--timeout <int>] [--rps <float>] [--insecure] [--json]"
allowed-tools: Bash, Read
---

# /retest

Replay a proof-of-concept and produce a regression verdict. Answers the
question: *is this bug actually fixed, or is it still exploitable (or fixed
then broken again)?*

## What This Does

1. Loads one PoC spec (`--finding`) or many (`--batch`).
2. (Optional) Gates every spec through scope — fail-closed.
3. Replays each request and evaluates the `match` (the VULNERABLE condition).
4. Emits a verdict per finding plus a batch summary.

## Run This

`/retest` is backed by `tools/retest.py`. **Run the script — do NOT
re-implement the replay/verdict logic inline.** The prose below documents
what the script already does.

Single finding:

```bash
python3 tools/retest.py --finding <poc.json>
```

Batch (re-test a whole set of previously-reported findings at once):

```bash
python3 tools/retest.py --batch <findings.json> \
  --scope <scope.json> \
  --out <report.json>
```

Tune transport and output as needed:

```bash
python3 tools/retest.py --batch <findings.json> \
  --scope <scope.json> --out <report.json> \
  --timeout 20 --rps 2.0 --insecure --json
```

Flags:

- `--finding <poc.json>` / `--batch <findings.json>` — **mutually exclusive,
  exactly one required.** `--finding` also accepts a JSON array; `--batch`
  also accepts a single object (both go through the same loader).
- `--scope <scope.json>` — enables fail-closed scope gating (see below).
- `--out <report.json>` — writes the full report as JSON (`indent=2,
  sort_keys=True`, trailing newline). Without it, a colored summary is printed.
- `--timeout <int>` — per-request timeout in seconds (default `15`).
- `--insecure` — disable TLS verification (`verify_tls=False`).
- `--rps <float>` — simple per-host min-interval throttle (requests/sec).
- `--json` — print the JSON report to stdout instead of the colored summary.

**Exit codes:** `0` whenever retests ran — verdicts (including `ERROR`) are
data, not process failure. `2` on usage error (no/both sources, unreadable or
invalid input, bad scope file, unwritable `--out`). Stdlib + `requests` only;
degrades gracefully if `scope_checker` / `audit_log` are absent.

## Verdicts

| Verdict | Meaning |
|---|---|
| `FIXED` | The `match` is no longer satisfied — the bug is gone. (An empty/absent `match` is fail-closed → `FIXED`.) |
| `STILL-VULN` | The `match` is still satisfied — the bug is still exploitable. |
| `REGRESSED` | `previous_status` was `FIXED` but the `match` is satisfied again — a fix that broke. |
| `ERROR` | Request failed, finding was out-of-scope, or the spec was malformed. Never crashes the run. |

Verdict matrix (`matched` × `previous_status`, compared case-insensitively):

| matched | previous_status | verdict |
|---|---|---|
| true | `FIXED` | `REGRESSED` |
| true | anything else / none | `STILL-VULN` |
| false | any | `FIXED` |

## PoC-spec JSON shape

A PoC spec describes the request to replay and the `match` that defines the
VULNERABLE condition. All keys present in `match` are **ANDed** — every listed
condition must hold for the match to be satisfied.

```json
{
  "id": "BUG-123",
  "target": "api.target.com",
  "url": "https://api.target.com/users/1",
  "method": "GET",
  "headers": {"X-Foo": "bar"},
  "body": "a=1&b=2",
  "match": {
    "status": 200,
    "body_contains": "secret",
    "body_regex": "id=\\d+",
    "header_contains": {"Server": "nginx"}
  },
  "previous_status": "FIXED"
}
```

- `url` is **required**; `method` defaults to `GET`; `headers` / `body` /
  `match` / `previous_status` are optional.
- `body` as a dict → sent as form data; as a str/bytes → sent as-is.
- `previous_status` ∈ `{"FIXED", "STILL-VULN"}` — drives `REGRESSED` detection.
- Scope host resolution: explicit `target`, else the hostname parsed from `url`.

`match` semantics:

- `status` (int) — `response_status == match.status`.
- `body_contains` (str) — substring of the response body.
- `body_regex` (str) — `re.search` against the body; an un-compilable regex
  simply does not match (it is not an error).
- `header_contains` (dict) — for each `{name: value}`, the header name is
  matched **case-insensitively** and `value` must be a **case-insensitive
  substring** of the actual header value.

A batch input is a JSON array of these objects:

```json
[
  {"id": "BUG-123", "url": "https://api.target.com/users/1", "match": {"status": 200, "body_contains": "secret"}, "previous_status": "FIXED"},
  {"id": "BUG-124", "url": "https://api.target.com/admin", "match": {"status": 200}, "previous_status": "STILL-VULN"}
]
```

The batch report has the shape:

```json
{
  "results": [
    {"id": "BUG-123", "verdict": "REGRESSED", "detail": "...", "status": 200, "url": "https://api.target.com/users/1"}
  ],
  "summary": {"still_vuln": 0, "fixed": 0, "regressed": 1, "error": 0}
}
```

## Scope safety (fail-closed)

When `--scope <scope.json>` is supplied, every finding is gated through
`scope_checker` **before any request is sent**. Out-of-scope findings get a
verdict of `ERROR` with detail `out-of-scope` and **zero** requests are made
for them — the gate is fail-closed (unknown / unresolvable host → blocked, not
contacted). Stay in scope: only test assets the program authorizes.

Scope file schema (also accepts `in_scope` / `out_of_scope` aliases, or a bare
JSON array of patterns):

```json
{
  "domains": ["*.target.com", "api.target.com"],
  "excluded_domains": ["blog.target.com"],
  "excluded_classes": ["dos"]
}
```

## Batch use-case: re-testing a reported set

The intended workflow is closed-loop verification of a large set of
previously-reported findings — e.g. resolved security tickets from a Jira
export. Convert each ticket into a PoC spec (carrying its `id` and its
`previous_status`), drop them into a single `findings.json` array, and run:

```bash
python3 tools/retest.py --batch findings.json \
  --scope scope.json --out retest-report.json --rps 2.0
```

Then read `retest-report.json` and act on the summary:

- `STILL-VULN` / `REGRESSED` → the ticket was closed prematurely or the fix
  broke. Re-open it and re-report with this fresh evidence.
- `FIXED` → confirmed resolved; close the loop.
- `ERROR` → out-of-scope or the spec needs fixing (bad `url`/`match`); triage
  the spec, not the target.

Because scope gating is fail-closed and out-of-scope/failed requests become
`ERROR` (never a crash), it is safe to point this at a large export and let it
run end-to-end.

## Usage

```
/retest --batch findings.json --scope scope.json --out retest-report.json
```
