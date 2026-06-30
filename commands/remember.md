---
description: Log current finding or successful pattern to hunt memory. Auto-fills from /validate output if available. Usage: /remember
---

# /remember

Save a finding or successful pattern to persistent hunt memory.

> **Model-driven workflow — no backing script.** There is no `tools/remember.py`
> or equivalent CLI. You (the model) carry out the steps below directly: gather
> the fields from session context, confirm with the user, then append the
> records to the hunt-memory JSONL files (`journal.jsonl`, `patterns.jsonl`)
> and update the target profile. The "pipeline" framing
> below describes what you do, not a command you run.

## What This Does

1. Auto-populates fields from session context (target, endpoint, vuln_class, technique)
2. If `/validate` was run in this session, pre-fills from validation output
3. Prompts you to confirm or edit before saving
4. Writes to `journal.jsonl` (always) + `patterns.jsonl` (if confirmed + payout > 0)
5. Updates the target profile's `tested_endpoints` and `findings`

## Usage

```
/remember                    # after finding something
/remember --from-validate    # explicitly pull from last /validate
```

## Interactive Flow

```
REMEMBER — Log finding to hunt memory

Target:     target.com (auto-detected)
Endpoint:   /api/v2/users/{id}/orders (from session)
Vuln Class: idor (from session)
Technique:  numeric_id_swap_with_put_method

Result:     [confirmed / rejected / partial / informational]?
Severity:   [critical / high / medium / low]?
Payout:     $___?
Notes:      ___?
Tags:       [comma-separated]?

Save to hunt memory? [y/n]
```

## Minimum Required Fields

- target
- vuln_class
- endpoint
- result

## What Gets Written

| Field | journal.jsonl | patterns.jsonl | target profile |
|---|---|---|---|
| Finding details | Always | If confirmed + payout > 0 | findings[] updated |
| Tested endpoint | — | — | tested_endpoints[] updated |
| Tech stack | — | From target profile | — |

## Saving a verified finding (replayable)

The JSONL hunt-memory above is for patterns/journal. To persist a **verified
finding into the dashboard DB with a replayable PoC** — so `/retest` can re-run
it against the live target later — also call:

```
python3 tools/save_finding.py \
  --target api.target.com \
  --title "IDOR on /users/{id}" \
  --severity high \
  --class idor \
  --url https://api.target.com/users/1 \
  --method GET \
  --header "Authorization: Bearer <token>" \
  --match-status 200 \
  --match-contains "ssn" \
  [--body ... --match-regex ... --endpoint ... --impact ... --remediation ... --cvss 8.1]
```

This resolves/creates the target, stores the finding via
`dashboard.database.add_finding(...)`, and attaches a structured `poc_spec`
(url/method/headers/body/match) that `tools/retest.py` replays to decide
FIXED / STILL-VULN / REGRESSED. It prints the new finding id. Importable too:
`from tools.save_finding import save_finding`.

## Why This Matters

- Next time you hunt a target with similar tech stack, your successful patterns are suggested first
- `/pickup target.com` shows which endpoints you've tested and which remain
- Cross-target learning: patterns from target A inform hunting on target B
