---
description: Mine a disclosed-report dataset (H1 / HuggingFace-style export) into reviewed hunt-* skill-grounding proposals you apply by hand. Wraps tools/disclosure_miner.py — local, stdlib-only, no network/LLM. It PROPOSES additions and never auto-edits skills/; needs a disclosure dataset to populate. Usage: /evolve-skills --input reports.json --out proposals.json
argument-hint: --input <reports.json|.jsonl> --out <proposals.json> [--skills-dir DIR]
allowed-tools: Bash, Read
---

# /evolve-skills

Keep the 48 `hunt-*` skills from going stale by feeding them real, already-disclosed
bug-bounty reports. Each report is classified into a vuln class, mapped onto the
best-matching `hunt-*` skill, mined for cheap signals (techniques, payloads,
endpoints), and turned into a **reviewed proposal** — a suggested note you fold
into the skill yourself.

This pairs with **hunt-memory**: hunt-memory captures what *we* learned hunting our
own targets; `/evolve-skills` captures what the *wider community* has already
disclosed. Run it periodically so the skills absorb live technique drift.

## Honest Note — Read First

- **It proposes; it never auto-edits.** `disclosure_miner.py` writes a proposals
  JSON only. Nothing here touches `skills/<name>/SKILL.md`. You (the operator)
  review the `suggested_note` lines and apply the ones worth keeping by hand.
- **It needs a disclosure dataset to do anything.** No dataset is bundled. Point
  `--input` at a disclosed-report export you supply — a local H1/HuggingFace-style
  disclosure dump (JSON array or JSONL). With no dataset there is nothing to mine.
- **Local and offline.** Stdlib only; no network or LLM calls at import or run
  time. The only files read are your `--input` and the `skills/*/SKILL.md`
  frontmatter used for mapping.

## What You Supply: the Disclosure Dataset

A JSON **array** or **JSONL** file (auto-detected by content, not extension; a
single top-level JSON object is accepted as one record). Fields are flexible — the
common H1 / HuggingFace disclosure-export shape. All are optional **except** that a
record must carry at least one readable text field (`title`, `weakness`,
`vuln_class`, or `summary`/`description`) or it is skipped and counted.

```json
[
  {
    "id":          "R1",
    "title":       "IDOR on /api/orders/{id} leaks other users' orders",
    "weakness":    "Insecure Direct Object Reference",
    "vuln_class":  "idor",
    "severity":    "high",
    "substate":    "resolved",
    "summary":     "Changed the order id to enumerate other accounts' orders.",
    "endpoint":    "/api/orders/{id}",
    "payload":     "GET /api/orders/1002"
  }
]
```

To use the configured HuggingFace H1 export, download it to a local file first
(`H1_USER`/`H1_TOKEN` in `.env` give faster/authenticated HuggingFace pulls), then
pass that file as `--input`. The miner reads a path — it does not fetch.

## Run This

```bash
python3 tools/disclosure_miner.py --input reports.json --out proposals.json
```

JSONL input and a custom skills inventory work too:

```bash
python3 tools/disclosure_miner.py --input reports.jsonl --out proposals.json --skills-dir skills
```

- `--input` (required): JSON array **or** JSONL disclosure export.
- `--out` (required): proposals JSON, written indented + `sort_keys=True` + trailing newline.
- `--skills-dir` (optional): defaults to `<repo>/skills`.

## What It Prints

A one-line summary, the touched skills, and the output path:

```
4 reports -> 3 proposals across 3 skills (1 skipped)
Skills: hunt-idor, hunt-open-redirect, hunt-xss
Wrote proposals.json
```

Empty or malformed records are skipped and counted — it never crashes on a bad row.

## Proposal Record Shape

One proposal per well-formed report:

```json
{
  "skill":          "hunt-idor",
  "vuln_class":     "idor",
  "source_id":      "R1",
  "signals":        { "techniques": ["..."], "payloads": ["..."], "endpoints": ["..."] },
  "suggested_note": "[high] idor — IDOR on order endpoint: techniques: ...; seen at: ... (disclosure R1)"
}
```

## How Mapping Works

Classification normalizes ~40 vuln classes that line up 1:1 with the `hunt-*`
family (sqli, idor, ssrf, ssti, xxe, rce, xss, csrf, cors, open-redirect, oauth,
saml, auth-bypass, race-condition, business-logic, graphql, file-upload, llm-ai,
k8s, … ), falling back to `unknown` → `hunt-misc`. `map_to_skill` prefers the
static class→skill target when it exists on disk, otherwise runs a
`skill_router`-style keyword scan over `skills/<name>/SKILL.md`, and degrades to
the static map when the skills dir is absent.

## After the Run — Apply by Hand

1. `Read` the `--out` proposals JSON.
2. Skim each `suggested_note`, highest `[severity]` first.
3. For the keepers, open `skills/<skill>/SKILL.md` and fold the note into the right
   section yourself. This step is human-reviewed on purpose — the tool never
   edits skills.
