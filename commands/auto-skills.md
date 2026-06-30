---
description: Rank which of the 89 plugin skills to load for a target, from its detected tech stack + attack surface (or a recon dir). Wraps tools/skill_router.py — local keyword routing, no network/LLM calls. Usage: /auto-skills --tech nextjs,graphql --surface api,auth
argument-hint: --tech <a,b> --surface <c,d> [--notes "..."] [--top 15] [--skills-dir DIR] [--json]
allowed-tools: Bash, Read
---

# /auto-skills

Topic-triggered skill auto-loading. At 89 skills you can't eyeball which apply
to a Next.js + GraphQL API target — this maps the target's fingerprint (tech +
surface + free-text notes) onto a keyword index built from each skill's
`SKILL.md` frontmatter and prints the ranked skills to load.

## Why This Matters

Loading the wrong skills wastes context; missing the right one means you hunt a
GraphQL endpoint without `hunt-graphql` loaded. The router is deterministic and
purely local: it scans `skills/<name>/SKILL.md`, scores every skill against your
fingerprint, and always keeps the baseline spine (`bb-methodology`,
`web2-recon`, `triage-validation`) even if it falls past the `--top` cutoff.

## Scoring (highest signal first)

- Fingerprint term in the skill **name** (`graphql` → `hunt-graphql`, `k8s` → `hunt-k8s`) — weight 5.0
- Term in the keyword index (tokens from name + description) — 2.0
- Term as a substring anywhere in the description — 1.0
- Baseline skills get a +0.5 nudge and are always returned

## Usage

```
/auto-skills --tech nextjs,graphql --surface api,auth
/auto-skills --tech aspnet,s3,kubernetes --surface upload,api --top 10
/auto-skills --tech nodejs --surface login,admin,redirect --notes "express jwt session"
/auto-skills --tech graphql --surface api --json
```

`--tech` and `--surface` are repeatable and/or comma-separated. Both lists and
`--notes` are optional; an empty fingerprint still returns the baselines.

## From a Recon Dir

The router takes a fingerprint, not a path. Derive `--tech`/`--surface` from your
recon output first, then route. For example, pull tech hints from a recon dir and
feed them in:

```bash
TECH=$(grep -rhoiE 'next\.js|nextjs|graphql|node|express|aspnet|laravel|spring|kubernetes|s3' \
  recon/target.com/ 2>/dev/null | tr 'A-Z' 'a-z' | sort -u | paste -sd, -)
python3 tools/skill_router.py --tech "$TECH" --surface api,auth,upload
```

## Run This

```bash
python3 tools/skill_router.py "$@"
```

Or pass the fingerprint explicitly:

```bash
python3 tools/skill_router.py --tech nextjs,graphql --surface api,auth --top 15
```

Add `--skills-dir DIR` to route against a different skills inventory, and
`--json` to emit `{fingerprint, top, skills_dir, baseline, routed, ranked}` for
piping into other tooling.

## Output

Default human view — `*` marks a routed skill, `[baseline]` marks the always-on spine:

```
Fingerprint: tech=['nextjs', 'graphql'] surface=['api', 'auth']
Routing 11 skills (top=8):
 *   9.00  graphql-audit
 *   9.00  hunt-graphql
 *   7.00  hunt-nextjs
 *   5.00  hunt-api-misconfig
 *   5.00  hunt-auth-bypass
 *   0.50  bb-methodology [baseline]
 *   2.50  web2-recon [baseline]
 *   0.50  triage-validation [baseline]
```

Then load the routed skills (e.g. `/graphql-audit`, `/web2-recon`) and start hunting.
