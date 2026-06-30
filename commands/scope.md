---
description: Check if a target asset is in scope for the program before hunting or submitting. Reads program scope page, checks asset against in-scope and out-of-scope lists, verifies the asset is owned by the target organization. Usage: /scope <asset>
argument-hint: <asset> (e.g. api.target.com | https://target.com/api/v2 | *.target.com)
allowed-tools: Bash
---

# /scope

Verify an asset is in scope before hunting or submitting a finding.

## Why This Matters

Out-of-scope reports are immediately closed. Testing out-of-scope assets can get you banned.
Always check scope BEFORE the first request.

**Real example:** City of Vienna explicitly excludes `/advuew/*`. Submitting XSS on that path = instant close.

## Usage

```
/scope api.target.com
/scope https://target.com/api/v2/users
/scope target-staging.company.com
/scope *.company.com
```

## Deterministic Local Check

Use the local scope checker before sending traffic:

```bash
python3 tools/scope_checker.py https://api.target.com/v2/users \
  --domain target.com \
  --domain '*.target.com' \
  --exclude-domain staging.target.com
```

Filter a discovered URL list:

```bash
python3 tools/scope_checker.py \
  --domain target.com \
  --domain '*.target.com' \
  --exclude-domain staging.target.com \
  --input-file recon/target.com/urls/all.txt \
  --output recon/target.com/urls/in_scope.txt
```

## Verdicts

`classify(url)` returns one of four verdicts instead of a plain pass/fail:

| Verdict | Meaning | Default action |
|---|---|---|
| `IN_SCOPE` | Matches an in-scope domain/wildcard, not excluded | Clear to test |
| `OUT_OF_SCOPE` | Matches an **explicit exclusion** (excluded domain/path/class) | Hard block — never testable |
| `NEEDS_REVIEW` | Doesn't match scope and isn't an explicit exclusion — an unmatched host, a bare IP, or a related/sibling host (acquisition, CNAME to a parent org) | Escalate to operator |
| `ERROR` | Unparseable input | Block, surface the parse error |

### Why `NEEDS_REVIEW` instead of a silent reject

Previously, anything that didn't match the allowlist was silently auto-rejected.
That quietly dropped a program's **siblings and acquisitions** — assets that are
often legitimately in scope but live on a host the allowlist hasn't been told
about yet. Silently vanishing them means **missed real findings**.

So an unmatched/IP/related host now returns `NEEDS_REVIEW` and, in interactive
mode, the operator is **asked to continue or skip** rather than having the asset
disappear without a trace.

### Guardrails

- **Explicit exclusions are NEVER continuable.** An `OUT_OF_SCOPE` verdict
  (excluded domain, excluded path, excluded vuln class) is a hard block. There
  is no "continue" prompt — the operator cannot override it.
- **Default non-interactive runs stay fail-closed.** Without `--interactive` /
  `--confirm`, `confirm_in_scope()` returns `False` on `NEEDS_REVIEW` — the
  asset is treated as not-in-scope and skipped. No silent traffic, no prompt.
- **"Continue" requires authorization + is audit-logged.** Choosing to continue
  on a `NEEDS_REVIEW` asset is an assertion by the operator that they have
  authorization to test that asset. Every such override is recorded to the
  audit log so the decision is traceable.

### Interactive / confirm mode

Pass `--interactive` (alias `--confirm`) to enable prompting. On a
`NEEDS_REVIEW` verdict the checker pauses and asks the operator to **continue or
skip** that asset:

```bash
python3 tools/scope_checker.py https://api.related-acquisition.com/v2/users \
  --domain target.com \
  --domain '*.target.com' \
  --exclude-domain staging.target.com \
  --confirm
```

```
NEEDS_REVIEW: api.related-acquisition.com is not in the allowlist and is not an
explicit exclusion (possible sibling/acquisition). Do you have authorization to
test this asset?
  [c]ontinue  — proceed, logged to audit
  [s]kip      — treat as out of scope
> 
```

`IN_SCOPE` proceeds silently; `OUT_OF_SCOPE` is hard-blocked with no prompt even
under `--confirm`.

## Run This

```bash
python3 tools/scope_checker.py https://api.target.com/v2/users \
  --domain target.com \
  --domain '*.target.com' \
  --exclude-domain staging.target.com \
  --confirm
```

`--confirm` (alias `--interactive`) enables the continue/skip prompt on a
`NEEDS_REVIEW` verdict. Omit it for a fail-closed, non-interactive run that
silently skips anything not `IN_SCOPE`. Explicit exclusions are hard-blocked
either way.

## Scope Check Process

### Step 1: Read In-Scope List

Go to the program page and extract:
```
In-scope:
- *.target.com
- target.com
- api.target.com
- mobile.target.com (iOS + Android apps)

Out-of-scope:
- staging.target.com (explicitly excluded)
- target.com/help/* (documentation only)
- partners.target.com (third-party managed)
```

### Step 2: Asset Ownership Check

Verify the asset is actually owned by the target company (not a third party):

```bash
# WHOIS
whois api.target.com | grep -iE "registrant|admin|tech|org"

# DNS — is it CNAME to a third party?
dig +short api.target.com CNAME
# If CNAME to salesforce.com, zendesk.com, etc. → not in scope

# Check if it's a known third-party service:
# intercom.io, freshdesk.com, zendesk.com, hubspot.com, etc.
```

### Step 3: Wildcard Interpretation

| Scope Pattern | Covers | Does NOT Cover |
|---|---|---|
| `*.target.com` | `api.target.com`, `app.target.com` | `target.com` itself |
| `target.com` | `target.com` only | `api.target.com` |
| `*.target.com` + `target.com` | Both | Sub-subdomains like `a.api.target.com` (depends on program) |

### Step 4: Path Exclusions

Some programs exclude specific paths on in-scope domains:
```
Domain: target.com (in scope)
But: target.com/terms, target.com/privacy, target.com/help/* = usually excluded

Check for:
- Wildcard exclusions: /admin/* excluded
- Path-specific exclusions: /api/v1/* excluded (use v2 only)
- Feature exclusions: "Do not test file upload feature"
```

### Step 5: Staging / Dev Check

Unless the program explicitly includes staging:
```
staging.target.com     → NOT in scope (usually)
dev.target.com         → NOT in scope (usually)
qa.target.com          → NOT in scope (usually)
test.target.com        → NOT in scope (usually)

Always confirm: does scope say "*.target.com" or only list production domains?
```

## Output

**IN SCOPE:** "asset.target.com is covered by the *.target.com wildcard. Owned by TargetCorp (WHOIS confirms). No path exclusions apply. Clear to test."

**OUT OF SCOPE:** "target.com/admin/* is explicitly excluded in the program rules under 'Out of Scope: Internal admin panel.' Do not test. Move to a different endpoint."

**NEEDS REVIEW (unclear):** "third-party.target.com appears to be a CNAME to Zendesk — a third-party service not owned by TargetCorp, and it isn't on the allowlist. This is `NEEDS_REVIEW`, not an explicit exclusion. Under `--confirm` you'll be asked to continue or skip; continue only if you have authorization (the choice is audit-logged). In a default non-interactive run it fails closed and is skipped."

## Safe Harbor Check

Before testing, confirm the program has a safe harbor clause:
```
Look for: "We will not pursue legal action against security researchers who..."
If no safe harbor → be more careful → stick strictly to documented scope
```
