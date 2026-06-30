---
description: Full GraphQL security audit against a target endpoint — introspection + schema dump, graphw00f engine fingerprint, clairvoyance field discovery, array-batching DoS, alias-bomb amplification, gqlmap injection, and a graphql-cop checklist. Surfaces introspection leaks, IDOR via aliasing, and resource-exhaustion DoS triggers.
argument-hint: <target-graphql-endpoint>
allowed-tools: Bash
---

# /graphql-audit

Run the 7-phase GraphQL audit pipeline against a target endpoint. This command
invokes the backing script `tools/graphql_audit.sh` directly — do NOT
re-implement the probes inline. The script already handles connectivity checks,
tool detection, and graceful curl fallbacks when optional tools are missing.

## Usage

```
/graphql-audit https://api.target.com/graphql
```

## Run This

Invoke the audit script with the user's target endpoint:

```bash
bash tools/graphql_audit.sh "$ARGUMENTS"
```

The endpoint must be a full URL (the script matches the `http*` positional
argument). Optional authenticated / proxied runs pass extra flags through:

```bash
# Authenticated session
bash tools/graphql_audit.sh "$1" --cookie "session=abc123"
bash tools/graphql_audit.sh "$1" --header "Authorization: Bearer TOKEN"

# Route through Burp/Caido for inspection
bash tools/graphql_audit.sh "$1" --proxy http://127.0.0.1:8080

# Pin the output directory
bash tools/graphql_audit.sh "$1" --output-dir ./findings/target/graphql
```

Results are written to `findings/graphql/<host>/<timestamp>/` with a
`summary.txt`, `introspection.json` (when introspection is enabled), and
per-phase output files.

## What it tests (7 phases)

1. **Introspection** — POST + GET probe, dumps the full schema and detects
   field-suggestion leakage (clairvoyance-able even when introspection is off).
2. **Engine fingerprint** — graphw00f to identify the GraphQL implementation.
3. **Field discovery** — clairvoyance to reconstruct the schema via suggestions.
4. **Batching DoS** — array-batched queries; flags if 100 queries are accepted
   in one request (brute-force amplifier / DoS).
5. **Alias bomb** — aliased duplicate fields for resource exhaustion.
6. **Injection** — gqlmap sweep for SQLi/NoSQLi reachable through resolvers.
7. **graphql-cop checklist** — common misconfig/DoS checks.

## Methodology note

After the sweep, hunt for the high-signal classes manually:

- **IDOR via aliasing** — request the same object-by-ID query under many aliases
  in one batched request to bypass per-request rate limits and enumerate.
- **Auth bypass** — re-run introspection and sensitive queries with and without
  the auth header; compare what fields/types each role can reach.
- **DoS triggers** — confirm batching/alias-bomb findings have real resource
  impact before reporting; many programs scope these tightly.

Then confirm any finding through the project's validation gate before writing it
up.

## See also

For the full methodology, payload patterns, and reporting guidance, load the
`hunt-graphql` / `graphql-audit` skill (`skills/graphql-audit/`).
