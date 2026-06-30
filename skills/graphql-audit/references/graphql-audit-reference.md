# Graphql-Audit — Extended Reference

This file contains extended content extracted from `SKILL.md` to keep the main document under the line limit.

---

## REPORT TEMPLATE — CVSS & REMEDIATION (continued)

```
- IDOR cross-user: CVSS 7.5-8.5 (High)
- Batching ATO chain: CVSS 9.0+ (Critical)
- Unauthenticated mutation: CVSS 9.8 (Critical)

Remediation:
- Disable introspection in production (allow only in dev environments)
- Enforce per-query depth limit (recommend <= 10)
- Enforce complexity limits
- Disable query batching or add per-batch rate limits
- Validate object ownership in every resolver (not just at route level)
- Remove field suggestions in production
```

---

## KILL SIGNALS — Walk Away

```
- Endpoint returns 404/410 consistently — not active
- All queries return generic "Unauthorized" with no suggestions — well-hardened
- Rate limit fires on query 2 — strong protection, low ROI
- Only __typename accessible, no types — schema fully locked down
- Engine is Apollo Federation gateway only — attack the downstream services instead
```

---

## TOOLS REFERENCE

| Tool | Purpose | Install |
|---|---|---|
| `graphql_audit.sh` | Automated multi-phase sweep | this repo |
| `graphw00f` | Engine fingerprinting | `pip install graphw00f` |
| `clairvoyance` | Field discovery (no introspection) | `pip install clairvoyance` |
| `graphql-cop` | Attack checklist runner | `pip install graphql-cop` |
| `gqlmap` | SQL/NoSQL injection scanner | `pip install gqlmap` |
| `inql` | Burp Suite extension — schema + IDOR | Burp BApp Store |
| `graphql-voyager` | Visual schema explorer | browser tool |
| `wscat` | WebSocket subscription testing | `npm i -g wscat` |
