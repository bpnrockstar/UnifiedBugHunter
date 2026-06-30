---
description: "Run a white-box source code audit on a repository or directory. Performs static analysis for SQLi, XSS, SSRF, command injection, hardcoded secrets, auth bypass, IDOR, deserialization flaws, path traversal, prototype pollution, crypto weaknesses, and business logic issues. Outputs prioritized findings with code snippets, curl PoCs, and fix recommendations. Usage: /code-audit [path] [--mode quick|full] [--language py|js|all]"
argument-hint: "[path] [--mode quick|full] [--language py|js|all]"
---

# /code-audit

Run a white-box source code audit on a target codebase.

> **Model-driven — no backing script.** This command is a model-driven audit:
> Claude reads the source and applies the methodology below; there is no tool in
> `tools/` to invoke. How the pieces relate:
> **command `/code-audit` = the entrypoint**, **skill `code-review` = the
> methodology** (SAST patterns + 10-phase process it follows), and **agent
> `code-reviewer` = the autonomous reviewer** for hands-off, multi-file audits.

## When to Use This

Use when you have source code access:
- The target has a public GitHub/GitLab repo
- You extracted a JS bundle with API endpoints
- You decompiled an APK (jadx) and have Java sources
- The target is a client-provided codebase for white-box assessment
- You want to verify a finding from black-box testing with source code

## Usage

```
/code-audit                           # Audit current directory (quick mode)
/code-audit /path/to/target           # Audit specific path
/code-audit --mode full               # Full audit (all phases)
/code-audit --mode quick              # Quick scan (high-signal patterns only)
/code-audit --language py             # Python only
/code-audit --language js             # JavaScript/TypeScript only
/code-audit --language all            # All languages
/code-audit --output findings.json    # Save findings to JSON
```

## What This Does

1. **Phase 0** — Maps the codebase: language, framework, entry points, auth middleware
2. **Phase 1** — Checks business logic: missing auth, IDOR, mass assignment
3. **Phase 2** — Scans for injection: SQLi, NoSQLi, command injection, SSTI, XSS
4. **Phase 3** — Hunts secrets: API keys, tokens, passwords, private keys, JWTs
5. **Phase 4** — Checks deserialization: pickle, unserialize, ObjectInputStream
6. **Phase 5** — Checks path traversal: file operations with user input
7. **Phase 6** — Checks SSRF: HTTP clients with user-controlled URLs
8. **Phase 7** — Checks crypto: weak algorithms, hardcoded IVs, JWT alg=none
9. **Phase 8** — Checks config: CORS, debug mode, verbose errors
10. **Phase 9** — Checks prototype pollution: unsafe merges (JavaScript)

## Quick Audit (--mode quick)

Runs only the highest-signal patterns:
- Hardcoded secrets (API keys, tokens, passwords)
- Raw SQL queries with string interpolation
- Command injection patterns (exec, subprocess, shell=True)
- Missing auth on admin/delete endpoints
- Hardcoded JWT secrets or alg=none
- Debug mode enabled in production

## Full Audit (--mode full)

Runs all 10 phases including:
- All injection variants
- Deserialization across all languages
- Prototype pollution (JS only)
- Crypto weakness audit
- Configuration hardening review
- Mobile-specific patterns (if Android sources detected)

## Output

### Summary
```
Language: Python 3.11+ (Flask + SQLAlchemy)
Framework: Flask RESTful with JWT auth
Auth middleware: @jwt_required() on 12/18 endpoints
Lines of code: 24,563
Dependencies: 47 packages (3 with known CVEs)

Findings Summary:
  CRITICAL: 1  — Hardcoded AWS key with S3 wildcard access
  HIGH:     3  — SQLi in /api/users/search, NoSQLi in profile update, Stored XSS in comments
  MEDIUM:   4  — IDOR on order history, Weak JWT secret, Missing rate limit on login, Verbose error messages
  LOW:      2  — Debug mode enabled, CORS wildcard
  TOTAL:    10
```

### Finding Detail
```
## [HIGH] SQLi in /api/users/search

**File:** app/routes/users.py:142

**Code:**
```python
query = f"SELECT * FROM users WHERE username = '{search_term}'"
db.execute(query)
```

**Root Cause:** Unsanitized user input concatenated into SQL query string.

**Impact:** Attacker can extract all user records including password hashes and PII.

**PoC:**
```bash
curl -X GET "https://target.com/api/users/search?q=admin'%20OR%201=1--"
```

**Fix:**
```python
query = "SELECT * FROM users WHERE username = %s"
db.execute(query, (search_term,))
```

**CVSS:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
```

## Tips

- Always check the `.env` file, config files, and CI/CD pipelines for secrets
- Pay special attention to endpoints marked with `# TODO: add auth` or `# FIXME: secure this`
- Check both the latest commit AND git history (secrets get committed then removed)
- For JS apps, check both client and server bundles separately
- When reviewing mobile apps, focus on hardcoded API keys and internal API endpoints
- Use `/validate` after extracting each finding from the audit
