---
name: code-review
description: White-box source code audit methodology for bug bounty and penetration testing. Covers SAST-driven analysis for SQLi, XSS, SSRF, command injection, insecure deserialization, hardcoded secrets, auth bypass, business logic flaws, path traversal, prototype pollution, crypto weaknesses, and JWT flaws. Language-agnostic with language-specific grep patterns for Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, and C#. Use when you have source code access (public repo, JS bundle, APK decompile, client-supplied code).
---

# Code Review Methodology

## Overview

White-box code review finds vulnerabilities black-box testing misses — logic flaws, auth gaps, insecure defaults, and subtle injection sinks in less-tested code paths. This methodology covers the full pipeline from codebase mapping to finding extraction.

## Phase 0: Recon — Map the Codebase

### Language & Framework ID
```bash
# Quick stack identification
ls *.{py,js,ts,java,go,rb,php,cs} 2>/dev/null | head -20
ls package.json Pipfile* go.mod Cargo.toml Gemfile composer.json build.gradle 2>/dev/null

# Entry points — routes, controllers, handlers
grep -rn "route(" *.{js,ts} 2>/dev/null | head -30
grep -rn "@app\.route\|@app\.get\|@app\.post\|def get\|def post" *.py 2>/dev/null | head -30
grep -rn "router\.\|app\.(get\|post\|put\|delete\|patch)" *.js 2>/dev/null | head -30
grep -rn "RequestMapping\|GetMapping\|PostMapping" *.java 2>/dev/null | head -30
grep -rn "router\.Handle\|http\.Handle\|mux\.\|echo\.\|gin\." *.go 2>/dev/null | head -30
grep -rn "Route\|routes" --include="*.rb" 2>/dev/null | head -20
```

### Auth Middleware Map
```bash
grep -rn "authenticate\|authorize\|middleware\|@LoginRequired\|require_auth\|auth_required\|is_authenticated" \
  --include="*.{py,js,ts,java,go,rb,php}" 2>/dev/null | head -30
```

### Dependency Audit
```bash
# Check for known-vulnerable versions
python3 -c "
import json, subprocess
data = json.load(open('package.json'))
for name, ver in {**data.get('dependencies',{}), **data.get('devDependencies',{})}.items():
    print(f'{name}@{ver}')
" 2>/dev/null | head -50
# Or use npm audit / pip audit / cargo audit
```

## Phase 1: Business Logic & Authorization Flaws

### Checklist
- [ ] Are admin-only endpoints gated by server-side middleware?
- [ ] Do object lookups verify user ownership?
- [ ] Is mass assignment prevented (allowlist vs denylist)?
- [ ] Are rate limits enforced server-side?
- [ ] Can a user escalate their role via API manipulation?
- [ ] Are state-changing operations idempotent?
- [ ] Is there a `?admin=true` or `role` parameter in requests?

### Search Patterns
```bash
# Missing auth on sensitive functions
grep -rn "def.*admin\|def.*delete\|def.*modify\|def.*impersonate\|def.*reset" --include="*.py" 2>/dev/null
grep -rn "function.*admin\|function.*deleteUser\|function.*impersonate" --include="*.{js,ts}" 2>/dev/null

# Ownership check absence
grep -rn "\.id\|object_id\|document_id\|params\.id\|req\.params" --include="*.{py,js,ts}" 2>/dev/null

# Mass assignment
grep -rn "request\.json\|request\.body\|request\.data\|body-parser\|req\.body" --include="*.{py,js,ts}" 2>/dev/null

# Race condition candidates — state-changing with no lock
grep -rn "\.save()\|\.update()\|\.create()\|UPDATE\|INSERT INTO" --include="*.{py,js,ts,java,go}" 2>/dev/null
```

## Phase 2: Injection Flaws

### SQL Injection
```bash
# Raw SQL construction (parameter interpolation, not parameterized)
grep -rn "execute(\|query(\|raw(\|RawSQL\|cursor\.execute\|db\.query\|db\.execute" --include="*.{py,js,ts,java,go,rb,php}" 2>/dev/null
grep -rn "f\"SELECT\|f'SELECT\|\+ \"SELECT\|\`SELECT\|\"SELECT\|\+ 'SELECT\|format(SELECT" --include="*.{py,js,ts,go}" 2>/dev/null
grep -rn "%s\|%d\|%f" --include="*.py" 2>/dev/null | grep -i "select\|insert\|update\|delete" 2>/dev/null
```
**Detection:** Look for string concatenation or f-strings in SQL queries. Safe patterns use `?` placeholders (psycopg2), `%s` (mysql-connector with params tuple), or ORM methods without `.raw()`.

### NoSQL Injection
```bash
grep -rn "\$where\|\$ne\|\$gt\|\$regex\|\$nin\|\$or\|\$and" --include="*.{js,ts}" 2>/dev/null
grep -rn "findOne\|findByIdAndUpdate\|findByIdAndDelete\|updateOne" --include="*.{js,ts}" 2>/dev/null
```
**Detection:** User input passed directly into MongoDB query operators without sanitization or type checking.

### Command Injection
```bash
grep -rn "subprocess\|subprocess\.Popen\|subprocess\.call\|subprocess\.run\|os\.system\|os\.popen\|exec\|eval" --include="*.py" 2>/dev/null
grep -rn "execSync\|exec(\|spawn(\|child_process\|shelljs" --include="*.{js,ts}" 2>/dev/null
grep -rn "Runtime\.getRuntime\(\)\.exec\|ProcessBuilder\|Process.start" --include="*.java" 2>/dev/null
grep -rn "exec\.Command\|exec\.Output\|os/exec" --include="*.go" 2>/dev/null
```
**Detection:** User input passed to shell execution functions without strict allowlist validation.

### Server-Side Template Injection
```bash
grep -rn "render_template_string\|Template(template)\|\.render(" --include="*.{py,js,ts,java}" 2>/dev/null
grep -rn "template\|Template\|tpl\|jinja\|twig\|freemarker\|velocity\|thymeleaf" --include="*.{py,js,ts,java}" 2>/dev/null
```

### XSS (Reflected / Stored)
```bash
# Backend — unsanitized output in HTML templates
grep -rn "innerHTML\|outerHTML\|document\.write\|v-html\|dangerouslySetInnerHTML\|\|safe\b" --include="*.{html,js,ts,vue}" 2>/dev/null
grep -rn "mark_safe\|format_html\|SafeString" --include="*.py" 2>/dev/null

# Stored XSS — user input stored then rendered
grep -rn "\.save\|INSERT INTO" --include="*.py" 2>/dev/null | head -20
grep -rn "req\.body\|req\.query\|req\.params" --include="*.{js,ts}" 2>/dev/null | grep -v "sanitize\|escape\|DOMPurify" 2>/dev/null
```

## Phase 3: Secrets & Credentials

```bash
# API keys, tokens, passwords
grep -rn "api_key\|API_KEY\|secret\|SECRET\|password\|PASSWORD\|token\|TOKEN\|sk-[a-zA-Z0-9]\{20,\}\|ghp_\|gho_\|ghu_" \
  --include="*.{py,js,ts,go,rb,php,java,json,yaml,yml,tfvars,env}" 2>/dev/null | grep -v "test\|\.example\|sample\|\.env\."

# Private keys
grep -rn "\-\-\-BEGIN.*PRIVATE KEY\-\-\-" --include="*" 2>/dev/null

# JWT secrets
grep -rn "jwt_secret\|JWT_SECRET\|jwt\.sign\|jwt\.verify\|jose\|jsonwebtoken" --include="*.{py,js,ts,go}" 2>/dev/null

# Cloud credentials
grep -rn "aws_access_key\|AWS_ACCESS_KEY\|aws_secret_access_key\|AWS_SECRET\|AZURE.*KEY\|GCP.*KEY\|service_account\|s3://" \
  --include="*.{py,js,ts,json,yaml,yml,tfvars}" 2>/dev/null

# Connection strings
grep -rn "mongodb://\|postgresql://\|mysql://\|redis://\|amqp://\|sqlite:///" --include="*.{py,js,ts,yaml,yml,json,env}" 2>/dev/null
```

## Phase 4: Insecure Deserialization

```bash
# Python
grep -rn "pickle\.loads\|pickle\.load\|cPickle\|dill\.loads\|shelve\|joblib\.load\|marshal\.loads" --include="*.py" 2>/dev/null

# PHP
grep -rn "unserialize(" --include="*.php" 2>/dev/null

# Java
grep -rn "ObjectInputStream\|readObject\|readUnshared\|XMLDecoder\|Yaml\.load\|SnakeYaml" --include="*.java" 2>/dev/null

# Node.js / Ruby
grep -rn "unserialize\|deserialize" --include="*.{js,ts,rb}" 2>/dev/null

# .NET
grep -rn "BinaryFormatter\|LosFormatter\|NetDataContractSerializer\|JavaScriptSerializer\|XmlSerializer" --include="*.cs" 2>/dev/null
```
**Validation:** If found, craft a PoC payload and test against a development instance if available.

## Phase 5: Path Traversal & File Operations

```bash
grep -rn "open(\|open(\|read(\|readFile\|writeFile\|sendFile\|download\|import\(" \
  --include="*.{py,js,ts,go,rb,php,java}" 2>/dev/null | grep -v "test\|\.pyc\|node_modules\|__pycache__"
grep -rn "os\.path\.join\|path\.join\|Path(" --include="*.{py,js,ts}" 2>/dev/null
grep -rn "../\|..\\\\|%2e%2e" --include="*.{py,js,ts}" 2>/dev/null
```
**Detection:** User-supplied filename consumed by file operations without resolving to a safe base directory.

## Phase 6: SSRF

```bash
grep -rn "requests\.get\|requests\.post\|urllib\|urlopen\|fetch(\|axios\.get\|httpx\.\|aiohttp" \
  --include="*.{py,js,ts,go}" 2>/dev/null | grep -v "test\|node_modules"
grep -rn "redirect\|proxy\|forward\|webhook\|callback_url\|return_url\|webhook_url\|image_url\|file_url" \
  --include="*.{py,js,ts}" 2>/dev/null
```
**Detection:** URL from user input passed to HTTP client without allowlist validation.

## Phase 7: Crypto & Auth Flaws

```bash
# Weak hashing
grep -rn "MD5\|SHA1\|DES\|RC4\|ECB\|PBE\|md5\|sha1\b" --include="*.{py,js,ts,java,go}" 2>/dev/null

# Predictable tokens
grep -rn "random\|uuid\|Math\.random\|token_urlsafe\|secrets" --include="*.{py,js,ts}" 2>/dev/null

# Hardcoded IV / salt
grep -rn "iv=\|IV=\|salt=\|SALT=\|nonce=" --include="*.{py,js,ts,java,go}" 2>/dev/null

# JWT alg=none
grep -rn "alg.*none\|none.*alg\|'none'\|\"none\"" --include="*.{py,js,ts,java,go}" 2>/dev/null

# Password storage
grep -rn "hash\|bcrypt\|scrypt\|argon2\|pbkdf2\|md5\|sha1" --include="*.{py,js,ts,java,go}" 2>/dev/null
```

## Phase 8: Configuration & Hardening

```bash
# CORS
grep -rn "Access-Control-Allow-Origin\|allow_origins\|cors" --include="*.{py,js,ts,java,go}" 2>/dev/null

# Debug mode in production
grep -rn "debug=True\|DEBUG=True\|environment.*development\|NODE_ENV.*development" --include="*.{py,js,ts,yaml,yml,env}" 2>/dev/null

# Verbose error pages
grep -rn "traceback\|stacktrace\|debug_info\|show_exceptions" --include="*.{py,js,ts}" 2>/dev/null
```

## Phase 9: Prototype Pollution (JavaScript)

```bash
grep -rn "Object\.assign\|_.merge\|_.extend\|\.assign\b\|\.merge\|\.cloneDeep\|\.set\b\|lodash\|jquery\|$.extend" \
  --include="*.{js,ts}" 2>/dev/null
grep -rn "__proto__\|constructor\.prototype" --include="*.{js,ts}" 2>/dev/null
```
**Detection:** Recursive merge/set operations on untrusted objects without `hasOwnProperty` checks.

## Phase 10: Mobile / APK Specific

When reviewing decompiled APK output (jadx):
```bash
# Hardcoded API endpoints
grep -rn "https\?://" *.java 2>/dev/null | grep -v "android\.\|googleapis\|github\|oauth\."

# Hardcoded secrets in Android resources
grep -rn "api_key\|secret\|token\|password" res/values/strings.xml 2>/dev/null

# Insecure WebView
grep -rn "setJavaScriptEnabled\|loadDataWithBaseURL\|addJavascriptInterface" *.java 2>/dev/null

# Exported components
grep -rn "android:exported=\"true\"" AndroidManifest.xml 2>/dev/null

# Debuggable
grep -rn "android:debuggable=\"true\"" AndroidManifest.xml 2>/dev/null
```

## Common Findings Cheat Sheet

| Pattern | Vuln Class | Confirmation |
|---------|-----------|-------------|
| `f"SELECT * FROM users WHERE id = {user_input}"` | SQLi | `' OR 1=1--` |
| `exec("ping " + user_input)` | Cmd Injection | `; whoami` |
| `open("/uploads/" + filename)` | Path Traversal | `../../etc/passwd` |
| `Template(user_input).render()` | SSTI | `{{7*7}}` |
| `eval(json_data)` | RCE | `__import__('os').system('id')` |
| `pickle.loads(data)` | Deserialization RCE | Standard pickle payload |
| `requests.get(url_param)` | SSRF | Collaborator callback |
| `json.dumps({"role": req.body.role})` | Mass Assignment | `{"role": "admin"}` |
| `Model.find({id: req.params.id})` | NoSQLi | `{"$gt": ""}` |
| `isAdmin = req.query.isAdmin` | PrivEsc | `?isAdmin=true` |

## Severity Rubric

| Severity | Criteria |
|----------|---------|
| CRITICAL | Pre-auth RCE, SQLi with full data exfil, hardcoded cloud creds with IAM access |
| HIGH | Auth SQLi, SSRF with metadata access, command injection, stored XSS on auth pages, IDOR on PII |
| MEDIUM | Reflected XSS, IDOR on non-sensitive data, path traversal on non-critical files, mass assignment on low-priv roles |
| LOW | Missing headers, info disclosure, weak crypto but no practical exploit path, verbose errors |

## Report Template

````markdown
## [SEVERITY] Finding Title

**Location:** `file/path.ext:line_number`
**Class:** SQLi / XSS / SSRF / IDOR / etc

### Root Cause
One sentence explaining the vulnerable pattern.

### Vulnerable Code
```[language]
vulnerable code snippet
```

### Impact
What an attacker can achieve (read all users, takeover admin, etc)

### Proof of Concept
```bash
curl -X GET "https://target.com/vulnerable-endpoint?param=payload"
```

### Remediation
```[language]
fixed code snippet
```

### CVSS: X.X (vector string)
````

## Tooling Reference

| Tool | Language | Use Case |
|------|----------|----------|
| semgrep | All | Custom SAST rules — `semgrep --config=auto .` |
| bandit | Python | `bandit -r . -f json` |
| njsscan | JS/TS | `njsscan .` |
| gosec | Go | `gosec ./...` |
| brakeman | Ruby | `brakeman -q` |
| phpstan | PHP | `phpstan analyse --level=max` |
| find-sec-bugs | Java | SpotBugs plugin for security |
| truffleHog | All | Secret scanning in git history |
| detect-secrets | All | Secret scanning for pre-commit |
| jadx | Android | APK decompile → Java source |
| objection | iOS/Android | Mobile runtime exploration |

## Related Skills

- `code-patch` — once this audit confirms a finding, hand the location and vuln class to `code-patch` to generate a minimal, tested fix.
- `/code-audit` command — the slash entry point that drives this methodology over a path (`/code-audit [path] [--mode quick|full]`).
- `hunt-sqli`, `hunt-xss`, `hunt-ssrf`, `hunt-idor`, `hunt-deserialization`, `hunt-rce` — class-specific hunt skills that deepen exploitation and PoC construction once a grep sink here flags a candidate.
- `report-writing` — turn confirmed findings into submission-ready reports with CVSS and remediation.
