---
name: bug-bounty
description: "Complete bug bounty workflow — recon (subdomain enumeration, asset discovery, fingerprinting, HackerOne scope, source code audit), pre-hunt learning (disclosed reports, tech stack research, threat modeling), vulnerability hunting (IDOR, SSRF, XSS, auth bypass, CSRF, race conditions, SQLi, XXE, file upload, business logic, GraphQL, HTTP smuggling, cache poisoning, OAuth, SSTI, subdomain takeover, cloud misconfig, ATO chains, AI), LLM/AI security testing (prompt injection, ASCII smuggling, exfil channels, system prompt extraction, ASI01-ASI10), A-to-B bug chaining (IDOR→auth bypass, SSRF→cloud metadata, XSS→ATO, open redirect→OAuth theft, S3→bundle→secret→OAuth), bypass tables (SSRF IP bypass, open redirect bypass, file upload bypass), language-specific grep, and reporting (7-Question Gate, CVSS 3.1, PoC generation, always-rejected list). Use for ANY bug bounty task — recon, hunting, source code audit, AI testing, validation, or writing reports. 中文触发词：漏洞赏金、安全测试、渗透测试、漏洞挖掘、信息收集、子域名枚举、XSS测试、SQL注入、SSRF、安全审计、漏洞报告"
---

# Bug Bounty Master Workflow

Full pipeline: Recon -> Learn -> Hunt -> Validate -> Report. One skill for everything.

## THE ONLY QUESTION THAT MATTERS

> **"Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions -- and does it cause real harm (stolen money, leaked PII, account takeover, code execution)?"**
>
> If the answer is NO -- **STOP. Do not write. Do not explore further. Move on.**

### Theoretical Bug = Wasted Time. Kill These Immediately:

| Pattern | Kill Reason |
|---|---|
| "Could theoretically allow..." | Not exploitable = not a bug |
| "An attacker with X, Y, Z conditions could..." | Too many preconditions |
| "Wrong implementation but no practical impact" | Wrong but harmless = not a bug |
| Dead code with a bug in it | Not reachable = not a bug |
| Source maps without secrets | No impact |
| SSRF with DNS-only callback | Need data exfil or internal access |
| Open redirect alone | Need ATO or OAuth chain |
| "Could be used in a chain if..." | Build the chain first, THEN report |

**You must demonstrate actual harm. "Could" is not a bug. Prove it works or drop it.**

---

## CRITICAL RULES

1. **READ FULL SCOPE FIRST** -- verify every asset/domain is owned by the target org
2. **NO THEORETICAL BUGS** -- "Can an attacker steal funds, leak PII, takeover account, or execute code RIGHT NOW?" If no, STOP.
3. **KILL WEAK FINDINGS FAST** -- run the 7-Question Gate BEFORE writing any report
4. **Validate before writing** -- check CHANGELOG, design docs, deployment scripts FIRST
5. **One bug class at a time** -- go deep, don't spray
6. **Verify data isn't already public** -- check web UI in incognito before reporting API "leaks"
7. **5-MINUTE RULE** -- if a target shows nothing after 5 min probing (all 401/403/404), MOVE ON
8. **IMPACT-FIRST HUNTING** -- ask "what's the worst thing if auth was broken?" If nothing valuable, skip target
9. **CREDENTIAL LEAKS need exploitation proof** -- finding keys isn't enough, must PROVE what they access
10. **STOP SHALLOW RECON SPIRALS** -- don't probe 403s, don't grep for analytics keys, don't check staging domains that lead nowhere
11. **BUSINESS IMPACT over vuln class** -- severity depends on CONTEXT, not just vuln type
12. **UNDERSTAND THE TARGET DEEPLY** -- before hunting, learn the app like a real user
13. **DON'T OVER-RELY ON AUTOMATION** -- automated scans hit WAFs, trigger rate limits, find the same bugs everyone else finds
14. **HUNT LESS-SATURATED VULN CLASSES** -- XSS/SSRF/XXE have the most competition. Expand into: cache poisoning, Android/mobile vulns, business logic, race conditions, OAuth/OIDC chains, CI/CD pipeline attacks
15. **ONE-HOUR RULE** -- stuck on one target for an hour with no progress? SWITCH CONTEXT
16. **TWO-EYE APPROACH** -- combine systematic testing (checklist) with anomaly detection (watch for unexpected behavior)
17. **T-SHAPED KNOWLEDGE** -- go DEEP in one area and BROAD across everything else

> **For the full hunting methodology** — 5-phase non-linear workflow, developer psychology framework, session discipline, tool routing by phase, and Wide/Deep route selection — see **`skills/bb-methodology/SKILL.md`**.

---

## AUTH-AWARE HUNTING (when bugs live behind a login)

Anonymous recon misses the bugs that pay most. IDOR, BOLA, mass-assignment,
privilege escalation, auth bypass, SSRF behind login, and most LLM/agent
bugs are invisible until you log in. Load auth **once** at session start and
every downstream tool (httpx, katana, ffuf, nuclei, dalfox, the SQLi / SSTI
/ upload PoC verifiers) sends those headers automatically.

```bash
# Pick ONE of these and run hunt.py normally:
python3 tools/hunt.py --target T --cookie 'session=eyJabc...'
python3 tools/hunt.py --target T --bearer 'eyJhbGciOi...'
python3 tools/hunt.py --target T --auth-file .private/T.json

# Or via env (persists for the shell):
export BBHUNT_COOKIE='session=eyJabc...'
python3 tools/hunt.py --target T
```

**For IDOR / BOLA hunts**, load two sessions and diff behavior:

```bash
python3 tools/hunt.py --target T --auth-file .private/T-user-a.json
python3 tools/hunt.py --target T --auth-file .private/T-user-b.json
# Audit log entries carry different session_id hashes → diff which
# endpoints behaved differently per identity.
```

**Safety**: cookies/tokens never appear in logs, hunt-memory, or `repr()`.
Only a 12-char `session_id` hash is recorded. `.private/` is gitignored.
MFA-skip and SAML signature-stripping probes deliberately stay anonymous —
that's the attack they're checking for.

Full guide: `docs/auth-sessions.md`. Template: `docs/auth.example.json`.

---

## A->B BUG SIGNAL METHOD (Cluster Hunting)

**When you find bug A, systematically hunt for B and C nearby.** This is one of the most powerful methodologies in bug bounty. Single bugs pay. Chains pay 3-10x more.

### Known A->B->C Chains

| Bug A (Signal) | Hunt for Bug B | Escalate to C |
|----------------|---------------|---------------|
| IDOR (read) | PUT/DELETE on same endpoint | Full account data manipulation |
| SSRF (any) | Cloud metadata 169.254.169.254 | IAM credential exfil -> RCE |
| XSS (stored) | Check if HttpOnly is set on session cookie | Session hijack -> ATO |
| Open redirect | OAuth redirect_uri accepts your domain | Auth code theft -> ATO |
| S3 bucket listing | Enumerate JS bundles | Grep for OAuth client_secret -> OAuth chain |
| Rate limit bypass | OTP brute force | Account takeover |
| GraphQL introspection | Missing field-level auth | Mass PII exfil |
| Debug endpoint | Leaked environment variables | Cloud credential -> infrastructure access |
| CORS reflects origin | Test with credentials: include | Credentialed data theft |
| Host header injection | Password reset poisoning | ATO via reset link |

### Cluster Hunt Protocol (6 Steps)

```
1. CONFIRM A     Verify bug A is real with an HTTP request
2. MAP SIBLINGS  Find all endpoints in the same controller/module/API group
3. TEST SIBLINGS Apply the same bug pattern to every sibling
4. CHAIN         If sibling has different bug class, try combining A + B
5. QUANTIFY      "Affects N users" / "exposes $X value" / "N records"
6. REPORT        One report per chain (not per bug). Chains pay more.
```

### Real Examples

**Coinbase S3->Bundle->Secret->OAuth chain:**
```
A: S3 bucket publicly listable (Low alone)
B: JS bundles contain OAuth client credentials
C: OAuth flow missing PKCE enforcement
Result: Full auth code interception chain
```

**Vienna Chatbot chain:**
```
A: Debug parameter active in production (Info alone)
B: Chatbot renders HTML in response (dangerouslySetInnerHTML)
C: Stored XSS via bot response visible to other users
Result: P2 finding with real impact
```

---

# TOP 1% HACKER MINDSET

## How Elite Hackers Think Differently

**Average hunter**: Runs tools, checks checklist, gives up after 30 min.
**Top 1%**: Builds a mental model of the app's internals. Asks "why does this work the way it does?" Not "what does this endpoint do?" but "what business decision led a developer to build it this way, and what shortcut might they have taken?"

## Pre-Hunt Mental Framework

### Step 1: Crown Jewel Thinking
Before touching anything, ask: "If I were the attacker and I could do ONE thing to this app, what causes the most damage?"
- Financial app -> drain funds, transfer to attacker account
- Healthcare -> PII leak, HIPAA violation
- SaaS -> tenant data crossing, admin takeover
- Auth provider -> full SSO chain compromise

### Step 2: Developer Empathy
Think like the developer who built the feature:
- What was the simplest implementation?
- What shortcut would a tired dev take at 2am?
- Where is auth checked -- controller? middleware? DB layer?
- What happens when you call endpoint B without going through endpoint A first?

### Step 3: Trust Boundary Mapping
```
Client -> CDN -> Load Balancer -> App Server -> Database
         ^               ^              ^
    Where does app STOP trusting input?
    Where does it ASSUME input is already validated?
```

### Step 4: Feature Interaction Thinking
- Does this new feature reuse old auth, or does it have its own?
- Does the mobile API share auth logic with the web app?
- Was this feature built by the same team or a third-party?

## The Top 1% Mental Checklist
- [ ] I know the app's core business model
- [ ] I've used the app as a real user for 15+ minutes
- [ ] I know the tech stack (language, framework, auth system, caching)
- [ ] I've read at least 3 disclosed reports for this program
- [ ] I have 2 test accounts ready (attacker + victim)
- [ ] I've defined my primary target: ONE crown jewel I'm hunting for today

## Mindset Rules from Top Hunters

**"Hunt the feature, not the endpoint"** -- Find all endpoints that serve a feature, then test the INTERACTION between them.

**"Authorization inconsistency is your friend"** -- If the app checks auth in 9 places but not the 10th, that's your bug.

**"New == unreviewed"** -- Features launched in the last 30 days have lowest security maturity.

**"Think second-order"** -- Second-order SSRF: URL saved in DB, fetched by cron job. Second-order XSS: stored clean, rendered unsafely in admin panel.

**"Follow the money"** -- Any feature touching payments, billing, credits, refunds is where developers make the most security shortcuts.

**"The API the mobile app uses"** -- Mobile apps often call older/different API versions. Same company, different attack surface, lower maturity.

**"Diffs find bugs"** -- Compare old API docs vs new. Compare mobile API vs web API. Compare what a free user can request vs what a paid user gets in response.

---

# TOOLS

## Go Binaries
| Tool | Use |
|------|-----|
| subfinder | Passive subdomain enum |
| httpx | Probe live hosts |
| dnsx | DNS resolution |
| nuclei | Template scanner |
| katana | Crawl |
| waybackurls | Archive URLs |
| gau | Known URLs |
| dalfox | XSS scanner |
| ffuf | Fuzzer |
| anew | Dedup append |
| qsreplace | Replace param values |
| assetfinder | Subdomain enum |
| gf | Grep patterns (xss, sqli, ssrf, redirect) |
| interactsh-client | OOB callbacks |

## Tools to Install When Needed
| Tool | Use | Install |
|------|-----|---------|
| arjun | Hidden parameter discovery | `pip3 install arjun` |
| paramspider | URL parameter mining | `pip3 install paramspider` |
| kiterunner | API endpoint brute | `go install github.com/assetnote/kiterunner/cmd/kr@latest` |
| cloudenum | Cloud asset enumeration | `pip3 install cloud_enum` |
| trufflehog | Secret scanning | `brew install trufflehog` |
| gitleaks | Secret scanning | `brew install gitleaks` |
| XSStrike | Advanced XSS scanner | `pip3 install xsstrike` |
| SecretFinder | JS secret extraction | `pip3 install secretfinder` |
| sqlmap | SQL injection | `pip3 install sqlmap` |
| subzy | Subdomain takeover | `go install github.com/LukaSikic/subzy@latest` |

## Static Analysis (Semgrep Quick Audit)
```bash
# Install: pip3 install semgrep

# Broad security audit
semgrep --config=p/security-audit ./
semgrep --config=p/owasp-top-ten ./

# Language-specific rulesets
semgrep --config=p/javascript ./src/
semgrep --config=p/python ./
semgrep --config=p/golang ./
semgrep --config=p/php ./
semgrep --config=p/nodejs ./

# Targeted rules
semgrep --config=p/sql-injection ./
semgrep --config=p/jwt ./

# Custom pattern (example: find SQL concat in Python)
semgrep --pattern 'cursor.execute("..." + $X)' --lang python .

# Output to file for analysis
semgrep --config=p/security-audit ./ --json -o semgrep-results.json 2>/dev/null
cat semgrep-results.json | jq '.results[] | select(.extra.severity == "ERROR") | {path:.path, check:.check_id, msg:.extra.message}'
```

## FFUF Advanced Techniques
```bash
# THE ONE RULE: Always use -ac (auto-calibrate filters noise automatically)
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac

# Authenticated raw request file — IDOR testing (save Burp request to req.txt, replace ID with FUZZ)
seq 1 10000 | ffuf --request req.txt -w - -ac

# Authenticated API endpoint brute
ffuf -u https://TARGET/api/FUZZ -w wordlist.txt -H "Cookie: session=TOKEN" -ac

# Parameter discovery
ffuf -w ~/wordlists/burp-parameter-names.txt -u "https://target.com/api/endpoint?FUZZ=test" -ac -mc 200

# Hidden POST parameters
ffuf -w ~/wordlists/burp-parameter-names.txt -X POST -d "FUZZ=test" -u "https://target.com/api/endpoint" -ac

# Subdomain scan
ffuf -w subs.txt -u https://FUZZ.target.com -ac

# Filter strategies:
# -fc 404,403          Filter status codes
# -fs 1234             Filter by response size
# -fw 50               Filter by word count
# -fr "not found"      Filter regex in response body
# -rate 5 -t 10        Rate limit + fewer threads for stealth
# -e .php,.bak,.old    Add extensions
# -o results.json      Save output
```

## AI-Assisted Tools
- **strix** (usestrix.com) -- open-source AI scanner for automated initial sweep

## AI-ASSISTED HUNT LOOP

Use AI as a second analyst, not as the authority.

1. **Decompose the feature** — ask for actors, assets, trust boundaries, hidden state, and sibling endpoints.
2. **Generate the test matrix** — anonymous vs authenticated, user A vs user B, fresh vs stale session, web vs mobile, legacy vs current API.
3. **Ask for developer shortcuts** — where a rushed implementation would likely skip a check, reuse a helper, or trust a client-side value.
4. **Ask for adjacent bugs** — if A is real, what B and C are likely nearby?
5. **Convert every idea into one request** — the output must be a concrete HTTP experiment or it stays speculation.
6. **Proof first, report later** — AI can rank hypotheses, but only live request/response diffs and cross-account deltas can promote a finding.

Good prompt shapes:
- "Given this feature, list the 10 most likely trust-boundary mistakes."
- "What sibling routes, methods, or roles should I test next?"
- "What would a tired developer probably reuse here?"
- "What is the smallest reproducible request that could prove impact?"
- "What evidence would downgrade this to N/A?"

---

# PHASE 1: RECON

## Standard Recon Pipeline
```bash
# Step 1: Subdomains
subfinder -d TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only TARGET | anew /tmp/subs.txt

# Step 2: Resolve + live hosts
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect -o /tmp/live.txt

# Step 3: URL collection
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -silent | anew /tmp/urls.txt
echo TARGET | waybackurls | anew /tmp/urls.txt
gau TARGET | anew /tmp/urls.txt

# Step 4: Nuclei scan
nuclei -l /tmp/live.txt -severity critical,high,medium -silent -o /tmp/nuclei.txt

# Step 5: JS secrets
cat /tmp/urls.txt | grep "\.js$" | sort -u > /tmp/jsfiles.txt
# Run SecretFinder on each JS file

# Step 6: GitHub dorking (if target has public repos)
# GitDorker -org TARGET_ORG -d dorks/alldorksv3
```

## Cloud Asset Enumeration
```bash
# Manual S3 brute
for suffix in dev staging test backup api data assets static cdn; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://${TARGET}-${suffix}.s3.amazonaws.com/")
  [ "$code" != "404" ] && echo "$code ${TARGET}-${suffix}.s3.amazonaws.com"
done
```

## API Endpoint Discovery
```bash
# ffuf API endpoint brute
ffuf -u https://TARGET/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,403 -ac
```

## HackerOne Scope Retrieval
```bash
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { team(handle: \"PROGRAM_HANDLE\") { name url policy_scopes(archived: false) { edges { node { asset_type asset_identifier eligible_for_bounty instruction } } } } }"}' \
  | jq '.data.team.policy_scopes.edges[].node'
```

## Quick Wins Checklist
- [ ] Subdomain takeover (`subjack`, `subzy`)
- [ ] Exposed `.git` (`/.git/config`)
- [ ] Exposed env files (`/.env`, `/.env.local`)
- [ ] Default credentials on admin panels
- [ ] JS secrets (SecretFinder, jsluice)
- [ ] Open redirects (`?redirect=`, `?next=`, `?url=`)
- [ ] CORS misconfig (test `Origin: https://evil.com` + credentials)
- [ ] S3/cloud buckets
- [ ] GraphQL introspection enabled
- [ ] Spring actuators (`/actuator/env`, `/actuator/heapdump`) — for full framework debug surface + triggering techniques → web2-vuln-classes "Error Disclosure / Debug Endpoints"
- [ ] Firebase open read (`https://TARGET.firebaseio.com/.json`)

## Technology Fingerprinting

| Signal | Technology |
|---|---|
| Cookie: `XSRF-TOKEN` + `*_session` | Laravel |
| Cookie: `PHPSESSID` | PHP |
| Header: `X-Powered-By: Express` | Node.js/Express |
| Response: `wp-json`/`wp-content` | WordPress |
| Response: `{"errors":[{"message":` | GraphQL |
| Header: `X-Powered-By: Next.js` | Next.js |

> **After any stack is identified:** immediately check its debug surface — probe the framework-specific paths from web2-vuln-classes "Error Disclosure / Debug Endpoints", then grep all 4xx/5xx response bodies for the framework regex patterns there before moving to Phase 3.

## Framework Quick Wins

**Laravel**: `/horizon`, `/telescope`, `/.env`, `/storage/logs/laravel.log`
**WordPress**: `/wp-json/wp/v2/users`, `/xmlrpc.php`, `/?author=1`
**Node.js**: `/.env`, `/graphql` (introspection), `/_debug`
**AWS Cognito**: `/oauth2/userInfo` (leaks Pool ID), CORS reflects arbitrary origins

## Source Code Recon
```bash
# Security surface
cat SECURITY.md 2>/dev/null; cat CHANGELOG.md | head -100 | grep -i "security\|fix\|CVE"
git log --oneline --all --grep="security\|CVE\|fix\|vuln" | head -20

# Dev breadcrumbs
grep -rn "TODO\|FIXME\|HACK\|UNSAFE" --include="*.ts" --include="*.js" | grep -iv "test\|spec"

# Dangerous patterns (JS/TS)
grep -rn "eval(\|innerHTML\|dangerouslySetInner\|execSync" --include="*.ts" --include="*.js" | grep -v node_modules
grep -rn "===.*token\|===.*secret\|===.*hash" --include="*.ts" --include="*.js"
grep -rn "fetch(\|axios\." --include="*.ts" | grep "req\.\|params\.\|query\."

# Dangerous patterns (Solidity)
grep -rn "tx\.origin\|delegatecall\|selfdestruct\|block\.timestamp" --include="*.sol"
```

### Language-Specific Grep Patterns

```bash
# JavaScript/TypeScript -- prototype pollution, postMessage, RCE sinks
grep -rn "__proto__\|constructor\[" --include="*.js" --include="*.ts" | grep -v node_modules
grep -rn "postMessage\|addEventListener.*message" --include="*.js" | grep -v node_modules
# ↑ If listeners found, verify origin-check robustness with attacker page —
#   see web2-vuln-classes section 3 "postMessage Testing"
grep -rn "child_process\|execSync\|spawn(" --include="*.js" | grep -v node_modules

# Python -- pickle, yaml.load, eval, shell injection
grep -rn "pickle\.loads\|yaml\.load\|eval(" --include="*.py" | grep -v test
grep -rn "subprocess\|os\.system\|os\.popen" --include="*.py" | grep -v test
grep -rn "__import__\|exec(" --include="*.py"

# PHP -- type juggling, unserialize, LFI
grep -rn "unserialize\|eval(\|preg_replace.*e" --include="*.php"
grep -rn "==.*password\|==.*token\|==.*hash" --include="*.php"
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" --include="*.php" | grep "include\|require\|file_get"

# Go -- template.HTML, race conditions
grep -rn "template\.HTML\|template\.JS\|template\.URL" --include="*.go"
grep -rn "go func\|sync\.Mutex\|atomic\." --include="*.go"

# Ruby -- YAML.load, mass assignment
grep -rn "YAML\.load[^_]\|Marshal\.load\|eval(" --include="*.rb"
grep -rn "attr_accessible\|permit(" --include="*.rb"

# Rust -- panic on network input, unsafe blocks
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" | grep -v "test\|encode\|to_bytes\|serialize"
grep -rn "unsafe {" --include="*.rs" -B5 | grep "read\|recv\|parse\|decode"
grep -rn "as u8\|as u16\|as u32\|as usize" --include="*.rs" | grep -v "checked\|saturating\|wrapping"
```

---

# PHASE 2: LEARN (Pre-Hunt Intelligence)

## Read Disclosed Reports
```bash
# By program on HackerOne
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ hacktivity_items(first:25, order_by:{field:popular, direction:DESC}, where:{team:{handle:{_eq:\"PROGRAM\"}}}) { nodes { ... on HacktivityDocument { report { title severity_rating } } } } }"}' \
  | jq '.data.hacktivity_items.nodes[].report'
```

## "What Changed" Method
1. Find disclosed report for similar tech
2. Get the fix commit
3. Read the diff -- identify the anti-pattern
4. Grep your target for that same anti-pattern

## Threat Model Template
```
TARGET: _______________
CROWN JEWELS: 1.___ 2.___ 3.___
ATTACK SURFACE:
  [ ] Unauthenticated: login, register, password reset, public APIs
  [ ] Authenticated: all user-facing endpoints, file uploads, API calls
  [ ] Cross-tenant: org/team/workspace ID parameters
  [ ] Admin: /admin, /internal, /debug
HIGHEST PRIORITY (crown jewel x easiest entry):
  1.___ 2.___ 3.___
```

## Extended Content

This page only contains the core methodology. Extended reference content (payloads, full tables, detailed examples) has been moved to [`references/`](references/bug-bounty-reference.md) for size management.

