---
name: hunt-aspnet
description: "Hunt ASP.NET across two eras — legacy Webforms/WCF (ViewState deserialization, machineKey recovery, dual-parser MAC-bypass, request-validator bypass, trace.axd/elmah.axd disclosure, load-balanced ViewState cross-node failures, SafeControl reflection, customErrors=Off) AND modern .NET Core/5-8 (Kestrel request smuggling, HTTP/2 Rapid Reset, minimal-API auth gaps, Blazor Server circuit + form-validation bypass, Blazor WASM client-trust leakage, model-binding overposting, Data Protection key mishandling). Built for Webforms + WCF + SharePoint farms and for cloud-hosted ASP.NET Core APIs and Blazor apps."
sources: github, authorized-engagement
report_count: 1
---

# HUNT-ASPNET — ASP.NET (Legacy Webforms/WCF + Modern .NET Core / Blazor)

## Crown Jewel Targets

ASP.NET deserialization bugs pay among the highest amounts in bug bounty when they reach RCE. Even when patched, the disclosure-tier findings (signed-only ViewState, dual-parser differential, request-validator quirks) reliably pay Low-Medium.

**Highest-value targets:**

- **SharePoint farms** (any version — 2013/2016/2019/SE) — sign-only ViewState + permissive ToolPane.aspx + anonymous FormDigest creates the CVE-2025-53770 ToolShell precondition chain
- **Telerik UI for ASP.NET AJAX** — `Telerik.Web.UI.WebResource.axd` is a documented RCE sink when keys leak (CVE-2017-11317, CVE-2017-11357, CVE-2019-18935)
- **Classic ASP.NET Webforms enterprise apps** — banking portals, dealer portals, HR systems left on .NET Framework 4.x
- **WCF services** (`*.svc?WSDL`) — often forgotten admin endpoints with looser auth than the main app
- **Sitecore CMS** — ViewState + Sitecore-specific deserialization chains (CVE-2021-42237)
- **DotNetNuke (DNN)** — historic ViewState RCE chains
- **Umbraco CMS** — ViewState + custom deserialization sinks

**Asset types that pay most:** internet-reachable ASP.NET Webforms apps > WCF admin services > Telerik-integrated sites > Classic ASP.NET MVC with VSF (very rare)

---

## Attack Surface Signals

**Response headers indicating ASP.NET:**
```
X-AspNet-Version: 4.0.30319          (classic — disclosure on its own)
X-Powered-By: ASP.NET
X-AspNetMvc-Version: 5.2
Server: Microsoft-IIS/10.0
Set-Cookie: ASP.NET_SessionId=...
Set-Cookie: .ASPXAUTH=...            (Forms auth cookie)
Set-Cookie: .ASPXFORMSAUTH=...
Set-Cookie: ASP.NET_SessionId=...; SameSite=None  (suggests cross-origin embedding)
```

**Body signals (in form HTML):**
```
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="..." />
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="..." />
<input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
                                        ↑ EMPTY = signed-only, not encrypted = exploitable if key leaks
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="..." />
<input type="hidden" name="__REQUESTDIGEST" id="__REQUESTDIGEST" value="0x...,...">
                                        ↑ SharePoint CSRF token; if anon-issued, see hunt-sharepoint
```

**URL patterns to probe:**
```
/trace.axd                            (per-app trace viewer; sometimes anon-accessible)
/elmah.axd                            (ELMAH error log viewer)
/elmah.axd/?id=...                    (ELMAH RCE / stack-trace leak)
/*.svc                                (WCF services)
/*.svc?wsdl                           (WCF WSDL)
/*.svc/mex                            (Metadata Exchange)
/*.asmx                               (legacy SOAP)
/*.asmx?WSDL                          (legacy SOAP description)
/*.asmx?disco                         (legacy discovery)
/Telerik.Web.UI.WebResource.axd       (Telerik AJAX components)
/ChartImg.axd                         (DataVisualization controls; historic deserialization)
/ScriptResource.axd                   (script resource handler; sometimes leaks paths)
/WebResource.axd                      (web resource handler)
/_vti_bin/*                           (SharePoint Web Service Forwarder)
/api/                                 (Web API 2.x is ASP.NET on classic framework)
/signin                               (often FedAuth / WS-Federation)
```

**Tech-stack signals:**
- `Server: Microsoft-IIS/10.0` (or `/8.5`, `/7.5`) — confirmed Windows + IIS
- `X-AspNet-Version` header — classic .NET Framework (4.x); .NET Core/5+ does NOT emit this
- Cookies with `ASP.NET_SessionId`, `.ASPXAUTH`, `FedAuth` — Forms or claims auth
- `__VIEWSTATE` in form bodies — Webforms (NOT MVC, NOT Razor Pages, NOT Blazor)
- `MicrosoftSharePointTeamServices` header (sometimes stripped by ELB but leaks in `start.aspx` body) — SharePoint

---

## Step-by-Step Hunting Methodology

1. **Fingerprint the framework version.** Trigger any 500 error (stale ViewState POST is a reliable way) and look for `Version Information: Microsoft .NET Framework Version:X.X.XXXXX; ASP.NET Version:X.X.XXXX.X` in the error body. This banner discloses both the runtime and ASP.NET-version-specific patch level. .NET 4.0.30319 + ASP.NET 4.8.x is the most common modern combination.

2. **Locate every form with `__VIEWSTATE`.** Spider the target and grep for `name="__VIEWSTATE"`. Each is a candidate sink for deserialization attacks if MAC / encryption is bypassable.

3. **Check `__VIEWSTATEENCRYPTED` value.** Empty (`value=""`) means ViewState is signed-only via `<machineKey>` but NOT encrypted. Recovery of the validation key → arbitrary deserialization. Non-empty (`value="something"`) means ViewState is BOTH signed and encrypted; both keys needed to forge.

4. **Test the ViewState parser-error differential** (the dual-parser anti-pattern). Send 7+ ViewState shapes and classify responses:
   - Trivial garbage (`AAAA`) → `"Validation of viewstate MAC failed"`
   - Real prefix from current page → `"Validation of viewstate MAC failed"`
   - Flipped-bit real ViewState → `"Validation of viewstate MAC failed"`
   - Oversize (`A * 100000`) → `"Validation of viewstate MAC failed"`
   - XML-shaped (`<xss/>`) → **"The state information is invalid for this page and might be corrupted"** ← different parser path
   - LosFormatter-style prefix (`/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA...`) → **"The state information is invalid for this page and might be corrupted"**

   The differential proves there are **two distinct deserialization entry points**, one of which dispatches BEFORE the MAC check on some payload shapes. Historically this enables MAC-before-parse-bypass exploits.

   **P3 legacy note — .NET 2.0 "ViewState MAC disabled by default" sweet spot (distinct from the 4.x signed-vs-encrypted differential above).** The Section-3/4 logic assumes MAC is *on* and you're classifying signed-only vs encrypted. On ASP.NET 1.1/2.0 (and 3.5, which is CLR 2.0) the runtime did NOT enforce ViewState MAC globally — `enableViewStateMac` could be (and frequently was) `false` per-page or app-wide, and even `MAC=true` apps were exploitable via the CVE-2020-1147 / pre-MS10-070 class of padding-oracle + MAC-strip tricks. When the fingerprint banner (Section 1) reads `ASP.NET Version:2.0.50727.x` — or `X-AspNet-Version: 2.0.50727`, or a `<%@ Page ... %>` with no MAC attribute on a 2.0 app — treat ViewState as **directly forgeable without any key recovery**: a raw `LosFormatter`/`ObjectStateFormatter` gadget (ysoserial.net `--islegacy`) deserializes with no MAC gate at all. This is a different bug than the 4.x case: 4.x always signs (so you need `validationKey`), whereas 2.0 MAC-disabled needs nothing. Probe specifically for it:
   ```bash
   # Confirm legacy runtime + look for MAC-off behavior
   curl -sk -D - "https://target.example/page.aspx" -o /dev/null | grep -i '^X-AspNet-Version: 2.0'
   # Then POST a syntactically-valid-but-unsigned ViewState; on a MAC-on app you get
   #   "Validation of viewstate MAC failed"; on a 2.0 MAC-OFF app it deserializes
   #   (no MAC error) and you proceed straight to gadget delivery — no machineKey needed.
   curl -sk -X POST "https://target.example/page.aspx" \
     --data "__VIEWSTATE=/wEPDwUKLTEx...&__VIEWSTATEGENERATOR=00000000"
   ```

5. **Look for load-balanced cross-node ViewState MAC failures.** If POST gets a 500 with `"Validation of viewstate MAC failed. If this application is hosted by a Web Farm or cluster, ensure that <machineKey> configuration specifies the same validationKey..."`, the farm has multiple WFEs WITHOUT machineKey sync, or without sticky-session affinity. Operationally this breaks legit users; security-wise it confirms farm topology.

6. **Probe `trace.axd` and `elmah.axd`.** If either returns 200 anonymously, it's a Critical finding (trace leaks every request + headers + form data; ELMAH leaks every server error including stack traces).

7. **Enumerate WCF services (`.svc`).** For each, fetch `?wsdl` and `?mex` (metadata exchange). MEX endpoints sometimes return full service contracts including admin operations.

8. **Test request-validator bypass.** ASP.NET's request validator blocks `<` in query strings by default. Bypass categories that may still get through:
   - HTML-entity-encoded payloads (`&lt;script&gt;` — but these don't execute)
   - Encoded inside JSON / XML POST bodies (different content-type ≠ same validator)
   - In path segments (not query) — validator scope depends on framework version
   - In Cookie / Referer headers (varies)
   - Inside `<%@ ... %>` ASP directives if reached via WebDAV PUT (rare)

   **Hand-off to `hunt-xss`.** Request-validator bypass is only an ASP.NET *precondition*, not the bug — the actual finding is the XSS that lands once the validator is defeated. The moment any of the above gets a `<`-bearing payload past the `"Potentially dangerous Request.QueryString value detected"` gate (or past a `ValidateRequest="false"` page, or a `[AllowHtml]`/`[ValidateInput(false)]` MVC action, or a request that bypasses validation via a non-querystring context), STOP testing the validator and switch to `hunt-xss` to prove sink + context + execution. Carry these two facts across the hand-off: (1) **which context** carried the payload (querystring vs JSON/XML body vs cookie vs path vs header) — `hunt-xss` needs it to pick the right reflected/DOM/stored probe; (2) **whether the value persists** (reflected single-response vs stored in a `.aspx`/server-control render) — stored ASP.NET XSS is Medium-High, reflected behind a defeated validator is Low-Medium. Do not report "request validator bypassed" as a standalone finding; it is N/A until `hunt-xss` confirms script execution in a victim's browser.

9. **Check `customErrors` mode.** If 500s expose full stack traces, framework versions, file paths, internal method names → `customErrors mode="Off"` is set. Should be `RemoteOnly` for production.

10. **Look for Telerik components.** `Telerik.Web.UI.WebResource.axd?type=rau` is the historic upload-to-RCE chain (CVE-2017-11317). The `dialogParametersHolder` parameter chain (CVE-2019-18935) requires the encryption key but is otherwise RCE.

11. **SharePoint-specific deserialization paths** — see `hunt-sharepoint` skill for the ToolPane.aspx + anonymous FormDigest + unencrypted ViewState chain.

12. **SafeControl enumeration via reflection.** SharePoint's `Picker.aspx?PickerDialogType=<TypeName>` (and DNN-equivalent endpoints) accept class names and return DIFFERENT error messages for "type exists but not whitelisted" vs "type does not exist." Feed a wordlist of `Microsoft.SharePoint.*.WebControls.*` types to enumerate the SafeControl list — useful for CVE-2019-0604-family hunting.

---

## Modern .NET Surface (.NET Core / 5-8, Kestrel, Minimal APIs, Blazor)

Everything above assumes classic **.NET Framework 4.x Webforms/WCF on IIS**. Modern ASP.NET Core (.NET Core 3.1, .NET 5/6/7/8) is a *different runtime* with a *different attack surface*: no ViewState, no request validator, no `.aspx`/`.svc`, no `X-AspNet-Version` header. It runs on the **Kestrel** HTTP server (often behind IIS/YARP/Nginx as a reverse proxy), uses attribute-routed controllers or minimal APIs, and increasingly ships **Blazor** (Server or WebAssembly). Fingerprint which era you are in FIRST — the wrong methodology wastes the 5-minute rule.

### Validation & False-Positives (Gate 0)

Run this BEFORE writing any modern-.NET finding. A permissive-looking response is not a bug until you cross a trust boundary or reach a sink.

1. **Kestrel smuggling — did a request actually desync, or did you just get a weird 400?** A parsing quirk is only CVE-2025-55315-class when you demonstrate a *smuggled* request reaching app code past the front proxy (e.g. a poisoned response served to a second connection, or a front-end-blocked path reached on the back-end). A lone malformed request that Kestrel rejects with 400 is not smuggling. Prove desync with the classic differential: front-end sees request A, back-end processes A+B. See `hunt-http-smuggling` for the desync oracle — this skill only tells you the target is Kestrel and which .NET version.
2. **Model-binding overposting — did the extra property CHANGE server state?** A 200 on a `PATCH` carrying `IsAdmin=true` proves nothing; MVC may have silently dropped the unbound property. Re-read the entity (`GET` after write) and confirm the field flipped, then confirm the privilege is *enforced* (you can now reach an `[Authorize(Roles="Admin")]` route). Unenforced = informational. This is `hunt-api-misconfig` Gate 0 item 2 applied to the ASP.NET Core binder — see that skill.
3. **Blazor Server — did you bypass a SERVER check, or a client render?** Hiding a button in Razor is UI only; the finding is when an interactive-server event handler / `[Authorize]` component executes for an unauthenticated circuit (CVE-2023-36558 class). Prove the *server* invoked the handler (state changed, DB row written), not that the DOM re-rendered.
4. **Blazor WASM — is the "secret" actually server-side?** A Blazor WebAssembly app ships its entire DLL set to the browser. Config, connection strings, or API keys found in the downloaded `_framework/*.dll` / `blazor.boot.json` are a **client-trust leakage** finding (route to `hunt-source-leak`), NOT server RCE. Confirm the leaked value is *live* (works against the API) before rating it.
5. **Common false positives to kill:** a decompiled Blazor WASM assembly containing a `NEXT_PUBLIC`-equivalent public key (not a secret); a minimal-API endpoint that returns 200 but is genuinely public; a Kestrel 400/431 that is correct hardening; Data-Protection ciphertext you can decode locally but the server never accepts a forged one; a `[BindNever]`/`[FromBody] record` DTO that already blocks the overpost.

### Fingerprint: Core vs Framework (do this first)

```bash
# .NET Core / 5-8 signals — ABSENCE of the classic headers is the tell
curl -skI "https://target.example/" | grep -iE '^(server|x-aspnet-version|x-powered-by):'
#  Server: Kestrel                       -> ASP.NET Core, no reverse proxy (or proxy passes it through)
#  Server: Microsoft-IIS/10.0 + NO X-AspNet-Version  -> IIS in-process/out-of-process hosting Core
#  NO X-AspNet-Version header at all      -> almost certainly Core (Framework emits it unless stripped)
#  NO __VIEWSTATE in any form             -> NOT Webforms; MVC/Razor Pages/minimal-API/Blazor
```

```
Body / route signals:
  <base href="/"> + <script src="_framework/blazor.web.js">   -> Blazor (unified .NET 8 web app)
  <script src="_framework/blazor.server.js">                  -> Blazor Server (SignalR circuit)
  <script src="_framework/blazor.webassembly.js"> + blazor.boot.json  -> Blazor WASM (client ships DLLs)
  /_blazor?id=...  (WebSocket/SSE)                            -> Blazor Server circuit endpoint (see hunt-websocket)
  /_framework/aspnetcore-browser-refresh.js                   -> DEV hot-reload left in prod (info leak)
  Set-Cookie: .AspNetCore.Antiforgery.*                       -> Core antiforgery (Data Protection)
  Set-Cookie: .AspNetCore.Identity.Application               -> ASP.NET Core Identity cookie
  Set-Cookie: .AspNetCore.Cookies                            -> cookie auth via Data Protection
  Bearer JWT in Authorization + no server cookie             -> JWT-bearer minimal API (see hunt-api-misconfig)
  /swagger, /swagger/v1/swagger.json, /openapi/v1.json       -> spec exposure (see hunt-api-misconfig + hunt-source-leak)
```

### Modern methodology

1. **Kestrel HTTP request smuggling (CVE-2025-55315).** All supported ASP.NET Core versions (2.3 on .NET Framework, 8, 9, 10) mis-parsed **chunk extensions** in chunked transfer-encoding: a lone `\n` inside a chunk extension was swallowed while many front proxies treat `\n` as a line terminator — the classic parser-discrepancy desync (CVSS **9.9**, the highest ASP.NET score to date). This is a *front-proxy + Kestrel* bug, so it only bites when a proxy sits in front. Fingerprint the version and hand the desync PoC to `hunt-http-smuggling` (it owns the CL.TE/TE.TE/chunk-extension oracle); this skill's job is to establish "back-end is Kestrel, front-end is X, versions are unpatched."

2. **HTTP/2 Rapid Reset DoS (CVE-2023-44487).** Kestrel (like most HTTP/2 stacks) allowed a client to open then immediately `RST_STREAM`-cancel streams faster than the server reclaimed them → resource exhaustion, exploited in the wild Aug-Oct 2023. On an authorized engagement, do NOT actually flood production — confirm HTTP/2 is offered (`curl -sI --http2 ...`) and check the patch level; report as a *version-based* finding, never by running the DoS. Frame honestly as DoS (see `hunt-http-smuggling` / DoS discipline), not RCE.

3. **HTTP/3 (QUIC) memory-safety bugs.** If the server advertises HTTP/3 (`alt-svc: h3=...`), note **CVE-2024-35264** (Kestrel HTTP/3 data corruption during request-body read → potential RCE) and **CVE-2025-36854** (race condition in HTTP/3 stream handling → use-after-free). These are version-gated: fingerprint the runtime, do not attempt live memory corruption on a bounty target — report as an unpatched-runtime finding and reference the advisory.

4. **Minimal-API / attribute-routed auth gaps.** .NET 6+ minimal APIs (`app.MapGet(...)`) and controller actions rely on `.RequireAuthorization()` / `[Authorize]` being present on *every* route. The common bug is an endpoint that was never decorated — an unauthenticated `/api/internal/*`, `/admin/*`, or `/v0/*` reachable directly. Enumerate the route table from the OpenAPI/Swagger spec (`/swagger/v1/swagger.json` or the .NET 9 built-in `/openapi/v1.json`) and test each for missing authz. Spec-driven mass-authz testing is owned by `hunt-api-misconfig` (BOLA/BFLA + the spec→attack-map workflow) — carry the route list there.

5. **Model-binding overposting (mass assignment).** ASP.NET Core MVC/Razor Pages bind the request body onto a model. When a controller binds directly to the EF Core entity (`public IActionResult Update([FromBody] User u)`) instead of a purpose-built input DTO, any extra property the client sends is bound — `IsAdmin`, `Role`, `EmailConfirmed`, `TenantId`, `OwnerId`. Probe by adding the privileged property alongside a legit one, then Gate 0 item 2 (read back + confirm enforcement). Microsoft's own guidance calls this "overposting" and prescribes `[Bind]`, `[BindNever]`, view models, or `TryUpdateModelAsync(..., includeExpression)`. The full privileged-field wordlist and the read-vs-write-DTO root cause live in `hunt-api-misconfig` (Class 2, Mass Assignment) — cross-link, do not re-transcribe.

   ```bash
   # Baseline write with only a legit field, capture shape
   curl -s -X PUT "https://target.example/api/users/me" \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"displayName":"probe"}' | jq
   # Overpost a privileged EF-entity property alongside it
   curl -s -X PUT "https://target.example/api/users/me" \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"displayName":"probe","role":"Admin","emailConfirmed":true}' | jq
   # GATE 0 item 2 — read back, THEN confirm the new privilege is enforced
   curl -s "https://target.example/api/users/me" -H "Authorization: Bearer $TOKEN" | jq '{role,emailConfirmed}'
   curl -s -o /dev/null -w '%{http_code}\n' "https://target.example/api/admin/dashboard" -H "Authorization: Bearer $TOKEN"
   ```

6. **Blazor Server — circuit + interactive-server form-validation bypass (CVE-2023-36558).** Blazor Server keeps UI state in a server-side **circuit** over a SignalR/WebSocket connection (`/_blazor`). In the disclosed CVE, an unauthenticated user could bypass validation on Blazor Server forms (interactive server-side rendering) and trigger unintended actions — the server executed component event handlers whose guard it assumed the client enforced (affected .NET 6 ≤ 6.0.24, .NET 7 ≤ 7.0.13, .NET 8 RC2; fixed 6.0.25 / 7.0.14 / 8.0.0). Test by driving the circuit directly rather than through the rendered UI: connect to `/_blazor`, replay component-update messages, and invoke event handlers on components/forms the UI hides or marks `[Authorize]`. The WebSocket/SignalR transport mechanics are owned by `hunt-websocket`; the finding here is *a server-side handler firing for an unauthorized circuit*.

7. **Blazor WASM — client-trust leakage.** A Blazor WebAssembly app downloads its full assembly set to the browser (`blazor.boot.json` → `_framework/*.dll` or `*.wasm`). Anything compiled in — appsettings, connection strings, API keys, internal endpoints, authorization *logic* — is client-visible. Pull the boot manifest, download the assemblies, and decompile.

   ```bash
   # Enumerate the shipped assemblies and grab them
   curl -s "https://target.example/_framework/blazor.boot.json" | jq '.resources.assembly // .resources.coreAssembly'
   curl -s -o /tmp/App.dll "https://target.example/_framework/App.wasm"   # (.wasm or .dll depending on runtime)
   # Decompile with an operator disassembler (ilspycmd / monodis) and grep for secrets + internal routes
   ilspycmd /tmp/App.dll > /tmp/App.cs 2>/dev/null && grep -niE 'connectionstring|api[_-]?key|secret|bearer|https?://[a-z0-9.-]*internal' /tmp/App.cs
   ```

   Client-trust leakage is a *source/secret* finding — route recovered secrets and internal routes to `hunt-source-leak` (owns the recover-source → grep-secrets → verify-live workflow); rate only *live* secrets, and treat client-side-only authorization logic as an authz-bypass lead against the real API, not as the bug itself.

8. **Data Protection key mishandling.** ASP.NET Core replaced the Framework `<machineKey>` with the **Data Protection** stack (`.AspNetCore.Antiforgery.*`, `.AspNetCore.Cookies`, `.AspNetCore.Identity.Application`, OIDC `state`, `TempData`, `BearerToken` all ride on it). Two live problem classes: (a) **key ring not persisted / not shared** — in a container or multi-instance deployment without a shared key store (`PersistKeysToFileSystem` on an ephemeral volume, or no Redis/Blob/DPAPI key ring), each instance/restart generates a new key so antiforgery + auth cookies break across nodes (the Core analogue of the Web-Farm machineKey desync in the legacy section — operationally breaks users, confirms topology); (b) **CVE-2026-40372** — the managed `ManagedAuthenticatedEncryptor` computed its HMAC integrity tag over the wrong payload slice, weakening the integrity guarantee for forged Data-Protection tokens (antiforgery/auth cookies/OIDC state/`BearerToken`/custom `IDataProtector` consumers); patch is .NET 10.0.7-class. Report as version-gated; do not fabricate a forgery you cannot reproduce. If you *recover* a Data-Protection key set (from a config/source leak), the deserialization/forgery consequences are owned by `hunt-deserialization`.

9. **Dev-leftover surfaces on Core.** `aspnetcore-browser-refresh.js` (hot-reload script) in a prod page, the `DeveloperExceptionPage` middleware left on (full stack trace + `Environment=Development` banner — the Core equivalent of `customErrors mode="Off"` above), `/swagger` UI enabled in prod, and `ASPNETCORE_ENVIRONMENT=Development` leaking via error detail. Trigger an unhandled exception (malformed JSON body to a strongly-typed action) and inspect for the developer exception page vs the generic `/error` handler.

### Modern CVE grounding (all real, verify before citing)

- **CVE-2025-55315** — ASP.NET Core Kestrel HTTP request smuggling via chunk-extension lone-`\n` parsing discrepancy; CVSS **9.9**, all supported versions (8/9/10 + 2.3 on .NET Framework).
- **CVE-2023-44487** — HTTP/2 "Rapid Reset" DoS; Kestrel among affected stacks; exploited in the wild 2023.
- **CVE-2024-35264** — Kestrel HTTP/3 request-body data corruption → potential RCE.
- **CVE-2025-36854** — ASP.NET Core HTTP/3 stream-handling race condition → use-after-free.
- **CVE-2023-36558** — Blazor Server interactive-server form-validation bypass (unauthenticated action trigger); fixed 6.0.25 / 7.0.14 / 8.0.0.
- **CVE-2024-21319** — .NET / ASP.NET Core Identity JWT DoS (untrusted-token processing).
- **CVE-2026-40372** — ASP.NET Core Data Protection `ManagedAuthenticatedEncryptor` HMAC tag computed over the wrong slice → integrity bypass on Data-Protection-issued tokens; OOB fix in .NET 10.0.7.
- **CVE-2025-53690** — Sitecore ViewState deserialization zero-day via a **sample/exposed machineKey** (the bridge between the legacy ViewState section and modern Sitecore-on-Core deployments; deserialization mechanics owned by `hunt-deserialization`).

---

## Payload & Detection Patterns

**Stack-trace fingerprint (trigger via stale ViewState POST):**
```bash
curl -sk -X POST "https://target.example/page.aspx" \
  --data "__VIEWSTATE=AAAA&__VIEWSTATEGENERATOR=AAAA"
# Inspect body for:
#  - "Validation of viewstate MAC failed" → confirms signed ViewState
#  - "The state information is invalid for this page" → confirms ALTERNATE parser path
#  - "Version Information: Microsoft .NET Framework Version:X.X.XXXXX" → exact patch level
#  - "Microsoft.SharePoint.Client.ServerStub..." → SharePoint farm
```

**ViewState parser-error differential probe (Python):**
```python
import requests, re, json
S = requests.Session(); S.verify = False
# Get fresh form
r = S.get("https://target.example/path/page.aspx")
real_vs = re.search(r'__VIEWSTATE" id="__VIEWSTATE" value="([^"]+)', r.text).group(1)
real_vsg = re.search(r'__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="([^"]+)', r.text).group(1)

# Test 7 payload shapes
for label, vs in [
    ("trivial",      "AAAA"),
    ("real",         real_vs),
    ("flipped-bit",  real_vs[:50] + "X" + real_vs[51:]),
    ("oversize",     "A" * 100000),
    ("base64",       "VGVzdE1hcmtlcjY3OFhZWg=="),
    ("xml-shaped",   "<xss/>"),
    ("losformatter", "/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA" + "A"*50),
]:
    r = S.post("https://target.example/path/page.aspx",
               data={"__VIEWSTATE": vs, "__VIEWSTATEGENERATOR": real_vsg})
    title = re.search(r'<title>([^<]+)</title>', r.text)
    title = title.group(1)[:100] if title else "—"
    print(f"  [{label:14s}] {r.status_code}  {title}")
```

**`trace.axd` anonymous check:**
```bash
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.example/trace.axd"
# 200 = full trace dump exposed → Critical
# 403 = mod set to localhost-only → check via X-Forwarded-For: 127.0.0.1
```

**WCF service enumeration:**
```bash
# Find all .svc files
curl -sk "https://target.example/" -o body.html
grep -oE '/[a-zA-Z0-9/_-]+\.svc' body.html | sort -u
# For each found:
curl -sk "https://target.example/Service.svc?wsdl" | xmllint --format - | head -60
```

**Request-validator bypass categories:**
```
# Default: <script>alert(1)</script> in ?q= → "Potentially dangerous Request.QueryString value detected"
# Bypasses that sometimes work:
?q=%3cscript%3e            (URL-encoded — depends on validator config)
?q=<svg/onload=alert(1)>  (depends on validator version)
?q=<%00script>             (NUL-byte; older validators)
?q=javascript:alert(1)     (no < at all — passes validator)
Cookie: foo=<script>       (cookie body not validated by default)
Referer: http://x.com/<script>  (referer not validated in classic ASP.NET)
```

**Telerik exploit gate (CVE-2019-18935 — requires encryption keys):**
```bash
# Fingerprint Telerik
curl -sk "https://target.example/Telerik.Web.UI.WebResource.axd?type=rau" -X POST
# If response is RadAsyncUploadHandler-style → Telerik present; try keys
# Public exploits require leaked machineKey AND telerikEncryptionKey
```

---

## Common Root Causes

1. **`viewStateEncryption="Auto"` defaults to signed-only on pages without sensitive ViewState data.** Many SharePoint pages are configured this way. When `__VIEWSTATEENCRYPTED` is empty, ViewState is signed-only — recovery of `validationKey` alone enables forgery.

2. **`<machineKey>` AutoGenerate in a Web Farm.** Each WFE generates a different key on first boot; ViewState issued by one WFE fails MAC validation on another. Operationally produces 500s; security-wise broadcasts the topology (the error message names the cluster).

3. **`<customErrors mode="Off">` left from development.** Stack traces with full method names, file paths, version banners exposed to anonymous internet users.

4. **`trace.axd` / `elmah.axd` left enabled in production.** Often forgotten in `<system.web><trace enabled="true">` blocks.

5. **Forgotten WCF `.svc` admin endpoints.** Built for internal admin tooling, never disabled when the main app went to internet exposure.

6. **Dual-parser anti-pattern: `ObjectStateFormatter` (legacy) vs `LosFormatter` (modern) deserialize in different orders relative to MAC validation.** Some payload shapes hit the legacy parser BEFORE MAC check.

7. **Request validator only applies to URL-encoded body and querystring.** Headers, cookies, XML/JSON bodies, and multipart fields are NOT validated by default. Developers assume validator is universal; it is not.

8. **`<machineKey>` checked into source repos.** Configuration check-ins to GitHub frequently leak validation/decryption keys. Combine with `hunt-misc` source-recon for Telerik / SharePoint / DNN keys.

9. **`SafeControls` web.config entries trusted to gate deserialization.** SharePoint's `<SafeControl>` list determines which classes Picker.aspx can instantiate. Bypasses exist when the inheritance check is the only gate (CVE-2019-0604 family).

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| `__VIEWSTATEENCRYPTED` non-empty (encrypted) | Recover both decryption + validation keys from any source-code leak / config-disclosure / VS forge primitive; without keys, deserialization cannot be triggered |
| Request validator blocks `<` in querystring | Move payload to Cookie / Referer / JSON body / multipart filename — validator doesn't reach those contexts in classic ASP.NET |
| `EnableViewStateMac="true"` enforced | Recover `validationKey` from web.config disclosure or `<machineKey>` AutoGenerate fingerprinting (ysoserial.net `--minify --islegacy` mode generates ViewState that passes some MAC-validation gaps) |
| `trace.axd` localhost-only | Set `X-Forwarded-For: 127.0.0.1` if the trace mode is `localOnly` and the validation uses Request.UserHostAddress (some apps use Forwarded-For instead) |
| WCF `.svc` 401 on anonymous | Try `?wsdl` and `?mex` first; metadata is sometimes anonymously enumerable even when service ops require auth |
| Telerik upload patched | Check the Telerik version: anything pre-2017Q1 (build 2017.1.118 or earlier) is the original RAU RCE. Check 2017Q3 - 2019Q3 for CVE-2019-18935 |
| `SafeControl` whitelist enforced | Inheritance gate (`instanceof PickerDialog`) IS the gate on patched SP — bypass requires finding a SafeControl subclass with a deserialization sink; enumerate via Picker.aspx |
| `customErrors mode="On"` (no stack traces) | Force a different error path: invalid Content-Length, malformed ViewState that triggers a parser-level exception below the customErrors handler |

---

## Gate 0 Validation

Before writing the report, confirm:

1. **What can the attacker DO right now with the disclosed information?**
   - `trace.axd` 200 with full request dump → **Critical** (PII / session cookies / Authorization headers exposed)
   - `elmah.axd` 200 with error log → **High** (stack traces + internal paths + sometimes credentials)
   - `__VIEWSTATEENCRYPTED` empty + recoverable machineKey via separate finding → **Critical chain to RCE**
   - `__VIEWSTATEENCRYPTED` empty without key recovery → **Low-Medium** (primitive present, not exploitable on its own)
   - Stack traces in 500s → **Low** unless they include credentials / connection strings

2. **Have you reproduced the full chain to attacker-attainable impact, or only the primitive?**
   - Cross-reference `triage-validation` Pre-Severity Gate. "Primitive confirmed" is not Critical until the chain ends in impact.

3. **Can a triager reproduce in <10 min from your report?**
   - Each step copy-pasteable curl / Python.
   - For RCE chains: link the public exploit tool (ysoserial.net, viewgen, telerik-revda) and the specific gadget chain.

---

## Real Impact Examples

### Scenario A — Signed-only ViewState + permissive ToolPane on EoL SharePoint 2013

`https://target-portal.example/_layouts/15/ToolPane.aspx?DisplayMode=Edit` returns 200 anonymously. The form contains `__VIEWSTATE` (signed only — `__VIEWSTATEENCRYPTED=""`), and `__REQUESTDIGEST` is anonymously issued via `_api/contextinfo`. Combined with SP2013 being end-of-life (no patch will ever ship), this is the canonical CVE-2025-53770 "ToolShell" precondition chain on a permanently-unpatched code path. Reported severity: **Critical**. The dual-parser test (Section 4 of Methodology) confirmed that XML-shaped payloads reach the legacy `ObjectStateFormatter` BEFORE MAC validation — additional evidence that the chain is reachable even without full machineKey recovery (though full RCE requires both).

### Scenario B — Telerik RadAsyncUploadHandler exposed on legacy bank portal

`/Telerik.Web.UI.WebResource.axd?type=rau` returns the Telerik upload handler. Telerik version (visible in JS bundle metadata) is 2016.3.1027. CVE-2017-11317 applies — keys are baked into the public Telerik DLL of that version. Upload → write `aspx` to `/app_data/` → request → RCE. Reported severity: **Critical**.

### Scenario C — trace.axd + elmah.axd both exposed on enterprise HR portal

`trace.axd` 200 returns 50 most recent requests, including `Authorization: Bearer eyJ...` headers on API requests. `elmah.axd` 200 returns full error log with database connection-string in one of the exceptions. Reported severity: **Critical** (credentials in plaintext to anonymous internet).

---

## Related Skills & Chains

- **`hunt-rce`** — ViewState deserialization is the headline ASP.NET RCE path; signed-only ViewState + leaked machineKey = RCE every time. Chain primitive: ASP.NET ViewState dual-parser MAC-bypass anti-pattern detected (signed but not encrypted, `<%@ Page enableViewStateMac="true" viewStateEncryptionMode="Never" %>`) + machineKey recovered (from web.config disclosure, `elmah.axd`, source leak, or GitHub) → `hunt-rce` ysoserial.net `TypeConfuseDelegate` gadget → arbitrary command in `w3wp.exe` worker-process identity.
- **`hunt-sharepoint`** — SharePoint farms inherit every ASP.NET anti-pattern plus their own surface. Chain primitive: ASP.NET fingerprint reveals SharePoint (X-SharePoint headers + `/_layouts/` reachable) → pivot to `hunt-sharepoint` for SP-specific RCE paths (ToolShell, SafeControl reflection) before generic ViewState attack.
- **`hunt-ntlm-info`** — IIS sites that advertise NTLM/Negotiate anonymously leak AD topology. Chain primitive: ASP.NET app behind IIS with `WWW-Authenticate: NTLM` → `hunt-ntlm-info` Type-2 challenge capture → internal forest name → cross-reference Entra tenant via `m365-entra-attack` discovery.
- **`hunt-file-upload`** — Telerik RadAsyncUpload, Kentico, Umbraco, and DotNetNuke all have historical upload-handler RCE. Chain primitive: ASP.NET CMS fingerprinted → `hunt-file-upload` bypass matrix against the CMS upload handler → `.aspx` written into web-accessible path → request → RCE under app-pool identity.
- **`hunt-deserialization`** — owns the gadget-chain mechanics for BOTH eras (cross-link, not duplicated): legacy .NET `BinaryFormatter`/`LosFormatter`/`ObjectStateFormatter` ViewState gadgets, and modern Sitecore/Core ViewState deserialization (CVE-2025-53690, sample/exposed machineKey). Chain primitive: this skill confirms the *precondition* (signed-only ViewState, recovered `machineKey`/Data-Protection key set from a config or source leak) → hand the key + sink to `hunt-deserialization` for the actual gadget construction and OOB/command-output proof. Do not re-derive gadget chains here; the kill gate (Interactsh callback or command output, never "500 = RCE") lives there.
- **`hunt-source-leak`** — owns the recover-source → grep-secrets → verify-live workflow (cross-link, not duplicated): Blazor WASM `_framework/*.dll`/`blazor.boot.json` client-trust leakage, `.js.map`/webpack recovery, and (legacy) `web.config`/`<machineKey>` disclosure and GitHub key check-ins. Chain primitive: this skill fingerprints Blazor WASM or the ASP.NET config surface → route the downloaded assemblies/config to `hunt-source-leak`; it verifies whether a recovered API key / connection string / `machineKey` / Data-Protection key is *live* before anyone rates it. Client-side-only authorization logic recovered there becomes an authz-bypass lead against the real API, not a standalone bug.
- **`hunt-api-misconfig`** — owns the modern-API bug depth (cross-link, not duplicated): the model-binding overposting field wordlist + read-vs-write-DTO root cause (Class 2), the OpenAPI/Swagger spec→attack-map + NSwag exposure workflow, BOLA/BFLA mass-authz testing, and JWT-bearer attacks (`alg=none`, key confusion, `jku`/`kid`) via `jwt_tool`. Chain primitive: this skill fingerprints ASP.NET Core minimal APIs / Swagger / JWT-bearer auth → carry the enumerated route table and the overpost candidate fields to `hunt-api-misconfig`, and apply its Gate 0 (read-back + enforced-privilege) to any overposting/mass-assignment claim here.
- **`hunt-http-smuggling`** — owns the request-desync oracle (cross-link, not duplicated): CL.TE/TE.TE and the chunk-extension parser-discrepancy behind Kestrel CVE-2025-55315, plus HTTP/2 Rapid Reset (CVE-2023-44487) DoS discipline. Chain primitive: this skill establishes "back-end is Kestrel, versions unpatched, front proxy is X" → hand the desync PoC to `hunt-http-smuggling`, which proves the smuggled request reaches app code past the proxy (a lone Kestrel 400 is not a finding).
- **`hunt-websocket`** — owns the SignalR/WebSocket transport mechanics for the Blazor Server circuit (`/_blazor`). Chain primitive: this skill flags the interactive-server circuit + a `[Authorize]`/validation-guarded component (CVE-2023-36558 class) → drive the circuit directly via `hunt-websocket` to invoke the server-side event handler for an unauthorized connection.
- **`hunt-xss`** — the ASP.NET request validator is only a *guard*; the bug is the XSS behind it. Chain primitive: request-validator bypass confirmed (Methodology step 8 — `<` reaches a sink via JSON/XML body, cookie, path segment, `ValidateRequest="false"` page, or `[ValidateInput(false)]`/`[AllowHtml]` MVC action) → hand off to `hunt-xss` carrying the **delivery context** and **persistence** (reflected vs stored) → `hunt-xss` proves sink/context/execution and assigns severity. The ASP.NET side stops at "validator defeated"; `hunt-xss` owns the reflected-vs-stored verdict. Conversely, if `hunt-xss` finds an apparent block on a `<`-payload, check back here first: it may be the request validator (a server-side ASP.NET gate), not output encoding — bypass categories above reopen the sink.
- **`triage-validation`** — `trace.axd`/`elmah.axd` disclosure is only Critical when it actually leaks live credentials/tokens; pure stack traces are usually Low. Chain primitive: pull every reported finding through `triage-validation` 7-Question Gate before submission — distinguish "verbose error" (informational) from "live bearer token in error log" (Critical) before writing the report (`redteam-report-template`).
