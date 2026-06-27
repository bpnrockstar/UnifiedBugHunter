---
name: osint-methodology
description: "Comprehensive OSINT methodology for external red-team operations and authorized attack-surface assessments. Covers 5-stage recon pipeline (seed discovery, asset expansion, enrichment, exposure analysis, reporting), asset-graph discipline with 29 asset types, severity rubric (CRITICAL/HIGH/MEDIUM/LOW/INFO), confidence upgrade workflows, identity-fabric mapping (Entra/Okta/ADFS/Google/SAML/M365), API and auth-map methodology, JS analysis, mobile/cloud attack surface, breach×identity correlation, detection-aware probing, WAF/CDN bypass + origin discovery, vulnerability prioritization (CVE/EPSS/KEV), phishing infrastructure planning, bug bounty/client deliverable templates, threat-actor investigation (incl. RU/CN pivots), cryptocurrency tracing, image/video forensics, chronolocation. Use when planning or executing recon against authorized targets, mapping external attack surface, investigating a person/entity, tracing crypto flows, geolocating media, or performing attribution work."
version: 2.1
triggers:
  - external recon
  - external red team
  - red team external
  - attack surface management
  - attack surface mapping
  - ASM
  - perimeter recon
  - target reconnaissance
  - bug bounty recon
  - asset discovery
  - footprint
  - attack path
  - identity fabric
  - SSO discovery
  - IdP fingerprinting
  - tenant fingerprinting
  - M365 enumeration
  - Microsoft 365 recon
  - API discovery
  - GraphQL introspection
  - mobile recon
  - APK analysis
  - cloud bucket enumeration
  - bucket enum
  - breach correlation
  - secret leak hunt
  - origin discovery
  - CDN bypass
  - WAF bypass
  - vulnerability prioritization
  - CVE prioritization
  - EPSS
  - CISA KEV
  - phishing infrastructure
  - pretext development
  - bug bounty submission
  - responsible disclosure
  - client report
  - exec summary
  - risk translation
  - confidence upgrade
  - time budget
  - engagement profile
  - asset triage
  - detection-aware probing
  - back-off strategy
  - persona rotation
  - OSINT methodology
  - open source intelligence
  - target profiling
  - data correlation
  - OSINT workflow
  - intelligence collection
  - OSINT campaign
  - recon methodology
  - threat actor investigation
  - attribution
---

# OSINT Methodology — External Red-Team Edition

## 0. When to use this skill / When NOT

**Use this skill when:**
- Planning or executing external reconnaissance against an authorized target (red team, bug bounty in-scope, ASM engagement).
- Mapping an organization's external attack surface end-to-end (subdomains → assets → exposure → attack paths).
- Investigating a person, entity, or threat actor where evidence discipline matters.
- Tracing cryptocurrency flows, geolocating media, performing image/video forensics, or chronolocating events.
- Building a structured OSINT campaign that needs reproducibility, severity grading, and clean handoffs.
- Producing client-facing deliverables (exec summaries, technical reports, reproduction packages) from offensive engagements.

**Do NOT use this skill when:**
- The user is asking for active exploitation, post-exploitation, lateral movement, AD privilege escalation, malware development, or anything beyond reconnaissance — those are out of scope.
- The user is asking for blue-team / defensive content (SIEM rules, detection engineering) — different domain.
- The target's authorization is unclear and the user is asking you to act against a third-party asset they don't own — see §1 below; gently surface the scope question before proceeding.

---

## 1. Authorization & Legal Posture

This skill is intended for assets the operator owns or has written authorization to assess (red-team rules of engagement, bug-bounty in-scope assets, ASM contracts).

**Soft scope check:** when a user asks you to act against a target whose authorization isn't established earlier in the conversation, ask once before proceeding:

> *"Quick scope check: is this a target you own or have written authorization to assess (e.g., a red-team engagement, in-scope bug-bounty asset, or your own infrastructure)? I want to make sure we stay on the right side of the engagement boundary."*

Once authorization is asserted, proceed without re-asking. If the user explicitly states the engagement type (e.g., "this is for our pentest of acme.com under contract"), you don't need to ask again.

**Always-on guardrails (regardless of authorization):**
- Never weaken auth, rate limits, banners, or any safety control that enforces scope on the target side.
- Never run destructive probes (true SYN scans on production, masscan at line rate, fuzzing/brute-force) outside an explicit DEEP / `--aggressive` mode.
- Never paste real PII, valid credentials, session tokens, API keys, or other secrets into cloud-hosted LLMs or third-party services.
- Never take action against assets outside the documented scope, even if "obviously related" (subsidiaries, vendors, employees' personal accounts, etc.).

---

## 2. Confidence Levels

Every assertion you make during an engagement should carry a confidence level. Three levels:

| Level | Meaning | Examples |
|---|---|---|
| **TENTATIVE** | Plausible based on indirect evidence; unverified. | Snippet-only Google dork match; email pattern inferred from name; subdomain returned by one passive source only; favicon-hash overlap (two hosts share a favicon — could be shared infra, could be a coincidence). |
| **FIRM** | Directly observed but uncorroborated. | Subdomain that resolves to an IP; HEAD-confirmed bucket exists (private); CT-log entry shows certificate; Shodan banner returned. |
| **CONFIRMED** | Multiple independent corroborations OR directly verified. | Live-validated PMAK token (read-only `/me` returned 200); breach corpus + crt.sh + DNS all agree; bucket listable AND files retrievable; user enumerated AND password reset flow returns valid hint. |

**Rule of three for attribution:** require three independent weak signals, OR one strong + one weak, before asserting linkage. Don't single-source attribute.

### 2.1 Confidence Upgrade Workflows

Confidence isn't static — every TENTATIVE asset should have a documented path to FIRM and to CONFIRMED. Use these per-asset-type rules.

| Asset type | TENTATIVE → FIRM | FIRM → CONFIRMED |
|---|---|---|
| **Subdomain** | Returned by ≥2 independent passive sources, OR DNS A/AAAA/CNAME resolves successfully. | Serves on a standard port (80/443/22/etc.) AND HTTP banner / TLS cert / SSH banner returned. |
| **IP** | Discovered via ≥2 sources (passive DNS, ASN lookup, Shodan). | Active probe responds (TCP SYN-ACK on at least one port, or ICMP echo reply). |
| **WebApp** | URL extracted from JS / API / archive but not yet hit. | HTTP request returns 2xx/3xx/4xx (any non-network-error response) AND content-length > 0. |
| **Email** | Generated from a name pattern OR returned by snippet-only dork. | Listed in Hunter.io / EmailRep / IntelX / breach corpus, OR `MAIL FROM`/`RCPT TO` SMTP probe returns 250 (without delivery — abort at DATA). |
| **Bucket (S3/GCS/Azure)** | Permutation candidate; no probe yet. | HEAD returns 200, 301, or 403 (existence confirmed). Then CONFIRMED when GET returns object listing or known object retrieval. |
| **Endpoint (API / wayback)** | Extracted from JS regex / Wayback / Postman. | HTTP request returns non-404 (route exists). Then CONFIRMED when the endpoint's behavior is fingerprinted (auth posture, response shape, rate limits). |
| **Credential / secret** | Matches catalog regex in captured text. | Read-only validator (`/me`, `auth.test`, `sts:GetCallerIdentity`, `/user`) returns success. Then CONFIRMED with documented scope + account ID. |
| **Person** | Name extracted from a single source (LinkedIn / breach / GitHub commit). | Confirmed by a second source (Hunter.io role + LinkedIn profile, or two breach sources with same email). |
| **Repo** | Name match on org keyword in GitHub search. | Repo metadata shows confirmed org/email/website match. Then CONFIRMED when commit-history shows employee involvement. |
| **Mobile app** | Name match in app store. | Ownership-confidence score ≥70 (see companion skill §21). Then CONFIRMED when binary metadata (signing cert, package name, dev account) ties back to target. |
| **Certificate** | Returned by crt.sh once. | CT-log entry confirmed in ≥2 logs. Then CONFIRMED when serving on a discovered host. |
| **SSO tenant** | Discovery-endpoint returns OIDC metadata. | Tenant GUID extracted AND domain resolves through the tenant's expected MX / autodiscover / SP record. |

**Default reporting posture:** never claim CONFIRMED without explicit corroboration. When in doubt, downgrade. Operators trust under-claims more than over-claims.

---

## 3. Output Format Conventions

When you produce findings during an active session, structure each finding to match the schema below — it drops cleanly into asset-management tools.

```
Finding:
  id:           <stable hash or UUID>
  module:       <which technique discovered it; "manual" if hand-found>
  asset_key:    <typed key, e.g. sub:api.example.com or webapp:https://example.com/admin>
  category:     <e.g. SECRET_LEAK, MISSING_HSTS, OPEN_GRAPHQL_API, LEAKED_CRED, SSO_EXPOSURE>
  severity:     <info|low|medium|high|critical>
  confidence:   <tentative|firm|confirmed>
  title:        <one-line summary>
  description:  <2-5 sentences>
  evidence:
    url:        <where it was found>
    timestamp:  <UTC ISO8601>
    sha256:     <hash of any downloaded artifact>
    raw:        <truncated to 2 KiB>
  references:
    - <CVE-ID, advisory URL, vendor doc>
  remediation:  <action the asset owner can take>
```

**Always use UTC timestamps**. Local time creates correlation bugs across notes/screenshots/logs.

---

## 4. Source Hygiene & Citations

For every artifact you capture, record: **URL + UTC timestamp + SHA-256 hash + tool version + run_id**.

- Hash all downloaded files with SHA-256.
- Screenshot in PNG (lossless, smaller than full-page WARC for evidence packs).
- Capture raw HTTP requests/responses, capped at 2 KiB body to keep evidence packs small.
- Use JSONL (NDJSON) logs, one line per event, with a `run_id` so the entire engagement is replayable.
- Separate evidence read-only from working copies; never edit captured artifacts.

When citing a source in your output, prefer durable references (CVE, vendor advisory, ATT&CK technique ID, RFC) over ephemeral ones (a Twitter post, a forum thread). If the only source is ephemeral, archive it (archive.today, Wayback SavePageNow) before citing.

---

## 5. Do NOT (hard rules)

- DO NOT paste creds, session tokens, API keys, real PII, infostealer logs, or unique pivots into cloud LLMs (ChatGPT, Claude.ai, Gemini, Perplexity). Use local models (Ollama, LM Studio, GPT4All) for sensitive analysis.
- DO NOT assume vendor labels are ground truth. Cross-label sanity: TRM, Chainalysis, Arkham can disagree. Treat every label as a hypothesis.
- DO NOT assume 1:1 bridge flows. Bridges/mixers/wrappers introduce mint/burn semantics; validate with on-chain proofs.
- DO NOT assert ownership from a single signal. Favicon-hash overlap, shared CT issuer, shared NS — each is a hypothesis. Need rule-of-three.
- DO NOT run fuzzing, SYN scans, masscan, or `nuclei fuzzing/*` templates outside an explicit DEEP / `--aggressive` mode.
- DO NOT use a credential validator to do anything except read-only verification (no create/delete/send).
- DO NOT mirror-image (assume the target thinks like you do). Separate capability from intent and sponsorship.
- DO NOT confuse correlation with control.
- DO NOT escalate when you encounter active defenses; back off and document (see §6.4).

---

## 6. OpSec

### 6.1 Sock Puppets

A sock puppet is a fake account that cannot be linked to you. Build a posting history, age the account, use it from a separate browser profile.

Resources & techniques:
- Persona generation: [Fake Name Generator](https://www.fakenamegenerator.com/), [This Person Does Not Exist](https://thispersondoesnotexist.com/).
- Browser isolation: [Firefox Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/), or dedicated profiles per persona.
- Disposable phone numbers: Burner, Silent Link (some platforms reject VoIP — keep a backlog of numbers).
- Hardware passkeys for any high-value persona; store recovery codes offline.
- Audit every browser extension before installation. Supply-chain attacks on popular extensions have repeatedly targeted investigators — assume the popular ones are at higher risk, not lower.
- Maintain chain-of-custody: timestamp every action, hash every key artifact, record tool versions per case.
- Personas should look like real low-engagement accounts: profile photo (synthetic), bio, a few low-effort posts spread across weeks before the persona is "used."

References:
- [Effective Sock Puppets](https://medium.com/@unseeable06/creating-an-effective-sock-puppet-for-your-osint-investigation-95fdbb8b075a)
- [Ultimate Guide to Sock Puppets](https://osintteam.blog/the-ultimate-guide-to-sockpuppets-in-osint-how-to-create-and-utilize-them-effectively-d088c2ed6e36)

### 6.2 Detectability & OpSec Tagging

Every probe leaves a footprint. Tag every operation in your notes with a detectability level so you can reason about the SIEM trail you're leaving on the target's side.

| Tag | Examples |
|---|---|
| **Low** | Passive Shodan InternetDB; CT-log queries (crt.sh); Wayback CDX; passive DNS (SecurityTrails); Hunter.io email enrichment; HTTP HEAD on public buckets; `getuserrealm.srf`; Microsoft OIDC metadata fetch. |
| **Medium** | Microsoft `GetCredentialType` user-enum; Okta `/api/v1/authn` user-enum; Postman API key validation; AWS `sts:GetCallerIdentity` (logs to CloudTrail); Slack `auth.test`; full-page screenshots; Swagger/GraphQL probes against a 28/13-path wordlist; targeted favicon-hash + JARM fingerprinting. |
| **High** | Active port scans (naabu / masscan / nmap); Nuclei full template runs against production; subdomain brute-force at scale; APK download from third-party mirrors; deep-mode user enumeration past N attempts per tenant; SMTP `RCPT TO` enumeration; web fuzzing (ffuf/gobuster). |

When working with a client, document the operations actually run and their detectability tag in the engagement report — clients appreciate knowing what their detection stack should have caught.

**Defaults:** passive by default. Active probes only when (a) explicitly authorized, (b) within agreed maintenance windows, and (c) with the operator's awareness of the resulting log volume.

### 6.3 Validator Discipline

When you discover a credential in the wild (a leaked API key, a sourcemap-exposed token, a hard-coded PMAK in a public Postman workspace), you may want to confirm it's live. Do this with **read-only validators only**.

Discipline:
- Read-only endpoint only (e.g., `/me`, `/whoami`, `auth.test`, `sts:GetCallerIdentity`).
- Never use the validated credential to create, modify, delete, or send anything.
- Tag the validation attempt with detectability — every validator generates an audit-log entry on the provider side.
- Record `checked_at` (UTC), the response (truncated), and the scope/account-ID returned.
- If the operator's rules of engagement forbid validation, mark the credential `validation_skipped_by_policy` and stop.

Concrete validator endpoints (Postman, AWS, GitHub, Slack, Anthropic, OpenAI, npm, Atlassian, DataDog) live in the companion `offensive-osint` skill.

### 6.4 Detection-Aware Probing (signs of detection + back-off)

Your probes will eventually hit detection. Recognize the signs and back off **before** you trip an active response.

**Signs you've been detected (in roughly increasing severity):**

1. **Rate-limit responses** — `429 Too Many Requests`, `Retry-After` header set, `X-RateLimit-Remaining: 0`.
2. **Captcha interstitials** — Cloudflare interstitial page, hCaptcha challenge, AWS WAF page.
3. **WAF page** — explicit "Access denied" with provider branding (Cloudflare, Akamai, Imperva, F5 ASM, AWS WAF, Sucuri).
4. **Status code drift** — endpoints that previously returned 200/401 now return 403 only from your IP.
5. **Banner change** — server header shape or response timing changes consistently.
6. **DNS poisoning back to NXDOMAIN** — target's authoritative servers stop resolving subdomains (probably their CDN took over).
7. **Honeypot bait** — endpoints that look too good (`/admin/db_dump.sql`, exposed `.env` with credentials that don't validate). Real exposures rarely look this clean.
8. **Direct contact** — your sock-puppet email gets a "we noticed unusual activity" message; or, in extreme cases, your IP gets a courtesy abuse-contact email.

**Back-off ladder:**

1. **Slow down.** Halve your concurrency. Add 2–10s jitter between requests.
2. **Switch endpoints.** Stop hitting the path that triggered. Move to a different module of the recon pipeline.
3. **Switch persona.** New User-Agent (rotate among realistic browsers), new TLS fingerprint (different httpx/curl version).
4. **Switch IP.** Rotate to a new egress (residential proxy, Tor for sensitive lookups, a different cloud region).
5. **Pause.** Wait 1–24 hours. Many WAFs have rolling-window IP-based reputation; passive time often resets it.
6. **Document and consult.** If you've hit (3) WAF, (4) status drift, or (8) direct contact, **stop active probing and consult the engagement lead**. Continued probing past these signals risks scope violation.

**Persona / IP rotation rules:**
- Never rotate persona to one that's been used in a prior engagement against the same target.
- Use residential proxies (Bright Data, Smartproxy, IPRoyal) for high-detectability work — but be aware they're sometimes IP-blocklisted by Cloudflare.
- Tor exit nodes are useful for **passive lookups** (CT logs, archive sites) but are blocked by most active-probe targets.
- Cloud egress IPs (AWS / GCP / Azure) are often blocklisted aggressively for recon. Use sparingly.
- Document every rotation with timestamp + reason; reviewers will ask.

**Don't:**
- Don't try to "outsmart" a confirmed WAF block by sending more aggressive payloads. That's how clients get extra logs and how you get caught.
- Don't switch source IPs to evade an explicit block-list — that crosses into evasion territory and may breach the rules of engagement.
- Don't ignore signals because the dashboard says "still up." The probe is being silently logged; the response will come later.

---

## 7. External Red-Team Recon Pipeline

A 5-stage pipeline for any authorized external assessment. Stages are sequential; modules within a stage can run concurrently.

### Stage 1 — Seed Discovery
Establish the ground truth of who/what the target is.

- WHOIS on the seed domain (registrant, dates, name servers).
- ASN enumeration: which AS does the org own/use? (Hurricane Electric BGP Toolkit, RIPEstat, BGPView.)
- DNS records (A/AAAA/MX/TXT/NS/SOA/CAA) — records-only, no walking yet.
- Certificate Transparency history for the root domain (crt.sh, Censys).

### Stage 2 — Asset Expansion
Discover everything that might belong to the target.

- Subdomain enumeration (passive sources first: crt.sh, VirusTotal, AlienVault OTX, Shodan, then permutations and bruteforce).
- Cloud bucket enumeration (S3/GCS/Azure permutations from company name + subdomain stems — see §15).
- Typosquat domain generation (dnstwist variants → resolve → WHOIS) — for both phishing risk and adjacent corp assets.
- Wayback CDX archive endpoints for forgotten paths.
- Mobile app discovery (Android via google-play-scraper, iOS via iTunes Search API — see §14).
- DNS deep walking (NSEC walk on misconfigured zones, AXFR opportunism).
- LinkedIn employee enumeration → email-pattern derivation.

### Stage 3 — Enrichment
Add depth to the discovered assets.

- Port + service detection (Shodan InternetDB free → naabu/masscan if authorized).
- Live TLS handshakes (cert chain, JARM, favicon mmh3 hash).
- Web tech detection (Wappalyzer-style ~600 signatures via httpx).
- WAF/CDN inference (header markers).
- Origin discovery if behind CDN (see §27).
- Security header audit.
- Bulk screenshots (triage 1000s of hosts visually).
- Email harvesting (6 parallel sources).
- Email security audit (SPF/DMARC/DKIM/BIMI/MTA-STS).
- GitHub code-search dorking (13 dork templates × 29+ secret regexes).
- JavaScript deep analysis (sourcemaps, secrets, endpoints, internal-host leakage).
- SSO/IdP tenant fingerprinting (Entra, Okta, ADFS, Google, SAML, M365 Teams/SharePoint/OAuth — see §11).
- API & auth-map discovery (Swagger/OpenAPI, GraphQL, Postman).
- Secrets-beyond-GitHub sweep (Postman public workspaces, Stack Exchange, Trello/Notion/Atlassian dorks).
- Vendor product fingerprinting (Citrix/F5/PaloAlto/Pulse/Fortinet/Cisco/VMware/Exchange).
- Container / CI-CD / cloud-native exposure check.
- Job posting harvest for tech-stack inference.

### Stage 4 — Exposure Analysis
Convert assets into findings.

- Nuclei (15 always-on built-in checks + optional binary).
- TLS deep audit (sslyze / testssl.sh).
- Breach × identity correlation (HudsonRock Cavalier, HIBP, DeHashed, IntelX, local corpus → SSO_EXPOSURE findings).
- Targeted misconfiguration probes (`.git/config`, `.env`, `phpinfo.php`, `/actuator/env`, `/actuator/heapdump`, `_cat/indices`, `/console`, `/manager/html`).
- Vulnerability prioritization (CVE × EPSS × CISA KEV × public-POC availability — see §28).

### Stage 5 — Reporting
Make the work usable.

- Risk scoring per finding (CVSS + program-specific weights).
- Asset graph export (D3-friendly nodes/links, GraphML, JSON).
- Client-facing report (executive summary + technical detail + remediation — see §31).
- Reproduction package (run_id, tool versions, raw evidence, JSONL log).
- Bug bounty submission (if applicable — see §30).

### 7.5 Pipeline Priority Order (highest signal density first)

When budget is constrained, work in this order:

1. **Breaches** — infostealer logs (HudsonRock Cavalier free tier) + HIBP + DeHashed. Highest ROI for red teams; often gives valid plaintext creds for corp SSO. Requires emails as input.
2. **GitHub recon** — code-search dorks. Finds AWS keys, Slack tokens, JWT secrets, `.env` files. Fastest path to cloud pivot.
3. **Nuclei misconfig sweep** — exposed admin panels, CVEs with public POCs.
4. **Cloud buckets** — permutate company name + subdomain stems. Listable bucket = CRITICAL.
5. **Ports** — Shodan InternetDB first (free, keyless). VPN concentrators, RDP, Jenkins, GitLab-CE, Elasticsearch are the high-value pivot points.
6. **Email OSINT** — feeds breaches; feeds phishing list.
7. **Web tech / WAF / screenshots** — triage thousands of hosts; know the stack before probing.
8. **Wayback** — archived JS often has hard-coded keys; archived endpoints reveal removed admin/dev paths.
9. **DNS deep + email security** — SPF/DMARC gaps enable email spoofing; TXT verification tokens reveal SaaS tenancies.
10. **Certificates** — CT-log timeline catches forgotten subdomains; weak ciphers = cheap findings.
11. **ASN + reverse DNS** — corporate IP space hosts unadvertised infra.
12. **WHOIS** — registrant PII reveals adjacent corp assets.
13. **Typosquat** — actively-registered squats are findings; unregistered ones go on the phishing-domain shortlist.
14. **Security headers** — low standalone value but required for client reports.

### 7.6 Time Budgeting & Engagement Profiles

Stage and asset count drive how long a recon takes. Rough estimates (single operator on a typical SaaS-style target):

| Stage | Small org (<100 employees) | Medium (100–1K) | Large (1K+) |
|---|---|---|---|
| 1. Seed discovery | 30 min | 30 min | 30 min |
| 2. Asset expansion | 1–2 h | 2–4 h | 4–8 h |
| 3. Enrichment (per 100 alive webapps) | ~1 h | ~1 h | ~1 h |
| 4. Exposure analysis | 1–3 h | 3–6 h | 6–12 h |
| 5. Reporting | 2–4 h | 4–8 h | 1–2 days |

**Engagement profiles:**

- **1-hour rapid recon ("how exposed is X?")** — Stage 1 (15 min) → passive subdomain (crt.sh + Subfinder, 10 min) → Shodan InternetDB on resolved IPs (5 min) → email harvest via Hunter+IntelX (10 min) → breach lookup on emails (10 min) → executive-summary-only output (10 min).
- **4-hour focused recon ("phish-readiness check")** — adds: full email harvest, LinkedIn employee enum, SPF/DMARC analysis, typosquat candidate generation, SSO/IdP fingerprinting. Output: phishing-feasibility report + target email list.
- **1-day standard recon** — full Stages 1–4 with the priority order above. Output: per-asset finding list + asset graph + exec summary.
- **1-week deep recon** — all of standard, plus: deep-mode user enumeration, JS deep analysis at full budget, mobile attack surface, cloud-native fingerprinting, vendor product fingerprinting, package registry leak hunting, vulnerability prioritization. Output: full client deliverable package + reproduction bundle.
- **Ongoing monitoring (weekly diff)** — re-run Stages 1–3 weekly; diff against baseline; alert on new asset / new finding / asset disappeared.

**When to abort early:**
- After Stage 1 if scope is wrong (target turns out to be subsidiary of unrelated corp; rules of engagement need clarification).
- After Stage 2 if attack surface is below threshold (no public webapps + no exposed services + no leaked emails → little to find externally).
- During any stage if you hit the WAF / detection signs in §6.4.

---

## 8. Asset Graph Discipline

Treat every discovery as a typed asset in a graph, not a free-floating string.

### 8.1 Asset Taxonomy (29 types)

| Category | Asset Types |
|---|---|
| **DNS / Network** | `domain`, `subdomain`, `ip`, `netblock`, `asn` |
| **Service** | `port`, `service`, `certificate` |
| **Identity** | `email`, `person`, `credential` |
| **Code / Config** | `repo`, `secret` |
| **Cloud / Storage** | `bucket`, `firebase_project` |
| **Web** | `webapp`, `wayback_endpoint`, `api_endpoint`, `api_spec`, `graphql_schema` |
| **Mobile** | `mobile_app`, `deep_link`, `exported_component` |
| **Phishing / Adversarial** | `typosquat_domain` |
| **Collaboration / SaaS** | `postman_collection`, `postman_workspace`, `postman_api_key`, `stack_post`, `saas_public_surface` |

### 8.2 Asset Schema

Every asset carries:
- `type` — one of the 29 above.
- `key` — unique dedup id (typed prefix, e.g. `sub:api.example.com`, `email:alice@example.com`).
- `value` — the actual string/object.
- `sources[]` — every source that confirmed this asset (deduplicated).
- `confidence` — TENTATIVE / FIRM / CONFIRMED.
- `first_seen`, `last_seen` — UTC timestamps.
- `attrs{}` — type-specific metadata (e.g., for a `webapp`: status_code, title, tech-stack list, JARM, favicon mmh3, screenshot path).

### 8.3 Edge Taxonomy

Relationships are typed edges, not text:
`RESOLVES_TO`, `HOSTED_ON`, `IN_NETBLOCK`, `BELONGS_TO_ASN`, `LISTED_IN_CERT`, `OWNED_BY`, `ALIAS_OF`, `BREACHED_FROM`, `EMPLOYED_BY`, `HOSTS_REPO`, `TYPOSQUAT_OF`, `EXPOSES`, `DOCUMENTED_BY`, `BELONGS_TO_HOST`, `REQUIRES_AUTH`, `LEAKS_SCHEMA`, `SHIPPED_BY_ORG`, `CONTAINS_SECRET`, `TALKS_TO_HOST`, `EXPOSES_DEEPLINK`, `HAS_EXPORTED_COMPONENT`, `USES_FIREBASE_PROJECT`, `LACKS_PINNING_FOR`.

### 8.4 Discipline rules

- **Every discovery is an asset.** Don't write findings against free-floating strings; create the asset first, then attach the finding.
- **Dedup by key, not by value.** Same value, different type ≠ same asset (`sub:api.example.com` and `webapp:https://api.example.com/` are different assets with a `BELONGS_TO_HOST` edge).
- **Provenance is non-negotiable.** `sources[]` must list every source. If two sources confirmed it, both go in.
- **Confidence is per-source, then aggregated.** A subdomain returned by 3 passive sources is FIRM; one returned by snippet-only Bing is TENTATIVE.
- **Late binding via sidecars.** When module A produces output that module B needs, write a JSON sidecar (`mobile_endpoints.json`, `secrets_sidecar.json`) — don't block module B on module A. See §24.

### 8.5 Asset-Level Triage Rules

When you have a mixed bag of assets and limited probe budget, prioritize by what each asset *enables*:

**WebApp priority by hostname signal (highest first):**

1. Auth-related hostnames (`auth.`, `login.`, `sso.`, `idp.`, `accounts.`, `oauth.`).
2. Admin paths (`/admin`, `/dashboard`, `/console`, `/manager`, `/wp-admin`, `/phpmyadmin`).
3. Dev/staging hosts (`dev.`, `staging.`, `stg.`, `qa.`, `uat.`, `test.`, `sandbox.`, `preprod.`, `preview.`) — lower defenses, often dump prod data.
4. API hostnames (`api.`, `services.`, `gateway.`, `graph.`).
5. Customer-facing hostnames (`portal.`, `app.`, `my.`, `account.`).
6. Marketing / content (`www.`, `blog.`, `news.`, `careers.`, `support.`).

**Subdomain priority by inferred function:**

- API > Admin > Dev > Auth > Prod-app > Marketing.

**IP priority by netblock:**

- Corporate ASN-owned (most likely to host unadvertised internal infra).
- Cloud netblocks (AWS / GCP / Azure / DO / OVH) — high turnover but interesting for cloud-native services.
- CDN ranges (Cloudflare / Akamai / Fastly) — usually edge, not origin; defer unless doing origin discovery.

**Email priority by role hint:**

| Role indicator | Priority | Why |
|---|---|---|
| `ceo@`, `cfo@`, `cto@`, `ciso@` | HIGHEST | Exec accounts have highest breach value (BEC, finance authority, board access). |
| `it@`, `helpdesk@`, `support@`, `security@` | HIGH | IT/security accounts have privileged tool access; helpdesk accounts handle reset workflows. |
| `dev`, `engineer`, `architect`, `dba` | MEDIUM | Developer accounts often have GitHub / cloud / CI access. |
| `sales`, `marketing`, `hr`, `finance` | MEDIUM | SaaS access (Salesforce, HubSpot, Workday); finance enables BEC. |
| Generic role accounts (`info@`, `noreply@`, `contact@`) | LOW | Often unmonitored or alias forwarded; less personal context. |

**Repo priority by recency + naming:**

- Recently-pushed (last 30 days) > stale.
- Public repo with target name in description > target name only in code.
- Forked from internal-looking parent > standalone.
- Mentions `prod`, `internal`, `private`, `secret` in name → priority HIGH despite being public (may be misnamed or accidentally exposed).

**Application order:** when you have N assets and budget for M probes (M < N), apply asset-type priority first, then within-type priority. E.g.: 50 subdomains → probe API + admin + dev first (~15), then auth + prod-app (~20), defer marketing/content to a later pass.

---

## 9. Findings Rubric & Severity Mapping

Severity is operational, not subjective. Use these anchors:

### 9.1 CRITICAL

Pre-auth code execution, confirmed valid credentials, listable production data, fundamental trust violations.

Examples:
- `.git/config` exposed on production webapp (full source-code disclosure).
- `/.env` exposed (credentials in plaintext, often DB / cloud / API).
- Spring Boot `/actuator/env` or `/actuator/heapdump` reachable unauthenticated.
- Listable S3 / GCS / Azure bucket containing user data.
- Unauthenticated POST/PUT/DELETE to a write endpoint that mutates state.
- Open Firebase Realtime Database (`https://{project}.firebaseio.com/.json` returns data).
- `android:debuggable=true` in a production Android app.
- Live-validated credential (PMAK, AWS key, Anthropic/OpenAI key) with broad scope.
- ≥10 employees compromised in a breach corpus + their tenant identified (SSO_EXPOSURE).
- Open Elasticsearch cluster (`/_cat/indices` returns data).
- Open Docker API (`/v1.40/containers/json` returns containers).
- Open Redis (no AUTH; can write `authorized_keys`).
- Open Kubernetes API server with anonymous-auth enabled.
- Open kubelet on 10250 (pod exec without auth).
- Open etcd on 2379 (cluster state and secrets).
- BlueKeep-vulnerable RDP, EternalBlue-vulnerable SMB.
- Citrix Netscaler / F5 BIG-IP with version-specific RCE CVE.

### 9.2 HIGH

Significant exposure but not yet RCE; clear path to escalation; high-value information disclosure.

Examples:
- Public secret in a GitHub repo (PAT, AWS key, Slack token, etc.).
- Sourcemap (`.js.map`) accessible — full original-source disclosure of frontend.
- Open GraphQL introspection on production (full schema leaked → mutations to enum).
- Subdomain takeover possible (CNAME points to unclaimed Heroku/Shopify/etc.).
- Reflected CORS with credentials (`Access-Control-Allow-Origin: <reflected>` + `Access-Control-Allow-Credentials: true`).
- Verb tampering: hidden DELETE/PATCH on an endpoint that publicly only allows GET.
- Missing HSTS on a sensitive path (`/login`, `/sso`, `/admin`, `/auth`) — escalated from MED.
- Exposed Jenkins/Tomcat-Manager/phpMyAdmin admin UI (no auth or default creds).
- Telnet (port 23) reachable.
- WebView with JS bridge in a mobile app (XSS → RCE potential).
- Sensitive deep-link handler in a mobile app.
- DMARC policy `p=none` on production sending domain (spoof-feasible).
- Vendor product banner with known unpatched CVE (KEV-listed).

### 9.3 MEDIUM

Information disclosure, hardening gaps, brute-force exposure.

Examples:
- Missing security headers on standard pages: HSTS, CSP.
- Apache `/server-status` or `/server-info` reachable.
- `phpinfo()` or `/info.php` reachable on dev/staging only.
- Internal IP / hostname / K8s service DNS leaked in JS.
- Schema leakage in error pages (stack traces, ORM signatures).
- `android:allowBackup=true` in Android app.
- `android:usesCleartextTraffic=true` in Android app.
- Exported activity/service without `android:permission` protection.
- Missing rate-limit on an API endpoint.
- Wildcard CORS (`Access-Control-Allow-Origin: *`) on an API that returns user-tied data (no creds).
- Slack webhook URL leaked.
- Twilio Account SID leaked (without auth token).
- SPF record permissive (`+all` or many includes).

### 9.4 LOW

Cosmetic or marginal hardening gaps.

Examples:
- Missing `X-Frame-Options`.
- Missing `X-Content-Type-Options`.
- `.DS_Store` exposed.

## Extended Content

This page only contains the core methodology. Extended reference content (payloads, full tables, detailed examples) has been moved to [`references/`](references/osint-methodology-reference.md) for size management.

