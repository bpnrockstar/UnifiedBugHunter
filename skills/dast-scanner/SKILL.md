---
name: dast-scanner
description: "Automated DAST scanning with OWASP ZAP and nuclei integration. Scans targets and imports findings into the bug hunter database for analysis and reporting."
---

# DAST Scanner Integration

Automated vulnerability scanning wrapper that runs OWASP ZAP and nuclei,
then imports all findings into the searchable bug hunter database.

## Tools

### OWASP ZAP
- Full active scan with spider + AJAX spider
- Imports all alerts (risk levels mapped to severity)
- Requires ZAP running in daemon mode

### Nuclei
- Fast template-based scanning
- Categories: cves, exposures, misconfiguration, vulnerabilities, technologies
- Deep scan with ALL templates

## Usage

```bash
# Nuclei scan (fast)
./tools/dast_scanner.sh nuclei https://target.com

# Nuclei deep scan
./tools/dast_scanner.sh nuclei-deep https://target.com

# ZAP scan (start ZAP daemon first)
zap.sh -daemon -port 8080
./tools/dast_scanner.sh zap https://target.com

# Import existing results
./tools/dast_scanner.sh import nuclei_results.json
```

## DAST Methodology

DAST is a black-box, runtime technique: you exercise the *running* application and observe responses, so coverage is only as good as the URLs and parameters you discover and the authenticated state you can hold. Run the phases in order.

### Phase 1: Crawl / Spider (build the attack surface)

A scanner can only test endpoints it has seen. Combine a passive crawl with active discovery so single-page apps and hidden routes are reached:

```bash
# Traditional spider + AJAX (JS-rendered) spider in one pass
zap.sh -daemon -port 8080 -config api.disablekey=true
zap-cli spider https://target.com
zap-cli ajax-spider https://target.com    # for SPAs / dynamic DOM

# Seed nuclei/ZAP with a real URL inventory from recon instead of crawling cold
cat recon/urls.txt | httpx -silent -mc 200,301,302,401,403 > live_urls.txt
```

Feed `live_urls.txt` (from the `web2-recon` pipeline: gau/katana/waybackurls) into the scanner so you do not rely on the spider alone — historical and JS-extracted URLs catch endpoints a crawler never links to.

### Phase 2: Authentication handling (scan behind login)

Most impactful findings live in authenticated areas. Configure session handling before active scanning or you will only test the public surface:

```bash
# ZAP context + form/JSON login (replay a known-good session)
zap-cli context import auth-context.yaml      # defines login URL, creds, logged-in/out regex
zap-cli open-session
# Or pin a captured session header for token-based auth:
zap-cli --api-key '' session ...               # set Authorization header in the context

# nuclei with an authenticated header
nuclei -l live_urls.txt -H "Authorization: Bearer $TOKEN" -H "Cookie: session=$SID"
```

Always define a "logged-out" indicator (e.g. a redirect to `/login` or a 401) so the scanner detects session expiry and re-authenticates instead of silently testing logged-out pages.

### Phase 3: Active scan profiles (tune intensity to scope)

Pick a profile by how aggressive the program allows you to be:

- **Passive only** — observe traffic, no injected payloads. Safe for production, finds missing headers, info leaks, mixed content.
- **Baseline / fast** — light active checks, low request volume. `nuclei` default templates; ZAP baseline scan.
- **Full active** — injection-heavy (SQLi, XSS, command injection, path traversal). Rate-limit it and confirm the program permits automated scanning first.

```bash
# nuclei tiers
nuclei -l live_urls.txt -t exposures/ -t misconfiguration/        # baseline
nuclei -l live_urls.txt -severity critical,high -rl 50            # full, rate-limited to 50 req/s

# ZAP full active scan with attack strength tuned
zap-cli active-scan --recursive --scanners all https://target.com
```

Respect rate limits (`-rl` in nuclei, `Tools > Options > Connection` in ZAP) and a single concurrency cap — an unthrottled active scan is indistinguishable from a DoS and can get you removed from a program.

### Phase 4: Triage

DAST output is noisy. Every finding is a *lead*, not a confirmed bug — manually reproduce before it leaves this skill. Drop info-level header findings unless they chain. Confirm injection findings with a manual PoC; relabel anything that cannot be reproduced as out of scope.

## Finding Import

Each confirmed finding from ZAP or nuclei is imported with:
- Severity mapping (critical/high/medium/low/info)
- Endpoint URL
- Description from scanner output
- Source tagged as 'dast' for traceability
- Associated with the correct target domain

## Related Skills

- `web2-recon` — supplies the subdomain/URL inventory and live-host list that seed the crawl phase.
- `web2-vuln-classes` / `security-arsenal` — to manually confirm and weaponise a raw DAST hit into a reproducible PoC.
- `graphql-audit` — DAST crawlers miss GraphQL; use that skill for introspection-driven testing of GraphQL endpoints.
- `triage-validation` — run the 7-Question Gate on any DAST finding before it becomes a report.
