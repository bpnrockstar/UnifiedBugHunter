---
description: Run the full recon pipeline by invoking tools/recon_engine.sh — subdomain enum (subfinder + amass + crt.sh + wayback), httpx live host probing with tech detection, nmap port scan, gau/wayback/katana URL collection, JS endpoint+secret grep, ffuf directory fuzzing, config exposure check, parameter frequency analysis, CI/CD workflow scan, nuclei sweep, and subdomain-takeover leads. Outputs to recon/<target>/. Handles FQDN, IP, CIDR, and file-of-hosts targets automatically. Usage: /recon target.com
argument-hint: <target.com | ip | cidr | path/to/scope.txt> [--quick]
allowed-tools: Bash
---

# /recon

Run the full recon pipeline on a target. **Always invoke the production script directly** — do not re-implement the steps inline. The methodology below is reference material; the script is the entry point.

## Run This (the only required step)

```bash
# Whatever the user passed (domain, CIDR, single IP, or path to a host-list file):
bash tools/recon_engine.sh $ARGUMENTS
```

The same entry point handles every target type — pass the user's argument(s)
straight through:

```bash
# Domain (full subdomain enum + crawl + fuzz):
bash tools/recon_engine.sh example.com

# CIDR — skips subdomain enum, runs nmap host sweep:
bash tools/recon_engine.sh 10.0.0.0/24

# Single IP — scope-locked, no subdomain enum:
bash tools/recon_engine.sh 192.0.2.10

# Domain list (programs without wildcard scope) — pre-resolved hosts in a file:
bash tools/recon_engine.sh path/to/scope.txt

# Quick mode (skip amass + reduce ffuf coverage):
bash tools/recon_engine.sh example.com --quick
```

The script auto-detects target type:
- Path to a readable file → loads it as a host list (one per line, `#` comments OK) and **skips subdomain enumeration entirely**.
- `x.x.x.x/y` → CIDR sweep (max /24, scope-locked).
- `x.x.x.x` → single IP, scope-locked.
- Anything else → treated as a domain; full enum runs.

Output lands in `recon/<target>/` (or `recon/<file-basename>/` for list mode):

```
recon/<target>/
├── subdomains/all.txt              # all discovered subdomains (deduped)
├── live/urls.txt                   # live hosts (httpx); status_200/3xx/401/403.txt splits
├── ports/open_ports.txt            # nmap open ports (if nmap ran)
├── urls/all.txt                    # all crawled/historical URLs (deduped)
├── urls/api_endpoints.txt          # /api/, /v\d+/, /graphql, /rest/ endpoints
├── urls/js_files.txt               # discovered .js bundles
├── urls/with_params.txt            # URLs carrying query parameters
├── js/endpoints.txt                # endpoints extracted from JS (if any)
├── params/unique_params.txt        # parameter names ranked by frequency
├── exposure/config_files.txt       # exposed .git/.env/swagger/etc.
├── nuclei/findings.jsonl           # nuclei findings (severity-split *.jsonl alongside)
├── takeover_candidates.txt         # dangling-CNAME takeover leads (if any)
└── cicd/<org>/                     # CI/CD workflow scan (if an org was detected)
```

## Troubleshooting

### "/recon path/to/file.txt still runs subdomain enumeration"

You're on an older revision of this command file where the model re-implemented the pipeline inline and never invoked the production script. Pull latest, or run the script directly:

```bash
bash tools/recon_engine.sh path/to/file.txt
```

The script logs `[*] Domain-list target …` and skips subdomain enumeration when handed a readable file.

### "/recon loops / doesn't actually run anything"

Same root cause as the hunt-loop bug. Run the bash directly:

```bash
bash tools/recon_engine.sh $ARGUMENTS
```

Or in your prompt: "Run `bash tools/recon_engine.sh <target>` and report the output. Do not re-implement the steps."

### "Missing tools"

The installer lives at the repo root, not under `tools/`:

```bash
bash install_tools.sh
```

Recon needs: `subfinder`, `amass`, `dnsx`, `httpx` (ProjectDiscovery — not the Python CLI), `katana`, `gau`, `nuclei`, `ffuf`, `nmap`. The installer handles all of them.

## After Recon

1. Review `recon/<target>/live/urls.txt` — open interesting ones in a browser.
2. Check `recon/<target>/nuclei/findings.jsonl` — any high/critical? (severity-split `*.jsonl` files sit alongside it.)
3. Review `recon/<target>/urls/api_endpoints.txt` — start IDOR testing.
4. `grep -E "admin|jenkins|grafana|gitlab" recon/<target>/live/urls.txt` — admin panels.
5. Run `/hunt <target>` to start active vulnerability testing on the recon output.

## 5-Minute Kill Signal

If after running this pipeline you see:
- All hosts return 403 even after `tools/bypass_403.sh` + wafw00f bypass, or return only static marketing pages
- No API endpoints visible
- No interesting parameters in URLs
- nuclei returns 0 medium/high findings

**→ Move on to a different target.** Don't sink hours into a dead surface.

# Reference: What the script does (informational)

The pipeline in `tools/recon_engine.sh` runs these phases (numbers may shift; check the script source):

1. **Subdomain enumeration** — subfinder + amass (passive) + crt.sh + wayback, deduped to `subdomains/all.txt`. Skipped for IP/CIDR/file-list targets.
2. **Live host discovery** — httpx with status/title/tech-detect; status splits written to `live/status_{200,3xx,401,403}.txt`.
3. **Port scan** — nmap top-1000 on live hosts (CIDR mode runs a wider sweep).
4. **URL collection** — gau + wayback historical, then katana crawl of the top live hosts; merged to `urls/all.txt`. Derived files: `urls/api_endpoints.txt`, `urls/js_files.txt`, `urls/with_params.txt`, `urls/sensitive_paths.txt`.
5. **JS analysis** — curl each top JS bundle and grep inline for endpoints (`js/endpoints.txt`) and potential secrets (`js/potential_secrets.txt`). No external LinkFinder/SecretFinder binary.
6. **ffuf directory fuzzing** — uses `wordlists/common.txt` (run `python3 tools/hunt.py --setup-wordlists` once if missing); per-host JSON in `dirs/`.
7. **Config exposure** — probes `.git/`, `.env`, `wp-config.php`, `.DS_Store`, swagger.json, etc. → `exposure/config_files.txt`.
8. **Parameter analysis** — frequency-ranks parameter names seen in the collected URLs (`params/unique_params.txt`, `params/interesting_params.txt`). No active Arjun/x8 probing.
9. **CI/CD scan** — `cicd_scanner.sh` (sisakulint) against any GitHub org detected in recon output → `cicd/<org>/`.
10. **Nuclei sweep** — runs when `nuclei` is installed; severity `medium,high,critical` (high/critical in `--quick`) over the top live hosts → `nuclei/findings.jsonl` plus per-severity `*.jsonl` splits.
11. **Subdomain takeover leads** — dig-based dangling-CNAME check → `takeover_candidates.txt`; confirm with `tools/takeover_scanner.sh --recon <recon-dir>`.

For the IDOR / SSRF / GraphQL / SSTI / etc. active-testing playbooks, see `/hunt` and its methodology section.
