---
description: Build or refresh the CISA-KEV → UBH-skill coverage matrix — offline from a bundled snapshot by default, or --fetch for the live CISA feed.
argument-hint: "[--kev <file>] [--fetch] [--out docs/KEV-MATRIX.md] [--all] [--skills-dir <dir>] [--json]"
allowed-tools: Bash
---

## Run This

Wrap `tools/kev_matrix.py`, which maps every CISA Known Exploited Vulnerabilities (KEV) entry to the UnifiedBugHunter skill that covers it, flags `(missing)` skills, and renders the result as a Markdown matrix. It runs **offline** out of the box from a bundled 12-entry fixture and only touches the network when `--fetch` is passed.

Pass the user's arguments straight through. With no arguments, regenerate the matrix from the bundled sample to `docs/KEV-MATRIX.md`.

```bash
python3 /Users/bipin/Music/UnifiedBugHunter/tools/kev_matrix.py $ARGUMENTS
```

What the flags do:

- `--kev <file>` — local KEV JSON snapshot to build from. Default = bundled sample (`tools/fixtures/kev_sample.json`). Accepts both the official `{"vulnerabilities":[...]}` envelope and a bare array; entries with no `cveID` are dropped. With `--fetch`, this is instead the **write destination** for the downloaded feed.
- `--fetch` — download the live CISA feed (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) into `--kev`, then build. **This is the only flag that enables network access.** Requires `requests`; fetch failures exit `1`.
- `--out <path>` — output path for the rendered Markdown (default `docs/KEV-MATRIX.md`; parent dirs are auto-created).
- `--all` — include every KEV entry, not just the edge/identity subset (Fortinet, Citrix, Ivanti, Pulse Secure, Palo Alto, Cisco, VMware, Microsoft, Okta, Atlassian, F5, SonicWall, Zoho, Zyxel, Juniper, Barracuda, Progress, Check Point, Array Networks, GitLab, Jenkins).
- `--skills-dir <dir>` — override `<repo>/skills` for the missing-skill check.
- `--json` — print the matrix as JSON to stdout instead of writing Markdown.

Routing notes: VPN/appliance → `enterprise-vpn-attack`; Microsoft identity/Exchange/Outlook → `m365-entra-attack`; SharePoint → `hunt-sharepoint`; Okta → `okta-attack`; vCenter/ESXi/vSphere → `vmware-vcenter-attack`; GitLab/Jenkins/CI → `hunt-cicd`; framework CVEs → `hunt-<framework>`; plus generic primitives (`hunt-rce`, `hunt-sqli`, `hunt-saml`, `hunt-auth-bypass`, …). Anything unmatched falls back to `scan-cves`. Rows are sorted newest-`dateAdded` first.

Common invocations:

```bash
# Offline default — regenerate docs/KEV-MATRIX.md from the bundled sample
python3 /Users/bipin/Music/UnifiedBugHunter/tools/kev_matrix.py

# Refresh live from CISA, caching the feed for later offline runs
python3 /Users/bipin/Music/UnifiedBugHunter/tools/kev_matrix.py --fetch --kev /Users/bipin/Music/UnifiedBugHunter/data/kev.json

# Full matrix (all vendors) as JSON to stdout
python3 /Users/bipin/Music/UnifiedBugHunter/tools/kev_matrix.py --all --json
```

Exit codes: `0` success; `1` load/fetch error (message on stderr). After a successful Markdown run, report the `--out` path and call out any `(missing)` skills so the user knows which coverage gaps to close.
