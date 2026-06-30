---
name: vuln-catcher
description: "Continuous recon monitor — watches targets for new subdomains, JS changes, open ports, and technology changes. Stores everything in a searchable SQLite database and alerts on changes."
---

# Vulnerability Catcher — Continuous Recon Monitor

Monitors target domains for changes that indicate new attack surface.
Runs in the background, stores results in the bug hunter database, and
surfaces changes through the dashboard.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  crt.sh API     │     │  subfinder       │     │  katana         │
│  (subdomains)   │────▶│  (subdomains)    │────▶│  (JS discovery) │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌──────────────────────────────────────────────────────────────┐
│                  SQLite Database (bughunter.db)               │
│  targets | findings | recon_data | reports | knowledge_base  │
│  monitoring_log | scan_history                               │
└──────────────────────────────────────────────────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Web Dashboard  │     │  AI Training     │     │  Search/Query   │
│  (Flask GUI)    │     │  Data Export     │     │  CLI tools      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## Setup

```bash
# Install dependencies
pip install flask

# Initialize the database
python3 -c "from dashboard.database import init_db; init_db()"

# Make tools executable
chmod +x tools/vuln_catcher.py tools/dast_scanner.sh tools/ai_training_data.py
```

## Usage

### Vulnerability Catcher

```bash
# Monitor a single target once
python3 tools/vuln_catcher.py --target example.com --once --check subdomains js

# Monitor all targets continuously (every hour)
python3 tools/vuln_catcher.py --all-targets --interval 3600

# Check only subdomains and ports
python3 tools/vuln_catcher.py --target example.com --check subdomains ports --once

# Run all checks on all targets
python3 tools/vuln_catcher.py --all-targets --once
```

### Web Dashboard

```bash
# Start the dashboard
python3 dashboard/app.py
# Open http://127.0.0.1:5000
```

### DAST Scanner

```bash
# Run nuclei fast scan
./tools/dast_scanner.sh nuclei https://example.com

# Run nuclei with all templates
./tools/dast_scanner.sh nuclei-deep https://example.com

# Run OWASP ZAP (requires ZAP running on port 8080)
./tools/dast_scanner.sh zap https://example.com

# Import external results
./tools/dast_scanner.sh import results.json
```

### AI Training Data

```bash
# Export in OpenAI fine-tuning format
python3 tools/ai_training_data.py --format openai --output training.jsonl

# Show stats
python3 tools/ai_training_data.py --stats

# Export only high+critical findings
python3 tools/ai_training_data.py --format chat --min-severity high
```

## Database Schema

**targets** — Target domains with program/platform info
**findings** — Vulnerabilities with severity, class, PoC, CVSS
**recon_data** — Subdomains, URLs, endpoints, JS files, ports, tech
**reports** — Generated reports
**knowledge_base** — Disclosed reports, payloads, techniques
**monitoring_log** — Change detection history
**scan_history** — DAST scan records

## Checks

| Check | Tool | What It Detects |
|-------|------|-----------------|
| subdomains | crt.sh + subfinder | New subdomains from CT logs and DNS |
| js | katana | JavaScript file content changes |
| ports | naabu | New open ports |
| tech | whatweb | Technology stack changes |

## API Endpoints (Dashboard)

| Endpoint | Description |
|----------|-------------|
| GET / | Dashboard with stats |
| GET /targets | Target list |
| GET /targets/<id> | Target detail |
| GET /findings | Searchable findings |
| GET /findings/<id> | Finding detail |
| GET /recon | Recon data browser |
| GET /reports | Report list |
| GET /knowledge-base | Searchable knowledge base |
| GET /monitoring | Monitoring log |
| GET /api/stats | JSON stats |
| GET /api/findings | JSON findings (filterable) |
| GET /api/knowledge-base | JSON knowledge base |
| GET /api/recon | JSON recon data |

## Related Skills & Chains

- **`web2-recon`** — Seeds the monitor. Run a full subdomain/URL/JS sweep first, store it as the baseline in `recon_data`, then hand off to `vuln-catcher` to watch that surface for deltas over time.
- **`hunt-subdomain`** — When `vuln-catcher` flags a new subdomain (crt.sh/subfinder delta), pivot into focused subdomain takeover and enumeration checks on the newly-surfaced host.
- **`hunt-source-leak`** — When the `js` check detects changed JavaScript bundles, chain into source-leak hunting (new endpoints, hardcoded secrets, API keys in the diff).
- **`dast-scanner`** — On a confirmed new host or port, trigger the bundled `dast_scanner.sh` (nuclei/ZAP) and import results into the same `bughunter.db`.
- **`knowledge-base`** — Findings and recon deltas land in the shared SQLite DB; the searchable knowledge base reuses that store for disclosed-report and payload lookups.
- **`auto-hunt`** — The autonomous hunter can consume `vuln-catcher` monitoring deltas as fresh attack-surface input to kick off a recon-to-report loop without manual prompting.
