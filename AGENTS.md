# Bug Bounty Agent Toolkit — Plugin Guide

This repo is an agent-portable bug bounty plugin for professional hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi. It supports Claude Code, OpenCode, Pi Agent, Codex-style Agent Skills, and shared `.agents/skills` harnesses.

## What's Here

### Skills (89 total — load with `/bug-bounty`, `/web2-recon`, `/token-scan`, etc.; includes 48 `hunt-*` per-class skills)

| Skill | Domain |
|---|---|
| `skills/bug-bounty/` | Master workflow — recon to report, all vuln classes, LLM testing, chains |
| `skills/bb-methodology/` | **Hunting mindset + 5-phase non-linear workflow + tool routing + session discipline** |
| `skills/web2-recon/` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `skills/web2-vuln-classes/` | 24 bug classes with bypass tables (SSRF, open redirect, file upload, Agentic AI) |
| `skills/security-arsenal/` | Payloads, bypass tables, gf patterns, always-rejected list |
| `skills/web3-audit/` | 10 smart contract bug classes, Foundry PoC template, pre-dive kill signals |
| `skills/meme-coin-audit/` | Meme coin rug pull detection, token authority checks, bonding curve exploits, LP attacks |
| `skills/report-writing/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, human tone |
| `skills/triage-validation/` | 7-Question Gate, 4 gates, never-submit list, conditionally valid table |

### Commands (35 slash commands)

> **Note:** All commands are prefixed to avoid conflicts with Codex's built-in commands.
> `/resume` is a reserved Codex command — use `/pickup` to continue a previous hunt.

| Command | Usage |
|---|---|
| `/recon` | `/recon target.com` — full recon pipeline |
| `/hunt` | `/hunt target.com` — start hunting |
| `/validate` | `/validate` — run 7-Question Gate on current finding |
| `/report` | `/report` — write submission-ready report |
| `/chain` | `/chain` — build A→B→C exploit chain |
| `/scope` | `/scope <asset>` — verify asset is in scope |
| `/scope-aggregate` | `/scope-aggregate <program>` — pull every in-scope asset across H1/Bugcrowd/Intigriti/YWH/Immunefi |
| `/triage` | `/triage` — quick 7-Question Gate |
| `/web3-audit` | `/web3-audit <contract.sol>` — smart contract audit |
| `/autopilot` | `/autopilot target.com --normal` — autonomous hunt loop |
| `/surface` | `/surface target.com` — ranked attack surface |
| `/pickup` | `/pickup target.com` — pick up previous hunt (was `/resume`) |
| `/remember` | `/remember` — log finding to hunt memory |
| `/intel` | `/intel target.com` — fetch CVE + disclosure intel |
| `/token-scan` | `/token-scan <contract>` — meme coin/token rug pull scanner |
| `/memory-gc` | `/memory-gc [--rotate|--purge-backups]` — inspect/rotate hunt-memory JSONL files (10MB cap, 3 backups) |
| `/secrets-hunt` | `/secrets-hunt --js-bundle <recon-dir>` — leaked-credential scan (trufflehog/noseyparker/gitleaks) |
| `/takeover` | `/takeover --recon <recon-dir>` — subdomain takeover candidates (dnsReaper/subjack) |
| `/cloud-recon` | `/cloud-recon --keyword <name>` — public S3/Azure/GCP + CloudFlare-bypass origin IPs |
| `/param-discover` | `/param-discover <url>` — find hidden HTTP parameters (Arjun/x8) |
| `/bypass-403` | `/bypass-403 <url>` — try header/method/encoding tricks against a 403/401 |
| `/arsenal` | `/arsenal [tool]` — list installed external tools or get an install hint |
| `/scan-cves` | `/scan-cves <host>` — focused nuclei CVE sweep (high/critical) + optional log4j-scan |

### Agents (28 specialized agents)

#### Bug Bounty Pipeline (9)
- `recon-agent` — subdomain enum + live host discovery
- `report-writer` — generates H1/Bugcrowd/Immunefi reports
- `validator` — 4-gate checklist on a finding
- `web3-auditor` — smart contract bug class analysis
- `chain-builder` — builds A→B→C exploit chains
- `autopilot` — autonomous hunt loop (scope→recon→rank→hunt→validate→report)
- `recon-ranker` — attack surface ranking from recon output + memory
- `token-auditor` — fast meme coin/token rug pull and security analysis
- `credential-hunter` — wordlist-gen + OSINT + breach-check + spray hard-stop

#### Offensive Security (19)
- `binary-exploit` — memory corruption, ROP, shellcode, format string exploitation
- `crypto-analyst` — cryptographic implementation audit (weak keys, nonce reuse, padding oracle)
- `forensics-analyst` — DFIR, timeline analysis, file carving, memory forensics
- `malware-analyst` — static/dynamic malware analysis, YARA rules, C2 extraction
- `reverse-engineer` — binary decompilation, algorithm extraction, firmware analysis
- `social-engineer` — phishing campaign design, pretexts, vishing scripts, evasion
- `container-escape` — Docker/K8s breakout, RBAC abuse, pod-to-cluster-admin
- `api-security` — deep REST/GraphQL/gRPC/WebSocket API testing (OWASP API Top 10)
- `privesc-advisor` — Linux/Windows privilege escalation (SUID, cron, token abuse)
- `payload-crafter` — custom WAF-bypass payloads (XSS/SQLi/SSTI/SSRF/command injection)
- `attack-planner` — multi-stage attack graphs from initial access to crown jewel
- `ad-attacker` — Active Directory (Kerberos, NTLM relay, ADCS ESC1-ESC13, DCSync)
- `swarm-orchestrator` — multi-agent parallel coordination and output merging
- `poc-validator` — independent PoC verification and minimization
- `exploit-guide` — step-by-step exploitation procedures for 20+ bug classes
- `code-reviewer` — white-box source code audit, SAST-driven, 10-phase methodology
- `code-patcher` — automated security patch generation with before/after diff and verification
- `vuln-catcher` — continuous recon monitor for subdomains, JS changes, ports, tech
- `llm-redteamer` — advanced LLM red teaming (180+ payloads, 6 categories, automated scanning)

### Rules (always active)

- `rules/hunting.md` — 17 critical hunting rules
- `rules/reporting.md` — report quality rules

### Tools (Python/shell — in `tools/`)

- `tools/hunt.py` — master orchestrator
- `tools/recon_engine.sh` — subdomain + URL discovery (now with optional `nuclei` phase)
- `tools/vuln_scanner.sh` — XSS/SQLi/SSTI/MFA/SAML probe pipeline
- `tools/validate.py` — 4-gate finding validator
- `tools/learn.py` — CVE + disclosure intel
- `tools/intel_engine.py` — on-demand intel with memory context
- `tools/scope_checker.py` — deterministic scope safety checker
- `tools/scope_aggregator.sh` — multi-platform scope pull (bbscope + bounty-targets-data)
- `tools/secrets_hunter.sh` — trufflehog/noseyparker/gitleaks wrapper for FS/git/JS/GH-org
- `tools/takeover_scanner.sh` — dnsReaper/subjack subdomain-takeover scanner
- `tools/cloud_recon.sh` — S3Scanner + cloud_enum + CloudFail wrapper
- `tools/param_discovery.sh` — Arjun/x8 hidden-parameter discovery
- `tools/bypass_403.sh` — byp4xx + built-in 403/401 bypass matrix
- `tools/cve_scan.sh` — focused nuclei CVE-tag sweep + optional log4j-scan
- `tools/external_arsenal.sh` — installed-tool registry (~50 tools); other scripts source this for `_have <tool>`
- `tools/cicd_scanner.sh` — GitHub Actions workflow scanner (sisakulint wrapper, remote scan)
- `tools/token_scanner.py` — automated token red flag scanner (EVM + Solana)

### External tool references

- `wordlists/REFERENCES.md` — pointers to SecLists / OneListForAll / fuzz4bounty / PayloadsAllTheThings
- `skills/security-arsenal/REFERENCES.md` — methodology, writeup archives, dorks, key-verification, AI-security skill repos
- `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md` — per-vuln quick-check tables distilled from HowToHunt + HolyTips + AllAboutBugBounty + KingOfBugBountyTips

### MCP Integrations (6 servers — in `mcp/`)

- `mcp/burp-mcp-client/` — Burp Suite proxy integration
- `mcp/caido-mcp-client/` — Caido proxy integration
- `mcp/hackerone-mcp/` — HackerOne public API (Hacktivity, program stats, policy)
- `mcp/bugcrowd-mcp/` — Bugcrowd public API (Crowdstream, program info, public bounties)
- `mcp/intigriti-mcp/` — Intigriti public API (research blog, XSS challenges)
- `mcp/immunefi-mcp/` — Immunefi public API (disclosed reports, program TVL/bounties, contracts)

### Hunt Memory (in `memory/`)

- `memory/pattern_db.py` — cross-target pattern learning
- `memory/audit_log.py` — request audit log, rate limiter, circuit breaker
- `memory/rotation.py` — size-based JSONL rotation (10MB cap, keep 3 backups), auto-fired on append
- `memory/schemas.py` — schema validation for all data

## Start Here

```bash
Codex
# /recon target.com
# /hunt target.com
# /validate   (after finding something)
# /report     (after validation passes)
```

## Install Skills

```bash
chmod +x install.sh && ./install.sh
```

Install for another harness:

```bash
./install.sh --agent opencode          # ~/.config/opencode/skills + commands + agents
./install.sh --agent pi                # ~/.pi/agent/skills + prompt templates
./install.sh --agent codex             # ~/.codex/skills + commands
./install.sh --agent agents            # ~/.agents/skills shared by OpenCode/Pi
./install.sh --agent all               # every supported global target
./install.sh --agent opencode --project # local .opencode/ install
./install.sh --agent pi --project       # local .pi/ install
```

## Critical Rules (Always Active)

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast — N/A hurts your validity ratio
5. 5-minute rule — nothing after 5 min = move on
