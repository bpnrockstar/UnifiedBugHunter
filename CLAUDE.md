# Unified Bug Hunter — Plugin Guide

This repo is a Claude Code plugin for professional bug bounty hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi.

## What's Here

### Skills (89 total — load with `/bug-bounty`, `/web2-recon`, `/token-scan`, etc.; includes 48 `hunt-*` per-class skills)

| Skill | Domain |
|---|---|
| `skills/bug-bounty/` | Master workflow — recon to report, all vuln classes, LLM testing, chains |
| `skills/auto-hunt/` | **Autonomous full-spectrum hunter** — given any target, runs all phases from recon to report with closed-loop verification (hunt→verify→repeat until 100% confidence). Covers 30+ classes. No prompts needed. |
| `skills/bb-methodology/` | **Hunting mindset + 5-phase non-linear workflow + tool routing + session discipline** |
| `skills/web2-recon/` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `skills/web2-vuln-classes/` | 24 bug classes with bypass tables (SSRF, open redirect, file upload, Agentic AI) |
| `skills/security-arsenal/` | Payloads, bypass tables, gf patterns, always-rejected list |
| `skills/web3-audit/` | 10 smart contract bug classes, Foundry PoC template, pre-dive kill signals |
| `skills/meme-coin-audit/` | Meme coin rug pull detection, token authority checks, bonding curve exploits, LP attacks |
| `skills/report-writing/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, human tone |
| `skills/triage-validation/` | 7-Question Gate, 4 gates, never-submit list, conditionally valid table |
| `skills/credential-attack/` | Password spray methodology — 4-stage pipeline, lockout tactics, legal guardrails |
| `skills/mobile-pentest/` | Android/iOS app pentest — runtime-first proxy workflow, APK/IPA decompile, deeplink injection, WebView bridge, SSL pinning bypass |
| `skills/cicd-security/` | CI/CD pipeline hunting — GitHub Actions injection, secret exfil, OIDC abuse, supply chain |
| `skills/graphql-audit/` | GraphQL hunting — introspection, batching DoS, IDOR via aliasing, injection, auth bypass |
| `skills/social-engineering/` | Phishing campaigns, pretext development, vishing scripts, SMTP infra setup |
| `skills/malware-analysis/` | Static/dynamic malware analysis, YARA rules, network sigs, MITRE ATT&CK mapping |
| `skills/reverse-engineering/` | Binary decompilation, algorithm extraction, firmware analysis, binary diffing |
| `skills/forensics/` | DFIR — disk/memory/network forensics, timeline analysis, IOC extraction |
| `skills/active-directory/` | AD security — Kerberos attacks, NTLM relay, ADCS ESC1-ESC13, ACL abuse, DCSync |
| `skills/container-security/` | Docker/K8s escape vectors, RBAC abuse, runtime CVE exploitation |
| `skills/code-review/` | White-box source code audit — SAST patterns for 10 languages, 10-phase methodology |
| `skills/code-patch/` | Security patch generation — minimal, tested fixes for all OWASP Top 10 classes |
| `skills/vuln-catcher/` | Continuous recon monitor — subdomains, JS changes, ports, tech changes |
| `skills/dast-scanner/` | Automated DAST scanning (OWASP ZAP + nuclei) with DB import |
| `skills/knowledge-base/` | Searchable vulnerability KB with disclosed reports, payloads, techniques |
| `skills/llm-redteam/` | **Advanced LLM red teaming** — 15+ techniques (token smuggling, adversarial poetry, ArtPrompt, CipherChat, emoji smuggling, Best-of-N, Crescendo/GOAT/JBFuzz), 180+ payloads, MCP security testing, automated CLI tool |

### Commands (42 slash commands)

> **Note:** All commands are prefixed to avoid conflicts with Claude Code's built-in commands.
> `/resume` is a reserved Claude Code command — use `/pickup` to continue a previous hunt.

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
| `/wordlist-gen` | `/wordlist-gen <target>` — company-specific password wordlist (cewler + hashcat); requires `--with-credential-attack` |
| `/osint-employees` | `/osint-employees <target>` — employee names + emails (theHarvester + username-anarchy, opt-in LinkedIn); requires `--with-credential-attack` |
| `/breach-check` | `/breach-check <wordlist>` — HIBP k-anonymity rank wordlist by real-world breach count |
| `/spray` | `/spray <url> --mode http-form\|oauth\|o365\|okta --users <f> --passes <f>` — password spray with hard guards (typed-host confirm, lockout warn, audit log) |
| `/graphql-audit` | `/graphql-audit <url>` — full GraphQL audit: introspection, batching DoS, IDOR, injection, alias bomb, graphw00f fingerprint |
| `/sast` | `/sast [path] [--engine semgrep\|auto] [--diff <base>]` — real Semgrep SAST → normalized findings (regex fallback); deterministic pass feeding `/code-audit` |
| `/sca` | `/sca [path] [--osv]` — lockfile SCA via osv-scanner/pip-audit → CVE advisories with upgrade paths |
| `/code-audit` | `/code-audit [path] [--mode quick|full]` — white-box source code audit for 10 languages; runs `sast_runner`/`sca_audit` first, then the model triages |
| `/patch` | `/patch [file:line] [--lang py|js|java|go|rb|php|rs]` — generate tested security patch for vulnerable code |
| `/vuln-catcher` | `/vuln-catcher <domain> [--check types] [--continuous]` — continuous recon monitor (subdomains, JS, ports, tech) |
| `/dast-scan` | `/dast-scan nuclei|zap <url>` — automated DAST scanning with result import |
| `/search-findings` | `/search-findings <query> [--findings|--kb|--recon]` — search all database tables |
| `/dashboard` | `/dashboard` — launch the web GUI |
| `/llm-redteam` | `/llm-redteam <endpoint> [--category] [--model]` — automated LLM red teaming (180+ payloads, 6 categories) |
| `/retest` | `/retest <finding-id\|poc>` — re-run a saved PoC against the live target → FIXED / STILL-VULN / REGRESSED |
| `/auto-skills` | `/auto-skills <topic>` — topic-triggered skill routing (`tools/skill_router.py`) |
| `/llm-config` | `/llm-config [--provider] [--model]` — multi-provider LLM completion router (`tools/llm_router.py`) |
| `/evolve-skills` | `/evolve-skills <report-source>` — ground/evolve skills from disclosed reports (`tools/disclosure_miner.py`) |
| `/kev-matrix` | `/kev-matrix` — map CISA-KEV catalog to skill coverage (`tools/kev_matrix.py`) |

### Agents (30 specialized agents)

#### Bug Bounty Pipeline (11)
- `recon-agent` — subdomain enum + live host discovery
- `report-writer` — generates H1/Bugcrowd/Immunefi reports
- `validator` — 4-gate checklist on a finding
- `web3-auditor` — smart contract bug class analysis
- `chain-builder` — builds A→B→C exploit chains
- `autopilot` — autonomous hunt loop (scope→recon→rank→hunt→validate→report)
- `recon-ranker` — attack surface ranking from recon output + memory
- `token-auditor` — fast meme coin/token rug pull and security analysis
- `credential-hunter` — wordlist-gen + osint-employees + breach-check; HARD STOPS at spray
- `regression-retest-agent` — drives `/retest` across a finding batch against live targets (FIXED/STILL-VULN/REGRESSED)
- `triage-dedup-agent` — clusters/dedups a large finding set and flags duplicates vs already-submitted

#### Offensive Security (19)
- `binary-exploit` — memory corruption, ROP, shellcode, format string exploitation
- `crypto-analyst` — cryptographic implementation audit (weak keys, nonce reuse, padding oracle)
- `forensics-analyst` — DFIR, timeline analysis, file carving, memory forensics (Volatility 3)
- `malware-analyst` — static/dynamic malware analysis, YARA rules, C2 extraction
- `reverse-engineer` — binary decompilation, algorithm extraction, firmware analysis
- `social-engineer` — phishing campaign design, pretexts, vishing scripts, SMTP evasion
- `container-escape` — Docker/K8s breakout, RBAC abuse, pod-to-cluster-admin escalation
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
- `tools/sast_runner.py` — Semgrep-backed SAST engine (normalize/dedup/triage findings; regex fallback); backs `/sast` and the engine pass of `/code-audit`
- `tools/sca_audit.py` — lockfile SCA via osv-scanner/pip-audit/govulncheck → CVE advisories with upgrade paths; backs `/sca`
- `tools/token_scanner.py` — automated token red flag scanner (EVM + Solana)
- `tools/wordlist_engine.sh` — company-specific password wordlist generator (cewler + hashcat rules); requires `--with-credential-attack`
- `tools/osint_employees.sh` — employee names + email patterns for spray prep (theHarvester + username-anarchy, opt-in CrossLinked); requires `--with-credential-attack`
- `tools/breach_checker.py` — HIBP k-anonymity wordlist enrichment; ranks passwords by breach count (no API key, free)
- `tools/spray_orchestrator.sh` — password spray with typed-hostname guard + lockout warning + audit log; modes: http-form / oauth / o365 / okta (TREVOR); requires `--with-credential-attack` for TREVOR modes
- `tools/graphql_audit.sh` — 7-phase GraphQL audit: introspection + schema dump, graphw00f fingerprint, clairvoyance field discovery, batching DoS, alias bomb, gqlmap injection, graphql-cop checklist
- `tools/llm_redteam.py` — **Advanced LLM red teaming**: 180+ payloads across 6 categories, OOB callback detection, confidence scoring, HTML reports, DB import
- `tools/llm_payloads/` — Organized payload library: injection/, jailbreak/, exfil/, encoding/, agentic/, multi-turn/
- `tools/retest.py` — PoC-replay regression engine (re-runs a saved PoC → FIXED / STILL-VULN / REGRESSED)
- `tools/dedup_findings.py` — finding dedup/cluster (groups a large finding set, flags duplicates)
- `tools/llm_router.py` — multi-provider LLM completion router
- `tools/redact.py` — PII/secret evidence-hygiene redactor
- `tools/skill_router.py` — topic→skill routing engine
- `tools/disclosure_miner.py` — skill grounding/evolution from disclosed reports
- `tools/kev_matrix.py` — CISA-KEV catalog → skill-coverage matrix
- `tools/dual_session.py` — dual-account IDOR/privesc test harness

### External tool references

- `wordlists/REFERENCES.md` — pointers to SecLists / OneListForAll / fuzz4bounty / PayloadsAllTheThings
- `skills/security-arsenal/REFERENCES.md` — methodology, writeup archives, dorks, key-verification, AI-security skill repos
- `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md` — per-vuln quick-check tables distilled from HowToHunt + HolyTips + AllAboutBugBounty + KingOfBugBountyTips

### MCP Integrations (in `mcp/`)

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
claude
# /recon target.com
# /hunt target.com
# /validate   (after finding something)
# /report     (after validation passes)
```

## Install Skills

```bash
chmod +x install.sh && ./install.sh
```

## Critical Rules (Always Active)

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast — N/A hurts your validity ratio
5. 5-minute rule — nothing after 5 min = move on
