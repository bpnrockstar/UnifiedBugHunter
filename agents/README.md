# Agents

24 specialized AI agents, built for covering the full security assessment lifecycle.

## Bug Bounty Agents (9 existing)

| Agent | Job |
|:---|:---|
| `recon-agent` | Subdomain enum · live host discovery · URL crawl · fingerprint |
| `recon-ranker` | Ranks attack surface by highest-value targets first |
| `report-writer` | Writes impact-first reports that get paid, not N/A'd |
| `validator` | Runs the 7-Question Gate and 4 pre-submission gates |
| `web3-auditor` | Smart contract audit across 10 bug classes |
| `chain-builder` | Bug A → finds bugs B and C that chain with it |
| `autopilot` | Full autonomous hunt loop with safety checkpoints |
| `token-auditor` | Meme coin / token rug pull and security scan |
| `credential-hunter` | Wordlist gen → OSINT → breach-check → hard-stop before spray |

## Offensive Security Agents (15 new)

| Agent | Job |
|:---|:---|
| `binary-exploit` | Memory corruption, ROP, shellcode, format string exploitation |
| `crypto-analyst` | Crypto implementation flaws — weak keys, nonce reuse, padding oracle |
| `forensics-analyst` | DFIR — disk/memory/network artifact analysis and timeline reconstruction |
| `malware-analyst` | Static + dynamic malware analysis, YARA rules, C2 extraction |
| `reverse-engineer` | Binary RE — decompilation, algorithm extraction, firmware analysis |
| `social-engineer` | Phishing campaign design, pretext development, vishing scripts |
| `container-escape` | Docker/K8s breakout, RBAC abuse, pod-to-cluster-admin escalation |
| `api-security` | Deep API testing (REST/GraphQL/gRPC/WebSocket) — mass assignment, rate limit, JWT |
| `privesc-advisor` | Linux/Windows privilege escalation — SUID, cron, token abuse |
| `payload-crafter` | Custom WAF-bypass payload generation (XSS/SQLi/SSTI/SSRF/command injection) |
| `attack-planner` | Multi-stage attack graphs — initial access to crown jewel |
| `ad-attacker` | Active Directory — Kerberos, NTLM relay, ADCS, ACL abuse |
| `swarm-orchestrator` | Multi-agent coordination — parallel task assignment and output merging |
| `poc-validator` | Independent PoC verification — reproduce and minimize exploit steps |
| `exploit-guide` | Step-by-step exploitation procedures for 20 bug classes |

Agents are activated automatically by the `/autopilot` command or called directly during a hunt.
