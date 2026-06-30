# Unified Bug Hunter

**89 AI-powered skills · 35 commands · 28 agents · Web Dashboard · LLM Red Team**  
The ultimate merged bug bounty hunting toolkit — AI-powered security testing from recon to report.

> **Warning**: For authorized security testing only. Always respect program scope.

---

## What's Included

### 89 Specialized Skills

| Category | Skills |
|----------|--------|
| **Hunt** (48) | api-misconfig, aspnet, ato, auth-bypass, brute-force, business-logic, cache-poison, cicd, cloud-misconfig, cors, csrf, deserialization, dispatch, dom, file-upload, graphql, grpc, host-header, http-smuggling, idor, k8s, laravel, ldap, lfi, llm-ai, mfa-bypass, misc, nextjs, nodejs, nosqli, ntlm-info, oauth, open-redirect, race-condition, rce, saml, session, sharepoint, source-leak, springboot, sqli, ssrf, ssti, subdomain, tls-network, websocket, xss, xxe |
| **Platform** (41) | active-directory, apk-redteam-pipeline, auto-hunt, bb-local-toolkit, bb-methodology, bug-bounty, bugcrowd-reporting, cicd-security, cloud-iam-deep, code-patch, code-review, container-security, credential-attack, dast-scanner, enterprise-vpn-attack, evidence-hygiene, forensics, graphql-audit, knowledge-base, llm-redteam, m365-entra-attack, malware-analysis, meme-coin-audit, mid-engagement-ir-detection, mobile-pentest, offensive-osint, okta-attack, osint-methodology, redteam-mindset, redteam-report-template, report-writing, reverse-engineering, security-arsenal, social-engineering, supply-chain-attack-recon, triage-validation, vmware-vcenter-attack, vuln-catcher, web2-recon, web2-vuln-classes, web3-audit |

### 35 Commands

**Built-in commands:** arsenal, autopilot, breach-check, bypass-403, chain, cloud-recon, code-audit, dashboard, dast-scan, graphql-audit, hunt, intel, llm-redteam, memory-gc, osint-employees, param-discover, patch, pickup, recon, remember, report, scan-cves, scope, scope-aggregate, search-findings, secrets-hunt, spray, surface, takeover, token-scan, triage, validate, vuln-catcher, web3-audit, wordlist-gen

### 53 Automation Tools
Breach checker, 403 bypass, cloud recon, CVE scanner, credential store, graphql auditor, IDOR scanner, oauth tester, race condition tester, recon engine, scope checker, secrets hunter, token scanner, WAF encoder, zero-day fuzzer, vulnerability catcher (continuous recon monitor), DAST scanner (ZAP/nuclei wrapper), **LLM red teamer (200+ payloads, 6 categories, automated)**, AI training data exporter, search findings CLI, and more.

### Engine & Evaluation
- **Python agent engine** (`agent.py`, `brain.py`, `engine.py`, `serve.py`)
- **Eval framework** with PortSwigger lab integration
- **Web3 audit system** with 16-module training path
- **Skill generator** (`generate-skill.py`) — pulls live H1 reports to update agent logic

### Integrations
- **MCP**: Burp Suite, Caido, HackerOne, Bugcrowd, Intigriti, Immunefi
- **AI Providers**: Ollama, Groq, DeepSeek, Anthropic, OpenAI, Cerebras, Gemini, Grok
- **Orchestration**: Claude Code, OpenCode, Codex CLI, Hermes Agent

---

## Quick Start

```bash
git clone https://github.com/bpnrockstar/UnifiedBugHunter.git
cd UnifiedBugHunter
./install.sh
```

For external scanning tools:
```bash
./install_tools.sh
```

### Configuration
```bash
cp config.example.json config.json
# Edit config.json with your API keys and targets
```

---

## Usage Workflow

```bash
# Run full recon on a target
/recon target.com

# Launch autonomous hunting
/hunt target.com

# Validate a finding
/validate

# Generate a report
/report

# Full autopilot mode — recon to report
/autopilot
```

---

## Requirements
- Python 3.10+
- Claude Code, OpenCode, or compatible AI CLI
- curl, jq, and standard UNIX tools

---

## License
MIT — see [LICENSE](LICENSE).
