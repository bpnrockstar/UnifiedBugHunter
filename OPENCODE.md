# Bug Bounty Hunter — OpenCode Guide

This repo is a professional bug bounty hunting framework for OpenCode, covering HackerOne, Bugcrowd, Intigriti, and Immunefi.

## Installation

### Prerequisites

```bash
# macOS
brew install go python3 node jq

# Linux (Ubuntu/Debian)
sudo apt install golang python3 nodejs jq
```

You also need [OpenCode](https://opencode.ai) installed.

### Install

```bash
git clone https://github.com/bpnrockstar/UnifiedBugHunter.git
cd UnifiedBugHunter
chmod +x install_tools.sh && ./install_tools.sh   # scanning tools
chmod +x install.sh && ./install.sh --opencode    # skills + commands
```

The installer will:
1. Symlink domain skills to `.opencode/skills/`
2. Copy commands to `.opencode/commands/`
3. Optionally write MCP server config to `opencode.json`

### Verify Installation

```bash
cd UnifiedBugHunter
opencode
# Ask: "do you have bug bounty skills?"
# Should confirm skills are loaded
```

## What's Here

### Skills (89 total, including 48 `hunt-*` per-class skills)

| Skill | Domain |
|---|---|
| `bug-bounty` | Master workflow — recon to report, all vuln classes, LLM testing, chains |
| `bb-methodology` | Hunting mindset + 5-phase non-linear workflow + tool routing + session discipline |
| `web2-recon` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `web2-vuln-classes` | 24 bug classes with bypass tables (SSRF, open redirect, file upload, Agentic AI) |
| `security-arsenal` | Payloads, bypass tables, gf patterns, always-rejected list |
| `web3-audit` | 10 smart contract bug classes, Foundry PoC template, pre-dive kill signals |
| `meme-coin-audit` | Meme coin rug pull detection, token authority checks, bonding curve exploits, LP attacks |
| `report-writing` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, human tone |
| `triage-validation` | 7-Question Gate, 4 gates, never-submit list, conditionally valid table |
| `social-engineering` | Phishing campaigns, pretexts, vishing, SMTP infrastructure |
| `malware-analysis` | Static/dynamic malware analysis, YARA, MITRE ATT&CK |
| `reverse-engineering` | Binary decompilation, firmware analysis, algorithm extraction |
| `forensics` | DFIR — disk/memory/network forensics, timeline analysis |
| `active-directory` | Kerberos, NTLM relay, ADCS, ACL abuse, DCSync |
| `container-security` | Docker/K8s escape, RBAC abuse, runtime CVEs |
| `code-review` | White-box source code audit — SAST for 10 languages, 10-phase methodology |
| `code-patch` | Security patch generation — minimal, tested fixes for all OWASP Top 10 classes |
| `auto-hunt` | Autonomous full-spectrum hunter — recon to report with closed-loop verification |
| `vuln-catcher` | Continuous recon monitor — subdomains, JS changes, ports, tech changes |
| `dast-scanner` | Automated DAST scanning (OWASP ZAP + nuclei) with DB import |
| `knowledge-base` | Searchable vulnerability KB — disclosed reports, payloads, bypass techniques |
| `llm-redteam` | **Advanced LLM red teaming** — 15+ techniques, 180+ payloads, automated CLI |

### Commands (35 commands)

| Command | Usage |
|---|---|
| `recon` | "recon target.com" — full recon pipeline |
| `hunt` | "hunt target.com" — start hunting |
| `validate` | "validate" — run 7-Question Gate on current finding |
| `report` | "report" — write submission-ready report |
| `chain` | "chain" — build A→B→C exploit chain |
| `scope` | "scope <asset>" — verify asset is in scope |
| `scope-aggregate` | "scope-aggregate <program>" — pull every in-scope asset |
| `triage` | "triage" — quick 7-Question Gate |
| `web3-audit` | "web3-audit <contract.sol>" — smart contract audit |
| `autopilot` | "autopilot target.com --normal" — autonomous hunt loop |
| `surface` | "surface target.com" — ranked attack surface |
| `pickup` | "pickup target.com" — pick up previous hunt |
| `remember` | "remember" — log finding to hunt memory |
| `intel` | "intel target.com" — fetch CVE + disclosure intel |
| `token-scan` | "token-scan <contract>" — meme coin/token rug pull scanner |
| `memory-gc` | "memory-gc" — inspect/rotate hunt-memory JSONL files |
| `secrets-hunt` | "secrets-hunt --js-bundle <recon-dir>" — leaked-credential scan |
| `takeover` | "takeover --recon <recon-dir>" — subdomain takeover candidates |
| `cloud-recon` | "cloud-recon --keyword <name>" — public S3/Azure/GCP |
| `param-discover` | "param-discover <url>" — find hidden HTTP parameters |
| `bypass-403` | "bypass-403 <url>" — try header/method/encoding tricks |
| `arsenal` | "arsenal [tool]" — list installed external tools |
| `scan-cves` | "scan-cves <host>" — focused nuclei CVE sweep |
| `code-audit` | "code-audit [path]" — white-box source code audit |
| `patch` | "patch [file:line]" — generate security patch for vulnerable code |
| `vuln-catcher` | "vuln-catcher target.com [--continuous]" — continuous recon monitor |
| `dast-scan` | "dast-scan nuclei target.com" — automated DAST scanning |
| `search-findings` | "search-findings ssrf --severity high" — search all database tables |
| `dashboard` | "dashboard" — launch web GUI |
| `llm-redteam` | "llm-redteam openai --category jailbreak" — automated LLM red teaming |

## Usage

### Invoking Commands

OpenCode doesn't have slash commands. Use natural language:

| Task | Say |
|------|-----|
| Run recon | "recon target.com" or "run recon on target.com" |
| Start hunting | "hunt target.com" or "start hunting target.com" |
| Validate finding | "validate this finding" or "run validation" |
| Write report | "write a report" or "generate report" |

Commands auto-invoke based on context.

### Quick Start

```bash
cd UnifiedBugHunter
opencode

# In OpenCode:
> recon target.com
> hunt target.com
> validate
> report
```

## MCP Integration (6 servers)

| Server | Purpose |
|--------|---------|
| `burp` | Burp Suite proxy — intercept and replay requests |
| `caido` | Caido proxy — alternative to Burp |
| `hackerone` | HackerOne public API — Hacktivity, program stats, policy |
| `bugcrowd` | Bugcrowd public API — Crowdstream, program info, public bounties |
| `intigriti` | Intigriti public API — research blog, XSS challenge search |
| `immunefi` | Immunefi public API — disclosed reports, program TVL/bounties/contracts |

OpenCode MCP servers are configured under the `mcp` key in your `opencode.json` (project-level) or `~/.config/opencode/config.json` (global).

> **Format note:** OpenCode uses `mcp` (not `mcpServers`), `command` is a single array merging the executable and its arguments, and environment variables go under `environment` (not `env`). Use `{env:VAR_NAME}` to reference shell environment variables.

**Burp Suite MCP:**
```json
{
  "mcp": {
    "burp": {
      "type": "local",
      "command": ["java", "-jar", "/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"],
      "enabled": true
    }
  }
}
```

**Caido MCP:**
```json
{
  "mcp": {
    "caido": {
      "type": "local",
      "command": ["npx", "-y", "@caido/mcp-server"],
      "enabled": true,
      "environment": {
        "CAIDO_API_KEY": "{env:CAIDO_API_KEY}",
        "CAIDO_URL": "{env:CAIDO_URL}"
      }
    }
  }
}
```

**HackerOne MCP** (run from the project root — path is relative):
```json
{
  "mcp": {
    "hackerone": {
      "type": "local",
      "command": ["python3", "mcp/hackerone-mcp/server.py"],
      "enabled": true
    }
  }
}
```

**Bugcrowd MCP:**
```json
{
  "mcp": {
    "bugcrowd": {
      "type": "local",
      "command": ["python3", "mcp/bugcrowd-mcp/server.py"],
      "enabled": true
    }
  }
}
```

**Intigriti MCP:**
```json
{
  "mcp": {
    "intigriti": {
      "type": "local",
      "command": ["python3", "mcp/intigriti-mcp/server.py"],
      "enabled": true
    }
  }
}
```

**Immunefi MCP:**
```json
{
  "mcp": {
    "immunefi": {
      "type": "local",
      "command": ["python3", "mcp/immunefi-mcp/server.py"],
      "enabled": true
    }
  }
}
```

See `mcp/*/opencode-config.json` for ready-to-copy snippets.

## Memory Management

Hunt memory auto-rotates at 10MB. To manually rotate:
```bash
python3 -m tools.memory_gc --rotate
```

## API Keys

Same as Claude Code version. See main README.md for:
- Chaos API (subdomain discovery)
- Optional keys (VirusTotal, SecurityTrails, etc.)

## The Rules (Always Active)

```
 1. READ FULL SCOPE FIRST   — only test what the program says you can
 2. ONLY REAL BUGS          — "Can an attacker do this RIGHT NOW?" if no, stop
 3. KILL WEAK FINDINGS FAST — 30-second check saves hours of wasted reporting
 4. NEVER GO OUT OF SCOPE   — one wrong request can get you banned
 5. 5-MINUTE RULE           — no progress after 5 min? move to the next target
 6. VALIDATE BEFORE REPORT  — run validation before you spend 30 min writing
 7. IMPACT FIRST            — start with the bugs that have the worst consequences
```

## Differences from Claude Code

| Feature | Claude Code | OpenCode |
|---------|-------------|----------|
| Commands | `/recon target.com` | "recon target.com" |
| Skills location | `~/.claude/skills/` | `.opencode/skills/` (in project) |
| Commands location | `~/.claude/commands/` | `.opencode/commands/` (in project) |
| Memory rotation | Auto (Stop hook) | Manual (`python3 -m tools.memory_gc --rotate`) |
| MCP config | `.claude/settings.json` | `opencode.json` (project) or `~/.config/opencode/config.json` (global) |

## Troubleshooting

### Skills not loading
1. Check symlinks: `ls -la .opencode/skills/`
2. Restart OpenCode in this project directory

### Commands not working
1. Check commands: `ls -la .opencode/commands/`
2. Make sure you're running OpenCode from the project root
3. Check OpenCode logs for errors

### MCP servers not connecting
1. Check `opencode.json` (or `~/.config/opencode/config.json`) syntax — ensure `mcp` key uses `command` array + `environment` (not `args`/`env`)
2. Verify Java is in your PATH: `java --version`
3. Test the proxy jar manually: `java -jar /path/to/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876`
4. List servers and auth status: `opencode mcp list`

## Contributing

Same as main project. See README.md.

---

**Built by bug hunters, for bug hunters.** Works with Claude Code and OpenCode.

<sub>MIT License · For authorized security testing only. Test only within an approved bug bounty program scope.</sub>
