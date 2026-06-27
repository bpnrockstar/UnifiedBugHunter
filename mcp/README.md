# MCP

MCP (Model Context Protocol) server integrations — 6 servers spanning all major bug bounty platforms.

| Integration | Purpose |
|:---|:---|
| `burp-mcp-client/` | Burp Suite proxy — pipe AI requests through Burp for interception |
| `caido-mcp-client/` | Caido proxy — alternative to Burp |
| `hackerone-mcp/` | HackerOne public API — Hacktivity, program stats, scope/policy |
| `bugcrowd-mcp/` | Bugcrowd public API — Crowdstream, program info, public bounty listings |
| `intigriti-mcp/` | Intigriti public API — research blog search, XSS challenge info |
| `immunefi-mcp/` | Immunefi public API — disclosed reports, program TVL/bounties/contracts |

## Configure

### Claude Code
Add to `~/.claude/settings.json` under `mcpServers`.

### OpenCode
Add to project `opencode.json` or `~/.config/opencode/config.json` under `mcp`.

See each server's `opencode-config.json` for a ready-to-copy configuration block.

## Quick Test

```bash
# Test each server independently:
python3 mcp/hackerone-mcp/server.py search "ssrf" --limit 3
python3 mcp/bugcrowd-mcp/server.py search "xss" --limit 3
python3 mcp/intigriti-mcp/server.py challenge
python3 mcp/immunefi-mcp/server.py search "reentrancy" --limit 3
```
