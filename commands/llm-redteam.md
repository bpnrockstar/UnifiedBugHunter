---
command: llm-redteam
description: "Run advanced LLM red teaming against an LLM endpoint — 200+ payloads across 6 attack categories with confidence scoring and HTML reports"
usage: |
  /llm-redteam <endpoint> [--model] [--category] [--limit] [--oob-host]
  /llm-redteam --list-payloads           — List all available payloads
  /llm-redteam --dry-run <category>      — Preview payloads without sending
---

# /llm-redteam — Advanced LLM Red Teaming

Tests LLM endpoints against 200+ prompt injection, jailbreak, encoding bypass,
exfiltration, agentic, and multi-turn escalation payloads.

Supports OpenAI API endpoints and custom HTTP endpoints.

## Examples

```bash
# Full scan against OpenAI
/llm-redteam openai --model gpt-4

# Test jailbreak payloads only (20)
/llm-redteam openai --category jailbreak --limit 20

# Test with OOB callback for exfil detection
/llm-redteam openai --oob-host collide.oastify.com --category exfil

# Test custom endpoint
/llm-redteam http://localhost:8080/chat --type custom

# Multi-turn escalation testing
/llm-redteam openai --category multi-turn

# Generate HTML report
/llm-redteam openai --html report.html

# Save results to DB
/llm-redteam openai --import-db

# See all payloads
/llm-redteam --list-payloads
```
