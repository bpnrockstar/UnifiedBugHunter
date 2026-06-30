---
description: Run advanced LLM red teaming against an LLM endpoint — 200+ payloads across 6 attack categories with confidence scoring and HTML reports
argument-hint: <endpoint> [--category <cat>] [--model <name>] [--limit N] [--oob-host <host>]
allowed-tools: Bash
---

# /llm-redteam — Advanced LLM Red Teaming

Tests LLM endpoints against 200+ prompt injection, jailbreak, encoding bypass,
exfiltration, agentic, and multi-turn escalation payloads.

Supports OpenAI API endpoints and custom HTTP endpoints.

## Run This

Invoke `tools/llm_redteam.py` directly — do not re-implement the payloads or
scoring. The endpoint is passed via `--target` (it is NOT positional):

```bash
python3 tools/llm_redteam.py --target $ARGUMENTS
```

## Usage

```
/llm-redteam <endpoint> [--model <name>] [--category <cat>] [--limit N] [--oob-host <host>]
/llm-redteam --list-payloads                  — List all available payloads
/llm-redteam --dry-run --category <cat>        — Preview payloads without sending
```

## Examples

```bash
# Full scan against OpenAI
python3 tools/llm_redteam.py --target openai --model gpt-4

# Test jailbreak payloads only (20)
python3 tools/llm_redteam.py --target openai --category jailbreak --limit 20

# Test with OOB callback for exfil detection
python3 tools/llm_redteam.py --target openai --oob-host collide.oastify.com --category exfil

# Test custom endpoint
python3 tools/llm_redteam.py --target http://localhost:8080/chat --type custom

# Multi-turn escalation testing
python3 tools/llm_redteam.py --target openai --category multi-turn

# Generate HTML report
python3 tools/llm_redteam.py --target openai --html report.html

# Save results to DB
python3 tools/llm_redteam.py --target openai --import-db

# Preview a category without sending (--dry-run is a standalone flag)
python3 tools/llm_redteam.py --dry-run --category jailbreak

# See all payloads
python3 tools/llm_redteam.py --list-payloads
```
