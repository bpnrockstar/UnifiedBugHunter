---
command: search-findings
description: "Search findings, recon data, and knowledge base across all stored data"
usage: |
  /search-findings <query>                    — Full-text search across all data
  /search-findings <query> --findings         — Search findings only
  /search-findings <query> --kb              — Search knowledge base only
  /search-findings <query> --recon           — Search recon data only
  /search-findings --severity <level>         — Filter by severity
  /search-findings --class <bug_class>        — Filter by bug class
  /search-findings --stats                    — Show database statistics
---

# /search-findings — Searchable Database

Search all collected data (findings, recon, knowledge base) from
a single command. Results are displayed in a unified format.

## Examples

```bash
# Full-text search across everything
/search-findings ssrf

# Search findings only
/search-findings "API key" --findings

# Search knowledge base for specific technique
/search-findings "bypass" --kb

# Filter by severity and class
/search-findings --severity high --class xss

# Show database stats
/search-findings --stats

# Search recon data
/search-findings admin --recon
```
