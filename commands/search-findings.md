---
description: Search findings, recon data, and knowledge base across all stored data
argument-hint: <query> [--findings|--kb|--recon] [--severity <level>] [--class <bug_class>] [--stats]
allowed-tools: Bash
---

# /search-findings — Searchable Database

Search all collected data (findings, recon, knowledge base) from
a single command. Results are displayed in a unified format.

## Run This

Invoke the backing script directly — do not re-implement the search:

```bash
python3 tools/search_findings.py "$ARGUMENTS"
```

The script takes an optional positional query plus flags: `--findings`,
`--kb`, `--recon` (scope to one table), `--severity <level>` and
`--class <bug_class>` (filters), `--limit <n>`, and `--stats` (DB statistics, no
query needed). Passing `"$ARGUMENTS"` forwards the user's query and any flags.

## Usage

```
/search-findings <query>                    — Full-text search across all data
/search-findings <query> --findings         — Search findings only
/search-findings <query> --kb               — Search knowledge base only
/search-findings <query> --recon            — Search recon data only
/search-findings <query> --severity <level> — Filter by severity
/search-findings <query> --class <bug_class> — Filter by bug class
/search-findings --stats                    — Show database statistics
```

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
