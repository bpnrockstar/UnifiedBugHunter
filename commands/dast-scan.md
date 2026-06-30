---
description: "Run automated DAST scanning against a target and import results into the bug hunter DB. Subcommands: nuclei <url> (fast: cves/exposures/misconfig), nuclei-deep <url> (all templates), zap <url> (OWASP ZAP active scan, requires ZAP daemon), import <file> (external scan results)."
argument-hint: "nuclei|nuclei-deep|zap <url> | import <file>"
allowed-tools: Bash
---

# /dast-scan — DAST Scanner

Runs automated vulnerability scanners and imports results
into the bug hunter database.

## Usage

```
/dast-scan nuclei <url>          # Fast nuclei scan (cves, exposures, misconfig)
/dast-scan nuclei-deep <url>     # All nuclei templates (slow)
/dast-scan zap <url>             # OWASP ZAP active scan (requires ZAP daemon)
/dast-scan import <file>         # Import external scan results (JSON)
```

## Run This

```bash
bash tools/dast_scanner.sh "$ARGUMENTS"
```

Invoke the script directly; do not re-implement it inline.

## Examples

```bash
# Quick nuclei scan
/dast-scan nuclei https://target.com

# Deep scan with all templates
/dast-scan nuclei-deep https://target.com

# ZAP scan (start ZAP daemon first: zap.sh -daemon -port 8080)
/dast-scan zap https://target.com

# Import existing nuclei/ZAP JSON results
/dast-scan import results.json
```
