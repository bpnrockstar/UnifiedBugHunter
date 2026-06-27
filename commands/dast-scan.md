---
command: dast-scan
description: "Run automated DAST scanning (ZAP/nuclei) against a target"
usage: |
  /dast-scan nuclei <url>           — Fast nuclei scan (cves, exposures, misconfig)
  /dast-scan nuclei-deep <url>      — All nuclei templates
  /dast-scan zap <url>             — OWASP ZAP active scan (requires ZAP daemon)
  /dast-scan import <file>         — Import external scan results
---

# /dast-scan — DAST Scanner

Runs automated vulnerability scanners and imports results
into the bug hunter database.

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
