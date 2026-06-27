---
name: dast-scanner
description: "Automated DAST scanning with OWASP ZAP and nuclei integration. Scans targets and imports findings into the bug hunter database for analysis and reporting."
---

# DAST Scanner Integration

Automated vulnerability scanning wrapper that runs OWASP ZAP and nuclei,
then imports all findings into the searchable bug hunter database.

## Tools

### OWASP ZAP
- Full active scan with spider + AJAX spider
- Imports all alerts (risk levels mapped to severity)
- Requires ZAP running in daemon mode

### Nuclei
- Fast template-based scanning
- Categories: cves, exposures, misconfiguration, vulnerabilities, technologies
- Deep scan with ALL templates

## Usage

```bash
# Nuclei scan (fast)
./tools/dast_scanner.sh nuclei https://target.com

# Nuclei deep scan
./tools/dast_scanner.sh nuclei-deep https://target.com

# ZAP scan (start ZAP daemon first)
zap.sh -daemon -port 8080
./tools/dast_scanner.sh zap https://target.com

# Import existing results
./tools/dast_scanner.sh import nuclei_results.json
```

## Finding Import

Each finding from ZAP or nuclei is automatically imported with:
- Severity mapping (critical/high/medium/low/info)
- Endpoint URL
- Description from scanner output
- Source tagged as 'dast' for traceability
- Associated with the correct target domain
