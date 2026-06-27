---
command: vuln-catcher
description: "Start continuous recon monitoring for a target"
usage: |
  /vuln-catcher [domain]           — Monitor a single target once, all checks
  /vuln-catcher --all              — Monitor all targets once
  /vuln-catcher --continuous       — Monitor all targets continuously (background)
  /vuln-catcher --check <types>    — Only specific checks (subdomains, js, ports, tech)
  /vuln-catcher --status           — Show monitoring status and recent changes
  /vuln-catcher --dashboard        — Start the web dashboard
---

# /vuln-catcher — Continuous Recon Monitor

Starts monitoring one or more targets for changes in:
- Subdomains (via crt.sh + subfinder)
- JavaScript files (content hash comparison)
- Open ports (via naabu)
- Technology stack (via whatweb)

## Examples

```bash
# Monitor a target once
/vuln-catcher example.com

# Monitor all targets in the database
/vuln-catcher --all

# Continuous monitoring (runs in background)
/vuln-catcher --continuous

# Check only subdomains and JS
/vuln-catcher example.com --check subdomains js

# Show monitoring status
/vuln-catcher --status

# Launch the dashboard GUI
/vuln-catcher --dashboard
```
