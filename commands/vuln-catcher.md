---
description: Start continuous recon monitoring for a target — watches subdomains, JS files, open ports, and tech stack for changes.
argument-hint: <domain> | --all-targets [--check subdomains js ports tech] [--once] [--interval N] [--force]
allowed-tools: Bash
---

# /vuln-catcher — Continuous Recon Monitor

Monitors one or more targets for changes in:
- Subdomains (via crt.sh + subfinder)
- JavaScript files (content hash comparison)
- Open ports (via nmap/naabu)
- Technology stack (via whatweb/wappalyzer)

By default monitoring loops forever on a polling interval. Pass `--once` to run a
single pass and exit.

## Run This

Invoke the backing script directly with the user's arguments; do NOT re-implement
the monitoring logic inline:

```bash
python3 tools/vuln_catcher.py $ARGUMENTS
```

## Usage

```
/vuln-catcher --target example.com --once            # One pass over a single target
/vuln-catcher --all-targets --once                   # One pass over all DB targets
/vuln-catcher --all-targets                           # Continuous loop (default interval 3600s)
/vuln-catcher --target example.com --check subdomains js   # Only specific checks
/vuln-catcher --target example.com --interval 1800    # Custom polling interval (seconds)
/vuln-catcher --target example.com --check subdomains --force   # Force re-check, ignore stored state
```

## Flags

| Flag | Effect |
|---|---|
| `--target <domain>` | Monitor a single target domain |
| `--all-targets` | Monitor every active target in the database |
| `--check <types...>` | Subset of checks: `subdomains js ports tech` (default: all four) |
| `--once` | Run a single pass and exit (omit for a continuous loop) |
| `--interval <seconds>` | Polling interval for the continuous loop (default: 3600) |
| `--force` | Re-check regardless of stored baseline state |

## Examples

```bash
# One-shot check of a single target, all checks
python3 tools/vuln_catcher.py --target example.com --once

# One-shot check of every target in the database
python3 tools/vuln_catcher.py --all-targets --once

# Continuous monitoring of all targets, poll every 30 min
python3 tools/vuln_catcher.py --all-targets --interval 1800

# Check only subdomains and JS for one target
python3 tools/vuln_catcher.py --target example.com --check subdomains js
```
