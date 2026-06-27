#!/usr/bin/env python3
"""
vuln_catcher.py — Continuous Recon Monitor for Unified Bug Hunter.

Watches targets for:
  - New subdomains (subfinder, crt.sh)
  - JavaScript file changes (content hash comparison)
  - New open ports (nmap/naabu)
  - Technology stack changes (whatweb/wappalyzer)
  - Certificate transparency updates

Usage:
    python3 tools/vuln_catcher.py --target example.com --interval 3600
    python3 tools/vuln_catcher.py --all-targets
    python3 tools/vuln_catcher.py --target example.com --check subdomains --force
"""
import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.database import init_db, get_db, get_targets, add_recon_data, log_monitoring, add_finding

HERE = Path(__file__).resolve().parent
STATE_DIR = HERE / ".vuln_catcher"
STATE_DIR.mkdir(parents=True, exist_ok=True)


def log(msg, level="INFO"):
    print(f"[{datetime.now().isoformat()}] [{level}] {msg}")


def hash_file(content):
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def check_subdomains_crtsh(domain):
    log(f"Fetching subdomains from crt.sh for {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = n.strip().lower()
                if n.endswith(f".{domain}") or n == domain:
                    subs.add(n)
        return sorted(subs)
    except Exception as e:
        log(f"crt.sh error: {e}", "ERROR")
        return []


def check_subdomains_subfinder(domain):
    log(f"Running subfinder for {domain}")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=120,
        )
        return sorted(set(result.stdout.strip().split("\n"))) if result.stdout.strip() else []
    except FileNotFoundError:
        log("subfinder not installed, skipping", "WARN")
        return []
    except Exception as e:
        log(f"subfinder error: {e}", "ERROR")
        return []


def check_js_changes(target_id, domain):
    log(f"Checking JS file changes for {domain}")
    state_file = STATE_DIR / f"js_{domain}.json"
    old_state = {}
    if state_file.exists():
        old_state = json.loads(state_file.read_text())

    try:
        result = subprocess.run(
            ["katana", "-u", f"https://{domain}", "-jc", "-silent"],
            capture_output=True, text=True, timeout=60,
        )
        urls = [u for u in result.stdout.strip().split("\n") if u.endswith(".js")] if result.stdout.strip() else []
    except FileNotFoundError:
        urls = []
    except Exception as e:
        log(f"katana error: {e}", "WARN")
        urls = []

    new_changes = []
    current_state = {}
    for url in urls[:50]:  # limit
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
            fhash = hash_file(content)
            current_state[url] = fhash
            if url in old_state and old_state[url] != fhash:
                new_changes.append(url)
                add_recon_data(target_id, "js_file", url, source="vuln_catcher")
                log_monitoring(target_id, "js_change", "changed", f"JS hash changed: {url}")
                log(f"JS changed: {url}")
        except Exception:
            pass

    state_file.write_text(json.dumps(current_state, indent=2))
    return new_changes


def check_ports(domain):
    log(f"Scanning ports for {domain}")
    try:
        result = subprocess.run(
            ["naabu", "-host", domain, "-silent", "-json"],
            capture_output=True, text=True, timeout=120,
        )
        ports = []
        for line in result.stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    ports.append(f"{data.get('port', '?')}/{data.get('protocol', 'tcp')}")
                except json.JSONDecodeError:
                    pass
        return sorted(set(ports))
    except FileNotFoundError:
        log("naabu not installed, skipping", "WARN")
        return []
    except Exception as e:
        log(f"naabu error: {e}", "ERROR")
        return []


def check_tech(domain):
    log(f"Detecting technology for {domain}")
    try:
        result = subprocess.run(
            ["whatweb", f"https://{domain}", "--log-json", "/dev/stdout", "--quiet"],
            capture_output=True, text=True, timeout=60,
        )
        techs = []
        for line in result.stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    if "plugins" in data:
                        techs.extend(data["plugins"].keys())
                except json.JSONDecodeError:
                    pass
        return sorted(set(techs))
    except FileNotFoundError:
        pass
    except Exception as e:
        log(f"whatweb error: {e}", "WARN")

    try:
        result = subprocess.run(
            ["curl", "-sI", f"https://{domain}"],
            capture_output=True, text=True, timeout=15,
        )
        headers = result.stdout.lower()
        techs = []
        if "cloudflare" in headers:
            techs.append("Cloudflare")
        if "nginx" in headers:
            techs.append("Nginx")
        if "apache" in headers:
            techs.append("Apache")
        if "fastly" in headers:
            techs.append("Fastly")
        if "akamai" in headers:
            techs.append("Akamai")
        return techs
    except Exception as e:
        log(f"curl error: {e}", "ERROR")
        return []


def monitor_target(target_id, domain, checks=None):
    init_db()
    if checks is None:
        checks = ["subdomains", "js", "ports", "tech"]

    log(f"Monitoring {domain} (checks: {', '.join(checks)})")

    if "subdomains" in checks:
        subs_crt = check_subdomains_crtsh(domain)
        subs_sf = check_subdomains_subfinder(domain)
        all_subs = sorted(set(subs_crt + subs_sf))
        log(f"Found {len(all_subs)} subdomains for {domain}")

        state_file = STATE_DIR / f"subs_{domain}.json"
        old_subs = set()
        if state_file.exists():
            old_subs = set(json.loads(state_file.read_text()))

        new_subs = [s for s in all_subs if s not in old_subs]
        if new_subs:
            log(f"NEW subdomains: {', '.join(new_subs[:10])}{'...' if len(new_subs) > 10 else ''}")
            for sub in new_subs:
                add_recon_data(target_id, "subdomain", sub, source="vuln_catcher")
            log_monitoring(target_id, "subdomain", "new", f"Found {len(new_subs)} new subdomains")
        else:
            log_monitoring(target_id, "subdomain", "unchanged", f"{len(all_subs)} subdomains (no change)")

        state_file.write_text(json.dumps(all_subs, indent=2))

    if "js" in checks:
        check_js_changes(target_id, domain)

    if "ports" in checks:
        ports = check_ports(domain)
        log(f"Found {len(ports)} open ports for {domain}")
        for p in ports:
            add_recon_data(target_id, "port", p, source="vuln_catcher")

    if "tech" in checks:
        techs = check_tech(domain)
        log(f"Detected {len(techs)} technologies for {domain}")
        for t in techs:
            add_recon_data(target_id, "technology", t, source="vuln_catcher")

    log(f"Completed monitoring {domain}")


def main():
    parser = argparse.ArgumentParser(description="Continuous Recon Monitor")
    parser.add_argument("--target", help="Single target domain")
    parser.add_argument("--all-targets", action="store_true", help="Monitor all targets in database")
    parser.add_argument("--interval", type=int, default=3600, help="Polling interval in seconds (default: 3600)")
    parser.add_argument("--check", nargs="+", default=["subdomains", "js", "ports", "tech"],
                        help="Checks to run: subdomains js ports tech")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--force", action="store_true", help="Force re-check regardless of state")
    args = parser.parse_args()

    init_db()

    if args.all_targets:
        targets = get_targets(status="active")
    elif args.target:
        targets = [{"id": 0, "domain": args.target}]
    else:
        parser.print_help()
        sys.exit(1)

    if args.once:
        for t in targets:
            if t["id"] == 0:
                # Need to add target to DB first
                from dashboard.database import add_target as add_t
                add_t(t["domain"])
                # Re-fetch
                targets = get_targets()
                t = targets[-1] if targets else None
                if not t:
                    continue
            monitor_target(t["id"], t["domain"], args.check)
        return

    log(f"Starting continuous monitoring (interval: {args.interval}s)")
    while True:
        for t in targets:
            try:
                monitor_target(t["id"], t["domain"], args.check)
            except Exception as e:
                log(f"Error monitoring {t['domain']}: {e}", "ERROR")
        log(f"Sleeping for {args.interval}s...")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
