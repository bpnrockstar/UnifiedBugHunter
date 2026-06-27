#!/usr/bin/env python3
"""
search_findings.py — CLI search across all stored bug hunter data.

Usage:
    python3 tools/search_findings.py "ssrf"
    python3 tools/search_findings.py "API key" --findings
    python3 tools/search_findings.py --severity high --class xss
    python3 tools/search_findings.py --stats
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.database import (
    get_findings,
    get_recon_data,
    search_knowledge_base,
    get_stats,
)

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
NC = "\033[0m"


def print_header(text):
    print(f"\n{BOLD}{BLUE}═══ {text} ═══{NC}\n")


def search_all(query, limit=20):
    print_header(f"Search Results for: {query}")

    # Findings
    findings, total = get_findings(search=query, limit=limit)
    if findings:
        print(f"{BOLD}Findings ({len(findings)}):{NC}")
        for f in findings:
            sev_color = (
                RED if f["severity"] == "critical" else
                YELLOW if f["severity"] == "high" else
                BLUE if f["severity"] == "medium" else
                CYAN
            )
            print(f"  [{sev_color}{f['severity']:8}{NC}] {BOLD}{f['title']}{NC}")
            print(f"         {f.get('domain', '')} | {f.get('bug_class', 'N/A')} | {f.get('endpoint', '')}")
        print()

    # Knowledge base
    kb = search_knowledge_base(search=query, limit=limit)
    if kb:
        print(f"{BOLD}Knowledge Base ({len(kb)}):{NC}")
        for k in kb:
            print(f"  [{GREEN}KB{NC}] {BOLD}{k['title']}{NC} ({k.get('bug_class', 'N/A')})")
            if k.get("tags"):
                print(f"       Tags: {k['tags']}")
        print()

    # Recon
    recon = get_recon_data(search=query, limit=limit)
    if recon:
        print(f"{BOLD}Recon Data ({len(recon)}):{NC}")
        for r in recon:
            print(f"  [{CYAN}{r['type']:12}{NC}] {r['value']}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Search bug hunter database")
    parser.add_argument("query", nargs="?", help="Search query")
    parser.add_argument("--findings", action="store_true", help="Search findings only")
    parser.add_argument("--kb", action="store_true", help="Search knowledge base only")
    parser.add_argument("--recon", action="store_true", help="Search recon data only")
    parser.add_argument("--severity", help="Filter by severity")
    parser.add_argument("--class", dest="bug_class", help="Filter by bug class")
    parser.add_argument("--limit", type=int, default=20, help="Max results")
    parser.add_argument("--stats", action="store_true", help="Show database stats")
    args = parser.parse_args()

    if args.stats:
        stats = get_stats()
        print_header("Database Statistics")
        print(f"  {BOLD}Targets:{NC}           {stats['targets']}")
        print(f"  {BOLD}Findings:{NC}          {stats['findings']} ({stats['open_findings']} open)")
        print(f"  {BOLD}  Critical:{NC}        {stats['critical']}")
        print(f"  {BOLD}  High:{NC}            {stats['high']}")
        print(f"  {BOLD}  Medium:{NC}          {stats['medium']}")
        print(f"  {BOLD}  Low/Info:{NC}        {stats['low']}")
        print(f"  {BOLD}Recon Entries:{NC}     {stats['recon_entries']}")
        print(f"  {BOLD}  Subdomains:{NC}      {stats['subdomains']}")
        print(f"  {BOLD}  URLs:{NC}            {stats['urls']}")
        print(f"  {BOLD}Reports:{NC}           {stats['reports']}")
        print(f"  {BOLD}Knowledge Base:{NC}    {stats['kb_entries']}")
        print(f"  {BOLD}Monitoring Checks:{NC} {stats['monitoring_checks']}")
        print()
        if stats["top_classes"]:
            print(f"{BOLD}Top Bug Classes:{NC}")
            for c in stats["top_classes"]:
                print(f"  {c['bug_class'] or 'Unclassified'}: {c['cnt']}")
        return

    if not args.query:
        parser.print_help()
        return

    if args.findings:
        findings, total = get_findings(search=args.query, severity=args.severity, bug_class=args.bug_class, limit=args.limit)
        print_header(f"Findings matching: {args.query}")
        for f in findings:
            print(f"  [{f['severity']:8}] {f['title']} ({f.get('domain', '')})")
    elif args.kb:
        entries = search_knowledge_base(search=args.query, bug_class=args.bug_class)
        print_header(f"Knowledge Base matching: {args.query}")
        for e in entries:
            print(f"  [{e.get('bug_class', 'N/A'):12}] {e['title']}")
    elif args.recon:
        data = get_recon_data(search=args.query)
        print_header(f"Recon Data matching: {args.query}")
        for r in data:
            print(f"  [{r['type']:12}] {r['value']} ({r.get('domain', '')})")
    else:
        search_all(args.query, args.limit)


if __name__ == "__main__":
    main()
