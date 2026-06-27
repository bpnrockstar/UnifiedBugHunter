#!/usr/bin/env python3
"""
ai_training_data.py — Export findings as fine-tuning data for LLMs.

Exports findings in OpenAI-compatible JSONL format for fine-tuning
security-focused LLMs. Each example includes the bug context and
the methodology used to find/validate it.

Usage:
    python3 tools/ai_training_data.py --format openai --output training.jsonl
    python3 tools/ai_training_data.py --format chat --min-severity high
    python3 tools/ai_training_data.py --stats
"""
import argparse
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.database import get_db, get_findings, get_targets, search_knowledge_base


INSTRUCTIONS_DEFAULT = """You are a bug bounty hunter analyzing a web application for security vulnerabilities. Based on the target information and findings below, describe how you would identify, validate, and report this vulnerability."""


def export_openai(findings, kb_entries, output_path):
    """Export in OpenAI fine-tuning JSONL format (chat completions)."""
    examples = []
    for f in findings:
        examples.append({
            "messages": [
                {"role": "system", "content": INSTRUCTIONS_DEFAULT},
                {"role": "user", "content": f"Target: {f.get('domain', 'unknown')}\nEndpoint: {f.get('endpoint', 'N/A')}\nBug Class: {f.get('bug_class', 'N/A')}\n\nHow do I find and validate this type of vulnerability?"},
                {"role": "assistant", "content": f"Finding: {f['title']}\nSeverity: {f['severity']}\n\nDescription: {f.get('description', 'N/A')}\n\nProof of Concept: {f.get('poc', 'N/A')}\n\nImpact: {f.get('impact', 'N/A')}\n\nRemediation: {f.get('remediation', 'N/A')}"},
            ]
        })

    for kb in kb_entries:
        examples.append({
            "messages": [
                {"role": "system", "content": "You are a bug bounty knowledge base. Provide techniques, payloads, and references for the given vulnerability class."},
                {"role": "user", "content": f"Tell me about {kb['title']} (class: {kb.get('bug_class', 'N/A')})"},
                {"role": "assistant", "content": f"Title: {kb['title']}\nClass: {kb.get('bug_class', 'N/A')}\nSource: {kb.get('source', 'N/A')}\n\nContent: {kb.get('content', 'N/A')}\n\nPayloads: {kb.get('payloads', 'N/A')}\n\nTechniques: {kb.get('techniques', 'N/A')}"},
            ]
        })

    with open(output_path, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")

    print(f"Exported {len(examples)} examples to {output_path}")
    return examples


def export_chat_format(findings, kb_entries, output_path):
    """Export in simpler prompt-completion format."""
    examples = []
    for f in findings:
        examples.append({
            "prompt": f"Bug class: {f.get('bug_class', 'N/A')}\nSeverity: {f['severity']}\nTarget: {f.get('domain', 'unknown')}\nEndpoint: {f.get('endpoint', 'N/A')}\n\nHow to find and validate:",
            "completion": f"Title: {f['title']}\nDescription: {f.get('description', 'N/A')}\nPoC: {f.get('poc', 'N/A')}\nImpact: {f.get('impact', 'N/A')}\nRemediation: {f.get('remediation', 'N/A')}",
        })

    for kb in kb_entries:
        examples.append({
            "prompt": f"Research: {kb['title']} ({kb.get('bug_class', 'N/A')})",
            "completion": f"Source: {kb.get('source', 'N/A')}\nContent: {kb.get('content', 'N/A')}\nPayloads: {kb.get('payloads', 'N/A')}\nTechniques: {kb.get('techniques', 'N/A')}",
        })

    with open(output_path, "w") as f:
        json.dump(examples, f, indent=2)

    print(f"Exported {len(examples)} examples to {output_path}")


def print_stats():
    conn = get_db()
    cur = conn.execute("SELECT COUNT(*) FROM findings")
    findings_count = cur.fetchone()[0]
    cur = conn.execute("SELECT COUNT(*) FROM knowledge_base")
    kb_count = cur.fetchone()[0]
    cur = conn.execute("SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity ORDER BY cnt DESC")
    sevs = cur.fetchall()
    cur = conn.execute("SELECT bug_class, COUNT(*) as cnt FROM findings WHERE bug_class IS NOT NULL GROUP BY bug_class ORDER BY cnt DESC LIMIT 10")
    classes = cur.fetchall()
    conn.close()

    print("=== Training Data Stats ===")
    print(f"Findings available: {findings_count}")
    print(f"Knowledge Base entries: {kb_count}")
    print(f"Total training examples: {findings_count + kb_count}")
    print("\nSeverity distribution:")
    for s in sevs:
        print(f"  {s['severity']}: {s['cnt']}")
    print("\nTop bug classes:")
    for c in classes:
        print(f"  {c['bug_class']}: {c['cnt']}")


def main():
    parser = argparse.ArgumentParser(description="Export findings as AI fine-tuning data")
    parser.add_argument("--format", choices=["openai", "chat"], default="openai", help="Output format")
    parser.add_argument("--output", default="training_data.jsonl", help="Output file path")
    parser.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"], help="Minimum severity to include")
    parser.add_argument("--limit", type=int, default=500, help="Max examples to export")
    parser.add_argument("--stats", action="store_true", help="Show stats about available training data")
    args = parser.parse_args()

    if args.stats:
        print_stats()
        return

    findings, _ = get_findings(severity=args.min_severity, limit=args.limit)
    kb_entries = search_knowledge_base(limit=args.limit)

    print(f"Exporting {len(findings)} findings + {len(kb_entries)} KB entries ({args.format} format)")

    if args.format == "openai":
        export_openai(findings, kb_entries, args.output)
    else:
        export_chat_format(findings, kb_entries, args.output)


if __name__ == "__main__":
    main()
