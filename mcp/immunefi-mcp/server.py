#!/usr/bin/env python3
"""
Immunefi MCP Server — public endpoints.

Provides:
  - search_reports: Search Immunefi's disclosed bug bounty reports
  - get_program: Get program details (name, TVL, bounty range, contract addresses)
  - list_bounties: List active bug bounty programs

Usage (standalone test):
    python3 mcp/immunefi-mcp/server.py search "reentrancy"
    python3 mcp/immunefi-mcp/server.py program "sushi"
    python3 mcp/immunefi-mcp/server.py bounties
"""

import json
import re
import sys
import urllib.request


IMMUNEFI_GRAPHQL = "https://immunefi.com/graphql"


def search_disclosed_reports(query: str, limit: int = 10) -> str:
    """Search Immunefi's disclosed reports via GraphQL."""
    graphql_query = {
        "query": """
        query SearchDisclosedReports($query: String!, $limit: Int!) {
            bugBounties(first: $limit, where: {disclosed: true, title_contains: $query}) {
                id
                title
                severity
                payout
                program { name }
                disclosedAt
            }
        }
        """,
        "variables": {"query": query, "limit": limit}
    }
    req = urllib.request.Request(
        IMMUNEFI_GRAPHQL,
        data=json.dumps(graphql_query).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "MCP/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            reports = data.get("data", {}).get("bugBounties", [])
            return json.dumps(reports[:limit], indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "query": query})


def get_program_info(program_slug: str) -> str:
    """Get public program info from Immunefi."""
    graphql_query = {
        "query": """
        query GetProgram($slug: String!) {
            program(slug: $slug) {
                name
                description
                tvl
                bountyMin
                bountyMax
                contracts { address chain }
                isActive
            }
        }
        """,
        "variables": {"slug": program_slug}
    }
    req = urllib.request.Request(
        IMMUNEFI_GRAPHQL,
        data=json.dumps(graphql_query).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "MCP/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            program = data.get("data", {}).get("program", {})
            return json.dumps(program, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "slug": program_slug})


def list_active_bounties(limit: int = 20) -> str:
    """List currently active bug bounty programs on Immunefi."""
    graphql_query = {
        "query": """
        query ListPrograms($limit: Int!) {
            programs(first: $limit, where: {isActive: true}) {
                name
                slug
                tvl
                bountyMin
                bountyMax
                isActive
            }
        }
        """,
        "variables": {"limit": limit}
    }
    req = urllib.request.Request(
        IMMUNEFI_GRAPHQL,
        data=json.dumps(graphql_query).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "MCP/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            programs = data.get("data", {}).get("programs", [])
            return json.dumps(programs[:limit], indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 server.py <command> [args]", file=sys.stderr)
        sys.exit(1)

    if sys.argv[1] == "search":
        query = sys.argv[2] if len(sys.argv) > 2 else ""
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        print(search_disclosed_reports(query, limit))
    elif sys.argv[1] == "program":
        slug = sys.argv[2] if len(sys.argv) > 2 else ""
        print(get_program_info(slug))
    elif sys.argv[1] == "bounties":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        print(list_active_bounties(limit))
    else:
        print(json.dumps({"error": f"Unknown command: {sys.argv[1]}"}))
