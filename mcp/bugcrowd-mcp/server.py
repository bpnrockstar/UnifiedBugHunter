#!/usr/bin/env python3
"""
Bugcrowd MCP Server — public endpoints (Crowdstream, public program info).

Provides:
  - search_crowdstream: Search Bugcrowd Crowdstream for disclosed findings
  - get_program_info: Get public program details (name, URL, scope summary)
  - search_public_bounties: List active public bounty programs

Usage (standalone test):
    python3 mcp/bugcrowd-mcp/server.py search "xss"
    python3 mcp/bugcrowd-mcp/server.py program "bugcrowd"
    python3 mcp/bugcrowd-mcp/server.py bounties
"""

import json
import sys
import urllib.request
import urllib.parse


BUGGROWD_API = "https://api.bugcrowd.com"
CROWDSTREAM_URL = "https://bugcrowd.com/crowdstream.json"
PUBLIC_BOUNTIES = "https://bugcrowd.com/programs.json"


def search_crowdstream(query: str, limit: int = 10) -> str:
    """Search Bugcrowd Crowdstream for disclosed findings matching query."""
    params = urllib.parse.urlencode({"search": query, "per_page": limit})
    url = f"{CROWDSTREAM_URL}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "MCP/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            results = data.get("crowdstream", data.get("findings", data))[:limit]
            # Normalize to readable JSON
            return json.dumps(results, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


def get_program_info(program_slug: str) -> str:
    """Get public info for a Bugcrowd program."""
    url = f"{BUGGROWD_API}/{program_slug}"
    req = urllib.request.Request(url, headers={"User-Agent": "MCP/1.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.dumps(json.loads(resp.read().decode()), indent=2, default=str)
    except urllib.error.HTTPError as e:
        # Fallback to scraping the program page for public info
        fallback_url = f"https://bugcrowd.com/{program_slug}"
        fb_req = urllib.request.Request(fallback_url, headers={"User-Agent": "MCP/1.0"})
        try:
            with urllib.request.urlopen(fb_req, timeout=15) as fb_resp:
                return json.dumps({"program_url": fallback_url, "status": fb_resp.status, "note": "Scraped from program page"})
        except Exception:
            return json.dumps({"error": f"Program '{program_slug}' not found"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def list_public_bounties(limit: int = 20) -> str:
    """List currently active Bugcrowd public bounty programs."""
    req = urllib.request.Request(PUBLIC_BOUNTIES, headers={"User-Agent": "MCP/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            programs = data[:limit] if isinstance(data, list) else data.get("programs", [])[:limit]
            return json.dumps(programs, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 server.py <command> [args]", file=sys.stderr)
        print("Commands: search <query> [limit], program <slug>, bounties [limit]", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "search":
        query = sys.argv[2] if len(sys.argv) > 2 else ""
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        print(search_crowdstream(query, limit))
    elif cmd == "program":
        slug = sys.argv[2] if len(sys.argv) > 2 else ""
        print(get_program_info(slug))
    elif cmd == "bounties":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        print(list_public_bounties(limit))
    else:
        print(json.dumps({"error": f"Unknown command: {cmd}"}))
