#!/usr/bin/env python3
"""
Intigriti MCP Server — public endpoints.

Provides:
  - search_research: Search Intigriti's public research/disclosed reports
  - get_challenge: Get current Intigriti XSS challenge details
  - search_blog: Search Intigriti blog for methodology articles

Usage (standalone test):
    python3 mcp/intigriti-mcp/server.py research "idor"
    python3 mcp/intigriti-mcp/server.py challenge
    python3 mcp/intigriti-mcp/server.py blog "ssrf"
"""

import json
import re
import sys
import urllib.request


INTIGRITI_BLOG = "https://blog.intigriti.com"
INTIGRITI_RESEARCH = "https://blog.intigriti.com/category/research"
INTIGRITI_CHALLENGE = "https://challenge.intigriti.io"


def search_research(query: str, limit: int = 5) -> str:
    """Search Intigriti's public research blog for articles matching query."""
    try:
        req = urllib.request.Request(f"{INTIGRITI_RESEARCH}/page/1", headers={"User-Agent": "MCP/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            # Extract article titles and URLs (basic HTML parsing)
            articles = re.findall(
                r'<h[2-3][^>]*>.*?<a[^>]*href=["\'](/[^"\']*)["\'][^>]*>(.*?)</a>.*?</h[2-3]>',
                html, re.DOTALL
            )
            results = []
            for url_path, title in articles[:limit]:
                clean_title = re.sub(r'<[^>]+>', '', title).strip()
                if query.lower() in clean_title.lower():
                    results.append({"title": clean_title, "url": f"{INTIGRITI_BLOG}{url_path}"})
            return json.dumps(results if results else [{"note": f"No articles found matching '{query}'"}], indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


def get_challenge() -> str:
    """Get current Intigriti XSS challenge details."""
    try:
        req = urllib.request.Request(INTIGRITI_CHALLENGE, headers={"User-Agent": "MCP/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            title_match = re.search(r'<title>(.*?)</title>', html)
            current = {"challenge_url": INTIGRITI_CHALLENGE}
            if title_match:
                current["title"] = title_match.group(1)
            return json.dumps(current, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


def search_blog(query: str, limit: int = 5) -> str:
    """Search Intigriti blog for methodology/tutorial articles."""
    try:
        search_url = f"{INTIGRITI_BLOG}/?s={urllib.request.quote(query)}"
        req = urllib.request.Request(search_url, headers={"User-Agent": "MCP/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            articles = re.findall(
                r'<h[2-3][^>]*>.*?<a[^>]*href=["\']([^"\']*)["\'][^>]*>(.*?)</a>.*?</h[2-3]>',
                html, re.DOTALL
            )
            results = []
            for url_path, title in articles[:limit]:
                clean_title = re.sub(r'<[^>]+>', '', title).strip()
                results.append({"title": clean_title, "url": url_path if url_path.startswith("http") else f"{INTIGRITI_BLOG}{url_path}"})
            return json.dumps(results if results else [{"note": "No articles found"}], indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 server.py <command> [args]", file=sys.stderr)
        sys.exit(1)

    if sys.argv[1] == "research":
        query = sys.argv[2] if len(sys.argv) > 2 else ""
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 5
        print(search_research(query, limit))
    elif sys.argv[1] == "challenge":
        print(get_challenge())
    elif sys.argv[1] == "blog":
        query = sys.argv[2] if len(sys.argv) > 2 else ""
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 5
        print(search_blog(query, limit))
    else:
        print(json.dumps({"error": f"Unknown command: {sys.argv[1]}"}))
