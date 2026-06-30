#!/usr/bin/env python3
"""
dedup_findings.py — Deterministic findings dedup / cluster engine for batch triage.

Built for large imported issue sets (e.g. a 600+ issue export from a DevSecOps
Jira board): collapses near-identical findings into clusters keyed by
(vuln_class, normalized_endpoint, param_names) and flags items that match an
already-submitted / already-reported set so you never re-file a known bug.

This is a CODE check, not LLM judgment — same philosophy as tools/scope_checker.py.
The key is fully deterministic so the same input always produces the same clusters.

A finding is a dict/JSON:
    {
        "id":        "JIRA-123",            # required, any hashable scalar
        "vuln_class": "idor",               # required (aka "bug_class")
        "url":       "https://api.x.com/v1/users/123/orders?sort=asc",
        "endpoint":  "/v1/users/123/orders" # alt to "url"
        "param":     "id",                  # optional; str or list[str]
        "title":     "IDOR on order lookup" # optional (used for representative only)
    }

Endpoint normalization (normalize_endpoint):
    - lowercase host, drop scheme and query VALUES (param NAMES kept separately)
    - collapse volatile path segments to placeholders:
        numeric        -> {n}
        UUID           -> {uuid}
        long hex/b64-ish -> {id}
    e.g. https://api.X.com/v1/users/123/orders/9f1c8e4a-...-aa
         -> api.x.com/v1/users/{n}/orders/{uuid}

CLI:
    python3 tools/dedup_findings.py --findings f.json
    python3 tools/dedup_findings.py --findings f.json --against submitted.json --out clusters.json
    python3 tools/dedup_findings.py --findings f.json --json

Importable functions (tests import these directly):
    normalize_endpoint(url_or_path: str) -> str
    finding_key(finding: dict) -> tuple
    cluster_findings(findings: list) -> dict
    dedup_against(findings: list, submitted: list) -> dict
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl

# ─── Color codes (match tools/validate.py / tools/search_findings.py) ───────────
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BLUE = "\033[94m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# ─── Segment-classification patterns (anchored, case-insensitive) ───────────────
_RE_NUMERIC = re.compile(r"^\d+$")
_RE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
# Long hex blob (e.g. sha/object ids) — >= 12 hex chars, no separators.
_RE_LONG_HEX = re.compile(r"^[0-9a-f]{12,}$", re.IGNORECASE)
# base64 / base64url-ish opaque token — >= 16 chars from the b64 alphabet,
# must contain at least one digit so we don't flatten ordinary long words
# like "subscriptions" or "notifications".
_RE_BASE64ISH = re.compile(r"^[A-Za-z0-9_\-]{16,}={0,2}$")
_RE_HAS_DIGIT = re.compile(r"\d")
# Mixed identifier with an embedded numeric run of 3+ digits (e.g. order_000123,
# user12345abc) — treat as a volatile id, not a stable route segment.
_RE_EMBEDDED_NUM = re.compile(r"\d{3,}")


def _classify_segment(segment: str) -> str:
    """Map a single path segment to itself or to a placeholder.

    Order matters: most specific (UUID) first, then numeric, then opaque ids.
    Returns the original (lowercased) segment when it looks like a stable route.
    """
    if not segment:
        return segment

    if _RE_NUMERIC.match(segment):
        return "{n}"
    if _RE_UUID.match(segment):
        return "{uuid}"
    if _RE_LONG_HEX.match(segment):
        return "{id}"
    if _RE_BASE64ISH.match(segment) and _RE_HAS_DIGIT.search(segment):
        return "{id}"
    # Mixed alnum token carrying a long digit run (e.g. ORD000123) is volatile.
    if _RE_EMBEDDED_NUM.search(segment) and not segment.replace("-", "").replace("_", "").isdigit():
        # already handled pure-numeric above; this catches alnum ids
        return "{id}"

    return segment.lower()


def normalize_endpoint(url_or_path: str) -> str:
    """Normalize a URL or path into a stable, comparable endpoint signature.

    - Lowercases the host.
    - Drops scheme and query VALUES (param names are extracted separately by
      finding_key; this string keeps only the path shape + host).
    - Collapses volatile path segments to placeholders:
        numeric           -> {n}
        UUID              -> {uuid}
        long hex / b64-ish -> {id}

    Examples:
        >>> normalize_endpoint("https://api.X.com/v1/users/123/orders/9f1c8e4a-1b2c-3d4e-5f60-708192a3b4c5")
        'api.x.com/v1/users/{n}/orders/{uuid}'
        >>> normalize_endpoint("/V2/Cart/Items/")
        '/v2/cart/items'

    Returns "" for empty / non-string input.
    """
    if not url_or_path or not isinstance(url_or_path, str):
        return ""

    raw = url_or_path.strip()
    if not raw:
        return ""

    # urlsplit needs a scheme to populate netloc; add a throwaway one if the
    # value clearly has a host but no scheme (e.g. "api.x.com/v1/...").
    had_authority = "://" in raw
    to_parse = raw if had_authority else raw
    parts = urlsplit(to_parse if had_authority else f"//{raw}" if _looks_like_authority(raw) else raw)

    host = (parts.netloc or "").lower()
    # Strip userinfo and port from host so api.x.com:443 == api.x.com.
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("["):  # IPv6 literal — keep bracketed form, drop port
        host = host.split("]", 1)[0] + "]"
    elif ":" in host:
        host = host.split(":", 1)[0]

    path = parts.path or ""

    # Collapse duplicate slashes, then split.
    segments = [s for s in path.split("/")]
    leading_slash = path.startswith("/")
    normalized_segments = [_classify_segment(s) for s in segments if s != ""]

    norm_path = "/".join(normalized_segments)
    if leading_slash and not host:
        norm_path = "/" + norm_path
    # Drop a single trailing slash artifact (already removed by filtering "").

    if host:
        return host + (("/" + norm_path) if norm_path and not norm_path.startswith("/") else norm_path)
    return norm_path


def _looks_like_authority(raw: str) -> bool:
    """Heuristic: does a scheme-less string start with a host (not a path)?

    "api.x.com/v1" -> True ; "/v1/users/1" -> False ; "v1/users" -> False
    A leading token with a dot and no leading slash is treated as a host.
    """
    if raw.startswith("/"):
        return False
    first = raw.split("/", 1)[0]
    return "." in first and " " not in first


def _normalize_vuln_class(value: object) -> str:
    """Normalize a vuln/bug class label: lowercase, trim, collapse separators.

    'SQL Injection' / 'sql_injection' / 'SQLi ' all need to be comparable, but
    we keep this conservative — only case, surrounding whitespace, and
    space/underscore/hyphen unification. We do NOT alias synonyms (that would be
    judgment, not a deterministic code check).
    """
    if value is None:
        return ""
    text = str(value).strip().lower()
    text = re.sub(r"[\s_\-]+", "_", text)
    return text


def _param_names(finding: dict) -> list[str]:
    """Extract sorted, de-duplicated param NAMES from a finding.

    Sources, merged:
      - query-string param names parsed from finding['url']
      - explicit finding['param'] (str) or finding['params'] (str | list)
    """
    names: set[str] = set()

    url = finding.get("url")
    if isinstance(url, str) and "?" in url:
        # urlsplit handles scheme-less values; ensure '?' survives parsing.
        query = urlsplit(url if "://" in url else f"//{url}").query
        for name, _value in parse_qsl(query, keep_blank_values=True):
            if name:
                names.add(name.strip().lower())

    for field in ("param", "params"):
        val = finding.get(field)
        if isinstance(val, str):
            for piece in re.split(r"[,\s]+", val):
                piece = piece.strip().lower()
                if piece:
                    names.add(piece)
        elif isinstance(val, (list, tuple, set)):
            for piece in val:
                if piece is None:
                    continue
                piece = str(piece).strip().lower()
                if piece:
                    names.add(piece)

    return sorted(names)


def _endpoint_source(finding: dict) -> str:
    """Pick the endpoint string from a finding: prefer 'url', fall back to 'endpoint'.

    Matches the dashboard findings schema which uses the 'endpoint' column.
    """
    for field in ("url", "endpoint"):
        val = finding.get(field)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def finding_key(finding: dict) -> tuple:
    """Compute the deterministic dedup key for a finding.

    Returns:
        (vuln_class_normalized, normalized_endpoint, (param_name, ...))

    The tuple is hashable and order-stable, so two findings with the same vuln
    class, the same endpoint shape, and the same set of parameters collapse to
    one cluster regardless of concrete ids, host casing, scheme, or query VALUES.
    """
    if not isinstance(finding, dict):
        raise TypeError(f"finding must be a dict, got {type(finding).__name__}")

    vuln_class = _normalize_vuln_class(
        finding.get("vuln_class", finding.get("bug_class"))
    )
    endpoint = normalize_endpoint(_endpoint_source(finding))
    params = tuple(_param_names(finding))
    return (vuln_class, endpoint, params)


def _finding_id(finding: dict, index: int) -> object:
    """Return the finding's id, or a synthetic index-based id if absent."""
    fid = finding.get("id")
    if fid is None:
        return f"_idx_{index}"
    return fid


def _representative(members: list[dict]) -> object:
    """Choose a stable representative id for a cluster.

    Deterministic: the lexicographically-smallest string form of the member ids,
    so re-running on the same set always picks the same representative.
    """
    ids = [_finding_id(f, i) for i, f in members]
    return min(ids, key=lambda x: str(x))


def cluster_findings(findings: list) -> dict:
    """Group findings into clusters by finding_key.

    Args:
        findings: list of finding dicts.

    Returns:
        {
          "clusters": [
              {
                "key": [vuln_class, endpoint, [param, ...]],
                "ids": [id, ...],          # input order preserved within cluster
                "representative": id,       # stable pick
                "count": int,
                "title": str | None         # representative's title, if any
              }, ...
          ],
          "unique_count": int,   # number of clusters
          "total": int,          # number of input findings
          "duplicate_count": int # total - unique_count
        }
    Clusters are ordered by descending size, then by key for determinism.
    """
    if not isinstance(findings, list):
        raise TypeError(f"findings must be a list, got {type(findings).__name__}")

    groups: dict[tuple, list] = {}
    titles: dict[object, object] = {}

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise TypeError(
                f"finding at index {index} must be a dict, got {type(finding).__name__}"
            )
        key = finding_key(finding)
        groups.setdefault(key, []).append((index, finding))
        fid = _finding_id(finding, index)
        if fid not in titles and isinstance(finding.get("title"), str):
            titles[fid] = finding["title"]

    clusters = []
    for key, members in groups.items():
        ids = [_finding_id(f, i) for i, f in members]
        rep = _representative(members)
        clusters.append(
            {
                "key": [key[0], key[1], list(key[2])],
                "ids": ids,
                "representative": rep,
                "count": len(ids),
                "title": titles.get(rep),
            }
        )

    # Deterministic ordering: biggest clusters first, ties broken by key string.
    clusters.sort(key=lambda c: (-c["count"], str(c["key"])))

    return {
        "clusters": clusters,
        "unique_count": len(clusters),
        "total": len(findings),
        "duplicate_count": len(findings) - len(clusters),
    }


def dedup_against(findings: list, submitted: list) -> dict:
    """Flag each finding as new or duplicate-of-an-already-submitted finding.

    A finding is a duplicate when its finding_key matches the key of any item in
    'submitted' (the already-reported / already-filed set). When several
    submitted items share a key, the lexicographically-smallest submitted id is
    reported as the match for stability.

    Args:
        findings:  candidate findings to triage.
        submitted: already-reported findings (same finding schema).

    Returns:
        {
          "new": [id, ...],                       # not seen in submitted
          "duplicate_of_submitted": [
              {"id": id, "matched_submitted_id": id, "key": [...]}, ...
          ],
          "new_count": int,
          "duplicate_count": int,
          "total": int
        }
    """
    if not isinstance(findings, list):
        raise TypeError(f"findings must be a list, got {type(findings).__name__}")
    if not isinstance(submitted, list):
        raise TypeError(f"submitted must be a list, got {type(submitted).__name__}")

    # Build key -> smallest submitted id (stable).
    submitted_index: dict[tuple, object] = {}
    for index, sub in enumerate(submitted):
        if not isinstance(sub, dict):
            raise TypeError(
                f"submitted item at index {index} must be a dict, "
                f"got {type(sub).__name__}"
            )
        key = finding_key(sub)
        sid = _finding_id(sub, index)
        existing = submitted_index.get(key)
        if existing is None or str(sid) < str(existing):
            submitted_index[key] = sid

    new_ids: list = []
    duplicates: list = []

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise TypeError(
                f"finding at index {index} must be a dict, got {type(finding).__name__}"
            )
        key = finding_key(finding)
        fid = _finding_id(finding, index)
        matched = submitted_index.get(key)
        if matched is not None:
            duplicates.append(
                {
                    "id": fid,
                    "matched_submitted_id": matched,
                    "key": [key[0], key[1], list(key[2])],
                }
            )
        else:
            new_ids.append(fid)

    return {
        "new": new_ids,
        "duplicate_of_submitted": duplicates,
        "new_count": len(new_ids),
        "duplicate_count": len(duplicates),
        "total": len(findings),
    }


# ─── CLI ────────────────────────────────────────────────────────────────────────
def _load_json_list(path: str) -> list:
    """Load a JSON file that holds a list of findings.

    Accepts either a top-level list, or an object with a 'findings' key
    (so exports wrapped as {"findings": [...]} also work).
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data["findings"]
    if isinstance(data, list):
        return data
    raise ValueError(
        f"{path}: expected a JSON list of findings or an object with a "
        f"'findings' list, got {type(data).__name__}"
    )


def _print_summary(cluster_result: dict, dedup_result: dict | None) -> None:
    """Print a human-readable triage summary to stdout."""
    total = cluster_result["total"]
    unique = cluster_result["unique_count"]
    dupes = cluster_result["duplicate_count"]

    print(f"{BOLD}{BLUE}═══ Findings Dedup Summary ═══{RESET}")
    print(
        f"  {total} findings -> {BOLD}{GREEN}{unique}{RESET} unique clusters "
        f"({DIM}{dupes} collapsed as in-batch duplicates{RESET})"
    )

    if dedup_result is not None:
        k = dedup_result["duplicate_count"]
        n = dedup_result["new_count"]
        print(
            f"  vs submitted set: {BOLD}{GREEN}{n}{RESET} new, "
            f"{BOLD}{YELLOW}{k}{RESET} already-reported (dup-of-submitted)"
        )

    # Show the largest clusters so triage can eyeball the heavy hitters.
    top = [c for c in cluster_result["clusters"] if c["count"] > 1][:10]
    if top:
        print(f"\n{BOLD}Largest in-batch clusters:{RESET}")
        for c in top:
            vuln_class, endpoint, params = c["key"]
            param_str = f" [{', '.join(params)}]" if params else ""
            label = c.get("title") or vuln_class or "(unclassified)"
            print(
                f"  {YELLOW}x{c['count']:<3}{RESET} {CYAN}{vuln_class or '?'}{RESET} "
                f"{endpoint or '(no endpoint)'}{param_str}  "
                f"{DIM}rep={c['representative']} :: {label}{RESET}"
            )

    if dedup_result is not None and dedup_result["duplicate_of_submitted"]:
        print(f"\n{BOLD}Already reported (skip these):{RESET}")
        for d in dedup_result["duplicate_of_submitted"][:20]:
            print(
                f"  {YELLOW}{d['id']}{RESET} matches submitted "
                f"{BOLD}{d['matched_submitted_id']}{RESET}"
            )
        extra = len(dedup_result["duplicate_of_submitted"]) - 20
        if extra > 0:
            print(f"  {DIM}... and {extra} more{RESET}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Deterministically dedup / cluster a batch of security findings and "
            "flag items that match an already-submitted set."
        )
    )
    parser.add_argument(
        "--findings",
        required=True,
        help="Path to JSON file: a list of findings (or {'findings': [...]}).",
    )
    parser.add_argument(
        "--against",
        help="Path to JSON file of already-submitted findings to dedup against.",
    )
    parser.add_argument(
        "--out",
        help="Write the full cluster/dedup result as JSON to this path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the machine-readable JSON result to stdout instead of a summary.",
    )
    args = parser.parse_args(argv)

    try:
        findings = _load_json_list(args.findings)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f"could not load --findings: {exc}")

    submitted = None
    if args.against:
        try:
            submitted = _load_json_list(args.against)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"could not load --against: {exc}")

    try:
        cluster_result = cluster_findings(findings)
        dedup_result = dedup_against(findings, submitted) if submitted is not None else None
    except TypeError as exc:
        parser.error(str(exc))

    output: dict[str, object] = {"clusters": cluster_result}
    if dedup_result is not None:
        output["dedup_against_submitted"] = dedup_result

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=2, sort_keys=True, default=str)
                f.write("\n")
        except OSError as exc:
            parser.error(f"could not write --out: {exc}")

    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True, default=str))
    else:
        _print_summary(cluster_result, dedup_result)
        if args.out:
            print(f"\n{DIM}Wrote full result -> {args.out}{RESET}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
