#!/usr/bin/env python3
"""
kev_matrix.py — Maintained CISA KEV / edge-appliance CVE matrix mapped to UBH skills.

The CISA Known Exploited Vulnerabilities (KEV) catalog is the authoritative list of
CVEs observed being exploited in the wild. A large and growing share of those entries
are edge appliances and identity providers — exactly the perimeter that UBH's
enterprise-vpn-attack / okta-attack / m365-entra-attack / vmware-vcenter-attack skills
target. This tool loads the KEV catalog (from a local JSON snapshot, or optionally a
live fetch), narrows it to the edge/identity-relevant subset, routes each CVE to the
UBH skill that hunts that surface, and renders a maintained Markdown matrix.

Design notes:
  * No network at import time or in tests. `requests` is imported lazily inside
    fetch_kev() and only reached when `--fetch` is explicitly passed.
  * All logic lives in importable top-level functions (load_kev, fetch_kev,
    filter_edge, map_cve_to_skills, build_matrix, render_markdown).
  * Runs fully offline against the bundled fixture (BUNDLED_KEV_SAMPLE).

KEV entry schema (fields read from each catalog `vulnerabilities[]` entry):
    cveID                       str   e.g. "CVE-2023-4966"          (required)
    vendorProject               str   e.g. "Citrix"                 (used for routing)
    product                     str   e.g. "NetScaler ADC ..."      (used for routing)
    vulnerabilityName           str   human-readable title
    shortDescription            str   one-line description
    dateAdded                   str   "YYYY-MM-DD" added to KEV
    dueDate                     str   "YYYY-MM-DD" remediation due
    requiredAction              str   CISA remediation guidance
    knownRansomwareCampaignUse  str   "Known" | "Unknown"
    cwes                        list[str]  e.g. ["CWE-77"]
    notes                       str   reference URLs
Only cveID is strictly required; every other field is optional and defaulted to "".

Usage:
  # Offline, against the bundled sample fixture:
  python3 tools/kev_matrix.py --kev tools/fixtures/kev_sample.json --out docs/KEV-MATRIX.md

  # Refresh from CISA first, then build (network only happens with --fetch):
  python3 tools/kev_matrix.py --fetch --kev /tmp/kev.json --out docs/KEV-MATRIX.md

  # All KEV entries, not just the edge/identity subset:
  python3 tools/kev_matrix.py --kev tools/fixtures/kev_sample.json --all --json
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import json
import os
import sys

# Repo layout: this file lives in <repo>/tools/. The bundled offline fixture sits in
# <repo>/tools/fixtures/, and the default rendered matrix lands in <repo>/docs/.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))

# BUNDLED sample fixture — a 12-entry KEV snapshot so the tool runs fully offline.
# Pass this to --kev when you have no live snapshot:
#   python3 tools/kev_matrix.py --kev tools/fixtures/kev_sample.json --out docs/KEV-MATRIX.md
BUNDLED_KEV_SAMPLE = os.path.join(_TOOLS_DIR, "fixtures", "kev_sample.json")

# Official CISA KEV feed. Only ever requested when --fetch is passed (lazy import).
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# Default destination for the rendered matrix.
DEFAULT_OUT = os.path.join(_REPO, "docs", "KEV-MATRIX.md")

# Edge-appliance / identity-provider vendors. KEV entries from these vendors are the
# perimeter UBH's enterprise skills are built to hunt. Lowercased substring match
# against vendorProject (and product, for vendors that ship under product names).
EDGE_VENDORS = [
    "Fortinet",
    "Citrix",
    "Ivanti",
    "Pulse Secure",
    "Palo Alto",
    "Cisco",
    "VMware",
    "Microsoft",
    "Okta",
    "Atlassian",
    "F5",
    "SonicWall",
    "Zoho",
    "Zyxel",
    "Juniper",
    "Barracuda",
    "Progress",  # MOVEit / WS_FTP
    "Check Point",
    "Array Networks",
    "GitLab",
    "Jenkins",
]

# Product/keyword signals that mark an entry as edge/identity even when the vendor
# alone is ambiguous (e.g. Microsoft ships everything; only the identity/edge bits
# belong in this matrix). Lowercased substring match against vendor + product + name.
_EDGE_PRODUCT_SIGNALS = [
    "vpn",
    "ssl-vpn",
    "globalprotect",
    "netscaler",
    "connect secure",
    "policy secure",
    "pulse",
    "gateway",
    "firewall",
    "fortios",
    "fortiproxy",
    "pan-os",
    "big-ip",
    "adc",
    "appliance",
    "vcenter",
    "esxi",
    "vsphere",
    "exchange",
    "outlook",
    "sharepoint",
    "active directory",
    "entra",
    "azure ad",
    "adfs",
    "manageengine",
    "moveit",
    "ws_ftp",
    "gitlab",
    "jenkins",
    "confluence",
    "bitbucket",
    "okta",
    "saml",
    "sso",
    "ios xe",
    "router",
    "edge",
]

# Routing rules, evaluated top-to-bottom. The first rule whose predicate matches the
# (vendor, product, name) haystack wins and contributes its skill. A CVE can match
# more than one rule (e.g. a Microsoft Exchange RCE → m365-entra-attack + hunt-rce),
# so map_cve_to_skills accumulates all matches and de-dupes, preserving rule order.
#
# Each rule: (skill_name, [trigger substrings]). Substrings are matched lowercase
# against vendor + " " + product + " " + vulnerabilityName + " " + shortDescription.
_SKILL_RULES: list[tuple[str, list[str]]] = [
    # --- Edge VPN / network appliances → enterprise-vpn-attack ---
    (
        "enterprise-vpn-attack",
        [
            "vpn", "ssl-vpn", "globalprotect", "netscaler", "connect secure",
            "policy secure", "pulse", "gateway", "firewall", "fortios",
            "fortiproxy", "pan-os", "big-ip", "sonicwall", "sma100", "adc",
            "ios xe", "zyxel", "juniper", "barracuda", "appliance",
        ],
    ),
    # --- Microsoft identity / collaboration → m365-entra-attack ---
    (
        "m365-entra-attack",
        [
            "entra", "azure ad", "active directory", "adfs", "exchange",
            "outlook", "office 365", "m365", "windows", "netlogon",
        ],
    ),
    # SharePoint has its own dedicated hunt skill.
    ("hunt-sharepoint", ["sharepoint"]),
    # --- Identity providers ---
    ("okta-attack", ["okta"]),
    # --- VMware virtualization fabric → vmware-vcenter-attack ---
    ("vmware-vcenter-attack", ["vcenter", "esxi", "vsphere"]),
    # --- CI/CD & dev platforms → hunt-cicd ---
    (
        "hunt-cicd",
        [
            "gitlab", "jenkins", "github actions", "bitbucket", "teamcity",
            "bamboo", "argo cd", "ci/cd", "pipeline",
        ],
    ),
    # --- Web frameworks / app servers → per-class hunt-* skills ---
    ("hunt-springboot", ["spring", "spring4shell", "tanzu"]),
    ("hunt-laravel", ["laravel"]),
    ("hunt-nextjs", ["next.js", "nextjs"]),
    ("hunt-nodejs", ["node.js", "nodejs"]),
    ("hunt-aspnet", ["asp.net", "aspnet", ".net framework"]),
    # --- SSO/SAML auth surfaces (ManageEngine etc.) → hunt-saml ---
    ("hunt-saml", ["saml", "single sign-on", " sso", "santuario"]),
    # --- Generic exploitation primitives, routed by description ---
    ("hunt-rce", ["remote code execution", "command injection", "code execution"]),
    ("hunt-sqli", ["sql injection"]),
    ("hunt-deserialization", ["deserialization", "deserialize"]),
    ("hunt-lfi", ["path traversal", "directory traversal", "file read", "lfi"]),
    ("hunt-ssrf", ["server-side request forgery", "ssrf"]),
    ("hunt-auth-bypass", ["authentication bypass", "missing authentication", "auth bypass"]),
    ("hunt-xxe", ["xml external entity", "xxe"]),
]

# Fallback skill when no rule matches — a generic CVE-tag nuclei sweep.
FALLBACK_SKILL = "scan-cves"


def _entry_haystack(entry: dict) -> str:
    """Build the lowercased text blob a CVE entry is matched against."""
    parts = [
        str(entry.get("vendorProject", "")),
        str(entry.get("product", "")),
        str(entry.get("vulnerabilityName", "")),
        str(entry.get("shortDescription", "")),
    ]
    return " ".join(parts).lower()


def load_kev(path: str) -> list[dict]:
    """Load a local CISA KEV JSON snapshot and return its vulnerability entries.

    Accepts either the official catalog envelope ({"vulnerabilities": [...]}) or a
    bare JSON array of entries. Entries missing a `cveID` are dropped.

    Args:
        path: Path to a KEV JSON file (e.g. BUNDLED_KEV_SAMPLE).

    Returns:
        A list of entry dicts (see module docstring for the schema).

    Raises:
        OSError: file cannot be read.
        ValueError: contents are not valid JSON or not a recognized KEV shape.
    """
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: not valid JSON: {exc}") from exc

    if isinstance(data, dict):
        entries = data.get("vulnerabilities", [])
    elif isinstance(data, list):
        entries = data
    else:
        raise ValueError(f"{path}: unrecognized KEV shape (expected object or array)")

    if not isinstance(entries, list):
        raise ValueError(f"{path}: 'vulnerabilities' is not a list")

    return [e for e in entries if isinstance(e, dict) and e.get("cveID")]


def fetch_kev(url: str = KEV_FEED_URL, timeout: int = 30, out_path: str | None = None) -> list[dict]:
    """Fetch the live CISA KEV catalog over HTTP. NEVER called at import or in tests.

    `requests` is imported lazily here so the module imports cleanly without it and
    so no network is reachable unless a caller explicitly invokes this function
    (the CLI only does so when --fetch is passed).

    Args:
        url: KEV feed URL (defaults to the official CISA feed).
        timeout: Per-request timeout in seconds.
        out_path: If set, the raw JSON is also written here as a snapshot.

    Returns:
        The parsed vulnerability entries (same shape as load_kev).

    Raises:
        RuntimeError: requests is not installed, or the fetch/parse fails.
    """
    try:
        import requests  # lazy: only when --fetch is used
    except ImportError as exc:  # pragma: no cover - exercised only with --fetch
        raise RuntimeError(
            "fetch_kev requires the 'requests' package (pip install requests)"
        ) from exc

    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # pragma: no cover - network path
        raise RuntimeError(f"failed to fetch KEV feed from {url}: {exc}") from exc

    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    entries = data.get("vulnerabilities", []) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise RuntimeError(f"KEV feed at {url} had an unexpected shape")
    return [e for e in entries if isinstance(e, dict) and e.get("cveID")]


def is_edge_entry(entry: dict) -> bool:
    """True if a KEV entry is an edge-appliance / identity-provider target.

    An entry qualifies when its vendor is in EDGE_VENDORS *and* either the vendor is
    an unambiguous appliance/identity vendor, or the text carries an edge product
    signal. Vendors that ship broad portfolios (Microsoft, VMware, Cisco, Atlassian)
    must also hit a product signal so we don't sweep in unrelated desktop CVEs.
    """
    haystack = _entry_haystack(entry)
    vendor = str(entry.get("vendorProject", "")).lower()

    vendor_hit = any(v.lower() in vendor or v.lower() in haystack for v in EDGE_VENDORS)
    if not vendor_hit:
        return False

    # Broad-portfolio vendors need a product signal to qualify; pure appliance /
    # identity vendors qualify on the vendor match alone.
    broad = ("microsoft", "vmware", "cisco", "atlassian", "progress", "apache")
    if any(b in vendor for b in broad):
        return any(sig in haystack for sig in _EDGE_PRODUCT_SIGNALS)

    return True


def filter_edge(entries: list[dict]) -> list[dict]:
    """Narrow KEV entries to the edge-appliance / identity-relevant subset."""
    return [e for e in entries if is_edge_entry(e)]


def map_cve_to_skills(entry: dict) -> list[str]:
    """Route a single KEV entry to the UBH skill(s) that hunt its surface.

    Evaluates _SKILL_RULES in order; every matching rule contributes its skill, with
    duplicates removed and rule order preserved. If no rule matches, returns the
    generic FALLBACK_SKILL ("scan-cves").

    Returns:
        A non-empty, de-duplicated, order-preserving list of skill names.
    """
    haystack = _entry_haystack(entry)
    skills: list[str] = []
    for skill, triggers in _SKILL_RULES:
        if any(trigger in haystack for trigger in triggers):
            if skill not in skills:
                skills.append(skill)
    if not skills:
        skills.append(FALLBACK_SKILL)
    return skills


def _skill_exists(skill: str, skills_dir: str) -> bool:
    """True if <skills_dir>/<skill>/ is a real skill directory."""
    return os.path.isdir(os.path.join(skills_dir, skill))


def build_matrix(entries: list[dict], skills_dir: str | None = None) -> list[dict]:
    """Build the KEV→skill matrix rows from a list of KEV entries.

    Args:
        entries: KEV entries (typically the output of filter_edge()).
        skills_dir: If provided, each routed skill is annotated with whether the
            skill directory actually exists under it (so the matrix can flag
            skills that still need authoring). Defaults to <repo>/skills when the
            directory is present; otherwise skill existence is reported as None.

    Returns:
        A list of row dicts sorted by dateAdded (newest first), then cveID. Each row:
            cve            -> str
            vendor         -> str
            product        -> str
            name           -> str
            description    -> str
            date_added     -> str
            due_date       -> str
            ransomware     -> str   ("Known" | "Unknown" | "")
            skills         -> list[str]
            skills_present -> list[bool] | None  (aligned with skills; None if no dir)
    """
    resolved_dir = skills_dir
    if resolved_dir is None:
        default_dir = os.path.join(_REPO, "skills")
        resolved_dir = default_dir if os.path.isdir(default_dir) else None

    rows: list[dict] = []
    for entry in entries:
        skills = map_cve_to_skills(entry)
        if resolved_dir is not None:
            present: list[bool] | None = [_skill_exists(s, resolved_dir) for s in skills]
        else:
            present = None
        rows.append(
            {
                "cve": str(entry.get("cveID", "")),
                "vendor": str(entry.get("vendorProject", "")),
                "product": str(entry.get("product", "")),
                "name": str(entry.get("vulnerabilityName", "")),
                "description": str(entry.get("shortDescription", "")),
                "date_added": str(entry.get("dateAdded", "")),
                "due_date": str(entry.get("dueDate", "")),
                "ransomware": str(entry.get("knownRansomwareCampaignUse", "")),
                "skills": skills,
                "skills_present": present,
            }
        )

    # Newest-added first; CVE id as a stable tiebreaker.
    rows.sort(key=lambda r: (r["date_added"], r["cve"]), reverse=True)
    return rows


def _md_escape(text: str) -> str:
    """Escape pipe characters so cell content doesn't break the Markdown table."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def render_markdown(matrix: list[dict]) -> str:
    """Render the KEV→skill matrix as a Markdown document.

    Returns a complete document (heading + provenance note + table). The body is a
    single table; each routed skill is rendered as a code span, with a `(missing)`
    tag appended when skills_present marks it absent.
    """
    lines: list[str] = []
    lines.append("# CISA KEV / Edge-Appliance CVE → UBH Skill Matrix")
    lines.append("")
    lines.append(
        "Auto-generated by `tools/kev_matrix.py`. Maps Known Exploited "
        "Vulnerabilities (edge-appliance & identity subset) to the UBH skill that "
        "hunts each surface. Regenerate after refreshing the KEV snapshot."
    )
    lines.append("")
    lines.append(f"**Entries:** {len(matrix)}")
    lines.append("")

    # Skill coverage rollup.
    counts: dict[str, int] = {}
    for row in matrix:
        for skill in row["skills"]:
            counts[skill] = counts.get(skill, 0) + 1
    if counts:
        lines.append("## Skill coverage")
        lines.append("")
        lines.append("| Skill | CVEs |")
        lines.append("|---|---|")
        for skill, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"| `{skill}` | {count} |")
        lines.append("")

    lines.append("## Matrix")
    lines.append("")
    lines.append("| CVE | Vendor | Product | Ransomware | Added | UBH Skill(s) |")
    lines.append("|---|---|---|---|---|---|")
    for row in matrix:
        present = row.get("skills_present")
        rendered_skills = []
        for idx, skill in enumerate(row["skills"]):
            tag = ""
            if present is not None and idx < len(present) and not present[idx]:
                tag = " (missing)"
            rendered_skills.append(f"`{skill}`{tag}")
        skills_cell = ", ".join(rendered_skills)
        lines.append(
            "| {cve} | {vendor} | {product} | {ransomware} | {added} | {skills} |".format(
                cve=_md_escape(row["cve"]),
                vendor=_md_escape(row["vendor"]),
                product=_md_escape(row["product"]),
                ransomware=_md_escape(row["ransomware"]) or "—",
                added=_md_escape(row["date_added"]) or "—",
                skills=skills_cell,
            )
        )
    lines.append("")
    return "\n".join(lines)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the CISA KEV / edge-appliance CVE → UBH skill matrix. "
            "Runs offline against the bundled sample at tools/fixtures/kev_sample.json."
        )
    )
    parser.add_argument(
        "--kev",
        default=BUNDLED_KEV_SAMPLE,
        help=(
            "Path to a local KEV JSON snapshot. With --fetch this is the write "
            "destination for the freshly downloaded feed. "
            "Default: bundled sample (tools/fixtures/kev_sample.json)."
        ),
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help=(
            "Download the live CISA KEV feed first (requires 'requests'), save it to "
            "--kev, then build. Only this flag enables any network access."
        ),
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help="Output path for the rendered Markdown matrix (default: docs/KEV-MATRIX.md).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Include every KEV entry, not just the edge/identity subset.",
    )
    parser.add_argument(
        "--skills-dir",
        default=None,
        help="Override the skills directory used to flag missing skills (default: <repo>/skills).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the matrix as JSON to stdout instead of writing Markdown.",
    )
    args = parser.parse_args(argv)

    if args.fetch:
        try:
            entries = fetch_kev(out_path=args.kev)
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
    else:
        try:
            entries = load_kev(args.kev)
        except (OSError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    subset = entries if args.all else filter_edge(entries)
    matrix = build_matrix(subset, skills_dir=args.skills_dir)

    if args.json:
        print(json.dumps(matrix, indent=2, sort_keys=True))
        return 0

    markdown = render_markdown(matrix)
    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(markdown)
        if not markdown.endswith("\n"):
            fh.write("\n")

    print(
        f"Wrote {len(matrix)} KEV rows "
        f"({'all entries' if args.all else 'edge/identity subset'}) -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
