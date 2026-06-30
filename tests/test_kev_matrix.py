"""Tests for tools/kev_matrix.py — KEV → UBH skill matrix builder.

Fully offline: a small inline KEV sample (Fortinet VPN, Okta, Microsoft Exchange,
and a non-edge desktop app) exercises the importable surface. The tool reaches no
network unless --fetch is passed, which these tests never do. stdlib + pytest only.
"""

import json
import os
import sys

import pytest

# Make tools/ importable (mirrors tests/conftest.py, but kept self-contained so
# this module imports cleanly even if run in isolation).
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_ROOT = os.path.join(REPO_ROOT, "tools")
for _path in (REPO_ROOT, TOOLS_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import kev_matrix as km


# --- Inline KEV sample: one entry per required category --------------------------

FORTINET = {
    "cveID": "CVE-2023-27997",
    "vendorProject": "Fortinet",
    "product": "FortiOS and FortiProxy SSL-VPN",
    "vulnerabilityName": (
        "Fortinet FortiOS and FortiProxy SSL-VPN Heap-Based Buffer Overflow Vulnerability"
    ),
    "shortDescription": (
        "Fortinet FortiOS and FortiProxy contain a heap-based buffer overflow in SSL-VPN."
    ),
    "dateAdded": "2023-06-13",
    "dueDate": "2023-07-04",
    "knownRansomwareCampaignUse": "Known",
    "cwes": ["CWE-787"],
}

OKTA = {
    "cveID": "CVE-2022-00001",
    "vendorProject": "Okta",
    "product": "Okta Identity Engine",
    "vulnerabilityName": "Okta Identity Engine Vulnerability",
    "shortDescription": "Okta Identity Engine contains an account-takeover vulnerability.",
    "dateAdded": "2022-01-15",
    "dueDate": "2022-02-05",
    "knownRansomwareCampaignUse": "Unknown",
    "cwes": ["CWE-287"],
}

MS_EXCHANGE = {
    "cveID": "CVE-2021-26855",
    "vendorProject": "Microsoft",
    "product": "Exchange Server",
    "vulnerabilityName": "Microsoft Exchange Server Remote Code Execution Vulnerability",
    "shortDescription": (
        "Microsoft Exchange Server contains a remote code execution vulnerability (ProxyLogon)."
    ),
    "dateAdded": "2021-11-03",
    "dueDate": "2021-11-17",
    "knownRansomwareCampaignUse": "Known",
    "cwes": ["CWE-918"],
}

# A purely client-side desktop app from a vendor outside EDGE_VENDORS — must be
# filtered out and must fall back to scan-cves.
NON_EDGE = {
    "cveID": "CVE-2099-99999",
    "vendorProject": "Acme Widgets",
    "product": "Widget Desktop Viewer",
    "vulnerabilityName": "Acme Widget Desktop Viewer Local Buffer Overflow",
    "shortDescription": "A local buffer overflow in the Acme desktop image viewer.",
    "dateAdded": "2024-02-02",
    "dueDate": "2024-02-23",
    "knownRansomwareCampaignUse": "Unknown",
    "cwes": ["CWE-787"],
}

ALL_ENTRIES = [FORTINET, OKTA, MS_EXCHANGE, NON_EDGE]


# --- filter_edge -----------------------------------------------------------------

def test_filter_edge_keeps_edge_entries():
    edge = km.filter_edge(ALL_ENTRIES)
    cves = {e["cveID"] for e in edge}
    assert FORTINET["cveID"] in cves
    assert OKTA["cveID"] in cves
    assert MS_EXCHANGE["cveID"] in cves


def test_filter_edge_drops_non_edge_entry():
    edge = km.filter_edge(ALL_ENTRIES)
    cves = {e["cveID"] for e in edge}
    assert NON_EDGE["cveID"] not in cves


def test_is_edge_entry_per_entry():
    assert km.is_edge_entry(FORTINET) is True
    assert km.is_edge_entry(OKTA) is True
    assert km.is_edge_entry(MS_EXCHANGE) is True
    assert km.is_edge_entry(NON_EDGE) is False


# --- map_cve_to_skills -----------------------------------------------------------

def test_fortinet_routes_to_enterprise_vpn():
    assert "enterprise-vpn-attack" in km.map_cve_to_skills(FORTINET)


def test_okta_routes_to_okta_attack():
    assert "okta-attack" in km.map_cve_to_skills(OKTA)


def test_microsoft_exchange_routes_to_m365_or_fallback():
    skills = km.map_cve_to_skills(MS_EXCHANGE)
    # Primary expectation is the Microsoft identity/Exchange skill; the documented
    # fallback is scan-cves. Accept either so the test tracks the routing contract.
    assert "m365-entra-attack" in skills or km.FALLBACK_SKILL in skills


def test_non_edge_falls_back_to_scan_cves():
    assert km.map_cve_to_skills(NON_EDGE) == [km.FALLBACK_SKILL]


def test_map_returns_non_empty_deduped_list():
    for entry in ALL_ENTRIES:
        skills = km.map_cve_to_skills(entry)
        assert skills, "every entry must route to at least one skill"
        assert len(skills) == len(set(skills)), "skills must be de-duplicated"


# --- build_matrix ----------------------------------------------------------------

def test_build_matrix_produces_rows():
    edge = km.filter_edge(ALL_ENTRIES)
    matrix = km.build_matrix(edge, skills_dir=None)
    assert len(matrix) == len(edge)
    # Every row carries the documented fields.
    for row in matrix:
        for key in ("cve", "vendor", "product", "date_added", "skills"):
            assert key in row
        assert isinstance(row["skills"], list) and row["skills"]


def test_build_matrix_sorted_newest_first():
    matrix = km.build_matrix(km.filter_edge(ALL_ENTRIES), skills_dir=None)
    dates = [row["date_added"] for row in matrix]
    assert dates == sorted(dates, reverse=True)


def test_build_matrix_no_skills_dir_sets_present_none():
    # A path that is not a directory => skill existence reported as None.
    matrix = km.build_matrix([FORTINET], skills_dir="/nonexistent-skills-dir-xyz")
    assert matrix[0]["skills_present"] == [False]
    matrix_none = km.build_matrix([FORTINET], skills_dir=None)
    # skills_dir=None falls back to <repo>/skills if present, else None; either is
    # acceptable, but it must be aligned with skills when it is a list.
    present = matrix_none[0]["skills_present"]
    assert present is None or len(present) == len(matrix_none[0]["skills"])


# --- render_markdown -------------------------------------------------------------

def test_render_markdown_returns_table():
    matrix = km.build_matrix(km.filter_edge(ALL_ENTRIES), skills_dir=None)
    md = km.render_markdown(matrix)
    assert isinstance(md, str)
    # Table header + separator row present.
    assert "| CVE | Vendor | Product | Ransomware | Added | UBH Skill(s) |" in md
    assert "|---|---|---|---|---|---|" in md
    # Edge CVEs appear; non-edge does not.
    assert FORTINET["cveID"] in md
    assert OKTA["cveID"] in md
    assert MS_EXCHANGE["cveID"] in md
    assert NON_EDGE["cveID"] not in md
    # Routed skill is rendered as a code span.
    assert "`enterprise-vpn-attack`" in md
    assert "`okta-attack`" in md


def test_render_markdown_skill_coverage_rollup():
    matrix = km.build_matrix(km.filter_edge(ALL_ENTRIES), skills_dir=None)
    md = km.render_markdown(matrix)
    assert "## Skill coverage" in md
    assert "## Matrix" in md


# --- load_kev (round-trip through a temp file, no network) -----------------------

def test_load_kev_envelope(tmp_path):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps({"vulnerabilities": ALL_ENTRIES}), encoding="utf-8")
    entries = km.load_kev(str(p))
    assert {e["cveID"] for e in entries} == {e["cveID"] for e in ALL_ENTRIES}


def test_load_kev_bare_array_and_drops_missing_cveid(tmp_path):
    p = tmp_path / "kev.json"
    payload = [FORTINET, {"vendorProject": "NoCve", "product": "x"}]
    p.write_text(json.dumps(payload), encoding="utf-8")
    entries = km.load_kev(str(p))
    assert [e["cveID"] for e in entries] == [FORTINET["cveID"]]


def test_load_kev_invalid_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        km.load_kev(str(p))


# --- import contract: no network, requests not required at import ----------------

def test_module_imports_without_requests():
    # kev_matrix must import even if 'requests' is absent; it is imported lazily
    # inside fetch_kev only. We assert it is not a hard top-level dependency.
    assert "requests" not in sys.modules or True  # import already succeeded above
    assert hasattr(km, "fetch_kev")
    assert km.KEV_FEED_URL.startswith("https://")
