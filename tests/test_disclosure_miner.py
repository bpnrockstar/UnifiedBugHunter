#!/usr/bin/env python3
"""
Pytest for tools/disclosure_miner.py — mining disclosed bug-bounty reports into
reviewed hunt-* skill proposals.

Runs against the *real* skill inventory under <repo>/skills so map_to_skill is
exercised the way it ships: a canonical class lands on a hunt-* skill that
actually exists on disk (hunt-sqli / hunt-idor / hunt-xss are all present). A
small inline sample of disclosed-report dicts (one each for SQLi, IDOR, XSS,
plus malformed/empty edge cases) drives the classify -> map -> extract -> mine
pipeline. stdlib + pytest only — no network, no LLM, no third-party deps; the
module performs no I/O at import and none of these tests touch the network.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

# ── Locate the repo and load disclosure_miner by path ─────────────────────────
# tests/ lives at <repo>/tests/, the module at <repo>/tools/disclosure_miner.py,
# and the real skill inventory at <repo>/skills/.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODULE_PATH = os.path.join(_REPO, "tools", "disclosure_miner.py")
_SKILLS_DIR = os.path.join(_REPO, "skills")


def _load_module():
    spec = importlib.util.spec_from_file_location("disclosure_miner", _MODULE_PATH)
    assert spec and spec.loader, f"cannot load module spec from {_MODULE_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dm = _load_module()


# ── Inline sample of disclosed-report dicts ───────────────────────────────────
# Mirrors the flexible H1 / HuggingFace disclosure export schema the module
# documents. One well-formed report per marquee class, with realistic
# weakness/title phrasing plus payload/endpoint hints to feed extract_signals.

SQLI_REPORT = {
    "id": "R-SQLI-1",
    "title": "Blind SQL Injection in /api/search filter",
    "weakness": "SQL Injection",
    "severity": "critical",
    "substate": "resolved",
    "summary": (
        "A time-based blind SQL injection in the search filter lets an "
        "attacker dump the users table. Reached via /api/search?q=test."
    ),
    "endpoint": "/api/search",
    "payload": "q=test' OR '1'='1' UNION SELECT password FROM users--",
}

IDOR_REPORT = {
    "id": "R-IDOR-2",
    "title": "IDOR on order endpoint exposes other users' invoices",
    "weakness": "Insecure Direct Object Reference",
    "severity": "high",
    "substate": "resolved",
    "summary": (
        "Swapping the sequential id in /api/orders/{id} returns another "
        "customer's invoice. No ownership check on the object reference."
    ),
    "endpoint": "/api/orders/{id}",
}

XSS_REPORT = {
    "id": "R-XSS-3",
    "title": "Stored XSS in profile bio field",
    "weakness": "Cross-Site Scripting",
    "severity": "medium",
    "substate": "resolved",
    "summary": (
        "A stored XSS fires on the profile page at /users/me when the bio "
        "contains <script>alert(1)</script>. Persists across sessions."
    ),
    "endpoint": "/users/me",
    "payload": "<script>alert(1)</script>",
}

# Edge cases that mine() / classify_report() / extract_signals() must tolerate.
MALFORMED_REPORTS = [
    None,                       # not a dict
    {},                         # empty dict
    "just a string",            # not a dict
    42,                         # not a dict
    {"id": "no-text"},          # dict with id but nothing readable
    {"severity": "high"},       # only metadata, no title/weakness/summary
    [],                         # not a dict
]

GOOD_REPORTS = [SQLI_REPORT, IDOR_REPORT, XSS_REPORT]


@pytest.fixture(scope="module")
def skills_dir():
    """The real on-disk skills directory (<repo>/skills)."""
    return _SKILLS_DIR


# ── Sanity: module + real inventory are where we expect ───────────────────────

def test_module_path_and_skills_dir_exist():
    assert os.path.isfile(_MODULE_PATH), f"missing module: {_MODULE_PATH}"
    assert os.path.isdir(_SKILLS_DIR), f"missing skills dir: {_SKILLS_DIR}"


def test_marquee_hunt_skills_present_on_disk():
    """map_to_skill can only return a real hunt-* skill if it exists on disk."""
    for name in ("hunt-sqli", "hunt-idor", "hunt-xss", "hunt-misc"):
        assert os.path.isdir(os.path.join(_SKILLS_DIR, name)), (
            f"expected real skill dir skills/{name}"
        )


# ── classify_report: weakness/title -> canonical class ────────────────────────

def test_classify_from_weakness():
    assert dm.classify_report(SQLI_REPORT) == "sqli"
    assert dm.classify_report(IDOR_REPORT) == "idor"
    assert dm.classify_report(XSS_REPORT) == "xss"


def test_classify_from_title_only():
    """No weakness field — classification falls through to the title/summary."""
    assert dm.classify_report({"title": "Reflected XSS in login form"}) == "xss"
    assert dm.classify_report({"title": "SQLi via the id parameter"}) == "sqli"
    assert dm.classify_report(
        {"title": "Insecure direct object reference in profile API"}
    ) == "idor"


def test_classify_honors_explicit_vuln_class():
    """An explicit canonical vuln_class wins, including underscore normalization."""
    assert dm.classify_report({"vuln_class": "idor", "title": "x"}) == "idor"
    assert dm.classify_report(
        {"vuln_class": "open_redirect", "title": "x"}
    ) == "open-redirect"


def test_classify_unknown_falls_back():
    assert dm.classify_report({"title": "something totally unrelated"}) == "unknown"


def test_classify_malformed_is_unknown_not_crash():
    for bad in (None, {}, "str", 42, []):
        assert dm.classify_report(bad) == "unknown"


# ── map_to_skill: canonical class -> real hunt-* skill ────────────────────────

def test_map_to_skill_returns_real_hunt_skills(skills_dir):
    assert dm.map_to_skill("sqli", skills_dir) == "hunt-sqli"
    assert dm.map_to_skill("idor", skills_dir) == "hunt-idor"
    assert dm.map_to_skill("xss", skills_dir) == "hunt-xss"


def test_map_to_skill_targets_exist_on_disk(skills_dir):
    """Whatever map_to_skill returns must be a directory under skills/."""
    for cls in ("sqli", "idor", "xss"):
        skill = dm.map_to_skill(cls, skills_dir)
        assert skill.startswith("hunt-")
        assert os.path.isdir(os.path.join(skills_dir, skill)), (
            f"map_to_skill({cls!r}) -> {skill} is not a real skill dir"
        )


def test_map_to_skill_unknown_goes_to_misc(skills_dir):
    assert dm.map_to_skill("unknown", skills_dir) == "hunt-misc"


# ── extract_signals: payload / endpoint / technique hints ─────────────────────

def test_extract_signals_pulls_payload_and_endpoint():
    sig = dm.extract_signals(SQLI_REPORT)
    assert set(sig) == {"techniques", "payloads", "endpoints"}
    # Explicit payload field is preferred and carried through verbatim.
    assert any("UNION SELECT" in p for p in sig["payloads"])
    # Explicit endpoint field is preferred.
    assert "/api/search" in sig["endpoints"]
    # "blind" + "time-based" phrasing surfaces technique hints.
    assert sig["techniques"], "expected at least one technique hint for blind/time-based SQLi"


def test_extract_signals_xss_payload_marker():
    sig = dm.extract_signals(XSS_REPORT)
    assert any("script" in p.lower() for p in sig["payloads"])
    assert "/users/me" in sig["endpoints"]
    # "stored" phrasing is a known technique hint.
    assert any("stored" in t.lower() for t in sig["techniques"])


def test_extract_signals_idor_endpoint_hint():
    sig = dm.extract_signals(IDOR_REPORT)
    assert "/api/orders/{id}" in sig["endpoints"]


def test_extract_signals_malformed_returns_empty_lists():
    for bad in (None, {}, "str", 42, []):
        sig = dm.extract_signals(bad)
        assert sig == {"techniques": [], "payloads": [], "endpoints": []}


# ── mine: proposals keyed to skills, malformed skipped ────────────────────────

def test_mine_produces_one_proposal_per_good_report(skills_dir):
    proposals = dm.mine(GOOD_REPORTS, skills_dir)
    assert len(proposals) == len(GOOD_REPORTS)


def test_mine_proposals_keyed_to_real_skills(skills_dir):
    proposals = dm.mine(GOOD_REPORTS, skills_dir)
    by_class = {p["vuln_class"]: p for p in proposals}

    assert by_class["sqli"]["skill"] == "hunt-sqli"
    assert by_class["idor"]["skill"] == "hunt-idor"
    assert by_class["xss"]["skill"] == "hunt-xss"

    for p in proposals:
        # Each proposal carries the full documented shape.
        assert set(p) == {"skill", "vuln_class", "source_id", "signals", "suggested_note"}
        assert p["skill"].startswith("hunt-")
        assert os.path.isdir(os.path.join(skills_dir, p["skill"]))
        assert set(p["signals"]) == {"techniques", "payloads", "endpoints"}
        assert isinstance(p["suggested_note"], str) and p["suggested_note"]


def test_mine_carries_source_id_and_signals(skills_dir):
    proposals = dm.mine([IDOR_REPORT], skills_dir)
    assert len(proposals) == 1
    prop = proposals[0]
    assert prop["source_id"] == "R-IDOR-2"
    assert "/api/orders/{id}" in prop["signals"]["endpoints"]
    # Note threads class + title + severity prefix together.
    assert "idor" in prop["suggested_note"]
    assert "[high]" in prop["suggested_note"]


def test_mine_skips_malformed_without_crashing(skills_dir):
    """Empty/non-dict/text-less records are dropped silently, no exception."""
    proposals = dm.mine(MALFORMED_REPORTS, skills_dir)
    assert proposals == []


def test_mine_mixed_good_and_malformed(skills_dir):
    """A noisy export yields exactly the well-formed reports' proposals."""
    mixed = [SQLI_REPORT, None, {}, IDOR_REPORT, "garbage", {"id": "x"}, XSS_REPORT]
    proposals = dm.mine(mixed, skills_dir)
    assert len(proposals) == 3
    classes = sorted(p["vuln_class"] for p in proposals)
    assert classes == ["idor", "sqli", "xss"]


def test_mine_empty_input_returns_empty(skills_dir):
    assert dm.mine([], skills_dir) == []
    assert dm.mine(None, skills_dir) == []
