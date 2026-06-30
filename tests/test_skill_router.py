#!/usr/bin/env python3
"""
Pytest for tools/skill_router.py — topic-triggered skill auto-loading.

Runs against the *real* skill inventory under <repo>/skills (89 skills at time
of writing). All assertions are inventory-relative (e.g. "hunt-graphql is in the
top results" rather than hard-coded counts) so they survive new skills being
added. stdlib + pytest only — no network, no LLM, no third-party deps.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

# ── Locate the repo and load skill_router by path ────────────────────────────
# tests/ lives at <repo>/tests/, the module at <repo>/tools/skill_router.py,
# and the real inventory at <repo>/skills/.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODULE_PATH = os.path.join(_REPO, "tools", "skill_router.py")
_SKILLS_DIR = os.path.join(_REPO, "skills")


def _load_module():
    spec = importlib.util.spec_from_file_location("skill_router", _MODULE_PATH)
    assert spec and spec.loader, f"cannot load module spec from {_MODULE_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sr = _load_module()


@pytest.fixture(scope="module")
def index():
    """The real skill index, loaded once from <repo>/skills."""
    return sr.load_skill_index(_SKILLS_DIR)


def _names(scored):
    """Pull skill names out of a [(name, score), ...] ranking."""
    return [name for name, _score in scored]


# ── load_skill_index ─────────────────────────────────────────────────────────

def test_module_path_and_skills_dir_exist():
    assert os.path.isfile(_MODULE_PATH), f"missing module: {_MODULE_PATH}"
    assert os.path.isdir(_SKILLS_DIR), f"missing skills dir: {_SKILLS_DIR}"


def test_load_skill_index_returns_real_skills(index):
    assert isinstance(index, list)
    assert len(index) >= 50, "expected the real (~89-skill) inventory, not a stub"

    names = {s["name"] for s in index}
    # The marquee per-class hunt skills the prompt calls out.
    assert "hunt-sqli" in names
    assert "hunt-xss" in names
    # Domain skills used elsewhere in these tests.
    assert "hunt-graphql" in names
    assert "hunt-nextjs" in names
    # Baselines must be discoverable in the real inventory.
    for base in sr.BASELINE_SKILLS:
        assert base in names, f"baseline {base!r} not found in real inventory"


def test_load_skill_index_entry_shape(index):
    for skill in index:
        assert set(skill.keys()) == {"name", "description", "keywords"}
        assert isinstance(skill["name"], str) and skill["name"]
        assert isinstance(skill["description"], str)
        assert isinstance(skill["keywords"], list)
        assert all(isinstance(k, str) for k in skill["keywords"])


def test_load_skill_index_sorted_by_name(index):
    names = [s["name"] for s in index]
    assert names == sorted(names), "index must be sorted by name ascending"
    assert len(names) == len(set(names)), "skill names must be unique"


def test_load_skill_index_default_dir_matches_repo_skills():
    # Default (no arg) should resolve to <repo>/skills and match the explicit one.
    default = sr.load_skill_index()
    explicit = sr.load_skill_index(_SKILLS_DIR)
    assert _names(
        [(s["name"], 0.0) for s in default]
    ) == _names([(s["name"], 0.0) for s in explicit])


def test_load_skill_index_nonexistent_dir_returns_empty():
    assert sr.load_skill_index(os.path.join(_REPO, "no-such-skills-dir-xyz")) == []


# ── score_skills ─────────────────────────────────────────────────────────────

def test_score_skills_covers_every_skill(index):
    scored = sr.score_skills({"tech": ["graphql"], "surface": ["api"]}, index)
    assert len(scored) == len(index), "every skill must appear in the ranking"
    assert _names(scored) != []
    # Tuple shape: (str, float).
    for name, score in scored:
        assert isinstance(name, str)
        assert isinstance(score, float)


def test_score_skills_sorted_by_score_then_name(index):
    scored = sr.score_skills({"tech": ["graphql"], "surface": ["api"]}, index)
    keys = [(-score, name) for name, score in scored]
    assert keys == sorted(keys), "must sort by score desc, then name asc"


def test_score_skills_graphql_api_ranks_graphql_skill_high(index):
    scored = sr.score_skills({"tech": ["graphql"], "surface": ["api"]}, index)
    top = _names(scored[:5])
    # graphql in the tech list should drive hunt-graphql to the very top.
    assert "hunt-graphql" in top, f"hunt-graphql not in top-5: {top}"
    # The dedicated graphql-audit domain skill should also surface near the top.
    assert "graphql-audit" in top, f"graphql-audit not in top-5: {top}"
    # The api surface term should pull the api-misconfig hunt skill up too.
    assert "hunt-api-misconfig" in _names(scored[:8])


def test_score_skills_nextjs_ranks_nextjs_skill(index):
    scored = sr.score_skills({"tech": ["nextjs"], "surface": []}, index)
    # A name-token hit (nextjs -> hunt-nextjs) is the strongest signal: #1.
    assert scored[0][0] == "hunt-nextjs", f"expected hunt-nextjs first, got {scored[0]}"
    # And it scores at least the name-match weight.
    nextjs_score = dict(scored)["hunt-nextjs"]
    assert nextjs_score >= sr.NAME_MATCH_WEIGHT


def test_score_skills_name_match_beats_baseline_bonus(index):
    # A real fingerprint hit must outrank the baseline +0.5 nudge.
    scored = dict(sr.score_skills({"tech": ["nextjs"]}, index))
    assert scored["hunt-nextjs"] > scored["bb-methodology"]
    # Baselines with no fingerprint hit still carry exactly the bonus.
    for base in sr.BASELINE_SKILLS:
        assert scored[base] >= sr.BASELINE_BONUS


def test_score_skills_baseline_bonus_applied_on_empty_fingerprint(index):
    scored = dict(sr.score_skills({}, index))
    for base in sr.BASELINE_SKILLS:
        assert scored[base] == pytest.approx(sr.BASELINE_BONUS)


def test_score_skills_multi_tech_surfaces_relevant_set(index):
    # The verified routing example from the module docstring.
    fp = {"tech": ["aspnet", "s3", "kubernetes"], "surface": ["upload", "api"]}
    top = set(_names(sr.score_skills(fp, index)[:12]))
    for expected in [
        "hunt-aspnet",
        "hunt-file-upload",
        "hunt-api-misconfig",
        "hunt-cloud-misconfig",
        "hunt-k8s",
    ]:
        assert expected in top, f"{expected} missing from top-12: {sorted(top)}"


def test_score_skills_tolerates_string_tech(index):
    # tech given as a bare string (not a list) must be handled.
    scored = sr.score_skills({"tech": "graphql"}, index)
    assert scored[0][0] in ("hunt-graphql", "graphql-audit")


# ── route ────────────────────────────────────────────────────────────────────

def test_route_includes_baselines_for_relevant_fingerprint():
    fp = {"tech": ["nextjs", "graphql"], "surface": ["api", "auth"]}
    routed = sr.route(fp, top=15, skills_dir=_SKILLS_DIR)
    for base in sr.BASELINE_SKILLS:
        assert base in routed, f"baseline {base!r} not routed"
    # Relevant skills should also be present.
    assert "hunt-graphql" in routed
    assert "hunt-nextjs" in routed


def test_route_respects_top_n_but_always_appends_baselines():
    fp = {"tech": ["nextjs", "graphql"], "surface": ["api", "auth"]}
    routed = sr.route(fp, top=2, skills_dir=_SKILLS_DIR)
    # top=2 ranked names + any baselines not already in those 2.
    # Result must contain all baselines even though they're cut off by top=2.
    for base in sr.BASELINE_SKILLS:
        assert base in routed
    # No duplicates.
    assert len(routed) == len(set(routed))
    # At most 2 ranked + 3 baselines.
    assert len(routed) <= 2 + len(sr.BASELINE_SKILLS)


def test_route_top_zero_returns_only_baselines():
    routed = sr.route({"tech": ["nextjs"]}, top=0, skills_dir=_SKILLS_DIR)
    assert sorted(routed) == sorted(sr.BASELINE_SKILLS)


def test_route_no_duplicates_and_subset_of_index(index):
    fp = {"tech": ["graphql", "nodejs"], "surface": ["api", "auth", "upload"]}
    routed = sr.route(fp, top=20, skills_dir=_SKILLS_DIR)
    assert len(routed) == len(set(routed)), "route must not return duplicates"
    available = {s["name"] for s in index}
    for name in routed:
        assert name in available, f"routed unknown skill: {name}"


def test_route_relevant_skill_ranks_above_baselines_in_order():
    fp = {"tech": ["graphql"], "surface": ["api"]}
    routed = sr.route(fp, top=15, skills_dir=_SKILLS_DIR)
    # hunt-graphql is a genuine name hit; it must appear before any baseline
    # that was only appended/nudged.
    gql_idx = routed.index("hunt-graphql")
    for base in sr.BASELINE_SKILLS:
        if base in routed:
            assert gql_idx < routed.index(base), (
                f"hunt-graphql ({gql_idx}) should outrank baseline {base}"
            )


def test_route_nonsense_fingerprint_returns_baseline_set():
    fp = {"tech": ["zzqqxx", "notarealtech"], "surface": ["blahblah"], "notes": "qwertyuiop"}
    routed = sr.route(fp, top=15, skills_dir=_SKILLS_DIR)
    # Baselines must always be present, even when nothing matches.
    for base in sr.BASELINE_SKILLS:
        assert base in routed, f"baseline {base!r} missing for nonsense fingerprint"


def test_route_nonsense_fingerprint_top0_is_exactly_baselines():
    # With no real hits and top=0, the *only* thing routed is the baseline set.
    fp = {"tech": ["zzqqxx"], "surface": ["blahblah"]}
    routed = sr.route(fp, top=0, skills_dir=_SKILLS_DIR)
    assert sorted(routed) == sorted(sr.BASELINE_SKILLS)


def test_route_empty_fingerprint_returns_baselines_at_minimum():
    routed = sr.route({}, top=15, skills_dir=_SKILLS_DIR)
    for base in sr.BASELINE_SKILLS:
        assert base in routed


# ── helpers / constants ──────────────────────────────────────────────────────

def test_tokenize_filters_stopwords_and_short_tokens():
    toks = sr._tokenize("The GraphQL API is a Next.js app")
    assert "the" not in toks and "is" not in toks and "a" not in toks
    assert "graphql" in toks
    assert "api" in toks
    # Single-char tokens dropped.
    assert all(len(t) > 1 for t in toks)


def test_parse_frontmatter_basic():
    md = '---\nname: hunt-demo\ndescription: "Find demo bugs in apps"\n---\n# body\n'
    fm = sr._parse_frontmatter(md)
    assert fm["name"] == "hunt-demo"
    assert fm["description"] == "Find demo bugs in apps"


def test_parse_frontmatter_no_block_returns_empty():
    assert sr._parse_frontmatter("# just a heading\nno frontmatter here") == {}


def test_fingerprint_terms_dedupes_and_lowercases():
    terms = sr._fingerprint_terms(
        {"tech": ["GraphQL", "graphql"], "surface": ["API"], "notes": "graphql notes"}
    )
    assert terms == [t for i, t in enumerate(terms) if t not in terms[:i]], "deduped"
    assert all(t == t.lower() for t in terms)
    assert "graphql" in terms and "api" in terms


def test_fingerprint_terms_tolerates_missing_keys():
    assert sr._fingerprint_terms({}) == []
    assert sr._fingerprint_terms({"tech": "graphql"}) != []


def test_baseline_constants_present():
    assert sr.BASELINE_SKILLS == ["bb-methodology", "web2-recon", "triage-validation"]
    assert sr.NAME_MATCH_WEIGHT > sr.KEYWORD_MATCH_WEIGHT > sr.DESCRIPTION_MATCH_WEIGHT
    assert sr.BASELINE_BONUS > 0
    assert sr.NAME_MATCH_WEIGHT > sr.BASELINE_BONUS


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
