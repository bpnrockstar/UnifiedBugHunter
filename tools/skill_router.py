#!/usr/bin/env python3
"""
skill_router.py — Topic-triggered skill auto-loading.

Given a target fingerprint (tech stack + attack surface + free-text notes),
rank which of the plugin's hunt-* / domain skills are worth loading. At the
89-skill scale, an operator can't eyeball which skills apply to a Next.js +
GraphQL API target; this maps the fingerprint onto a keyword index built from
each skill's frontmatter and returns the top-N most relevant skill names.

The index is read at runtime from skills/<name>/SKILL.md frontmatter (stdlib
only — a minimal YAML-ish parser, no PyYAML dependency). No network or LLM
calls happen at import time or in tests.

Usage:
  python3 tools/skill_router.py --tech nextjs,graphql --surface api,auth
  python3 tools/skill_router.py --tech aspnet --surface upload --notes "sharepoint farm" --top 10
  python3 tools/skill_router.py --tech s3,kubernetes --surface api --json
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import json
import os
import re
import sys

# Repo layout: this file lives in <repo>/tools/, skills live in <repo>/skills/.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_SKILLS_DIR = os.path.join(_REPO, "skills")

# Baseline skills always loaded regardless of fingerprint — the methodology,
# recon, and validation spine that applies to every engagement.
BASELINE_SKILLS = ["bb-methodology", "web2-recon", "triage-validation"]

# Name-token matches weigh more than description matches: a fingerprint term
# appearing in the skill *name* (e.g. "graphql" -> hunt-graphql) is a far
# stronger signal than the same term buried in prose.
NAME_MATCH_WEIGHT = 5.0
KEYWORD_MATCH_WEIGHT = 2.0
DESCRIPTION_MATCH_WEIGHT = 1.0
# Small nudge so baseline skills sort above zero-scoring skills but never
# outrank a genuine fingerprint hit.
BASELINE_BONUS = 0.5

# Tokens too generic to carry routing signal — they'd match nearly every skill.
_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with",
    "use", "when", "any", "via", "from", "this", "that", "is", "are", "be",
    "it", "as", "at", "by", "if", "all", "can", "you", "your", "not",
}

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    """Lowercase, split on non-alphanumerics, drop stopwords and 1-char noise."""
    if not text:
        return []
    return [
        tok
        for tok in _TOKEN_RE.findall(text.lower())
        if len(tok) > 1 and tok not in _STOPWORDS
    ]


def _parse_frontmatter(text: str) -> dict[str, str]:
    """Parse the leading --- ... --- YAML-ish frontmatter block.

    Minimal, stdlib-only: handles `key: value` and `key: "quoted value"` on a
    single line, the format every SKILL.md in this repo uses. Returns {} when
    no frontmatter block is present. Not a general YAML parser by design.
    """
    stripped = text.lstrip()
    if not stripped.startswith("---"):
        return {}

    # Find the closing delimiter after the opening one.
    lines = stripped.splitlines()
    # lines[0] is the opening "---"
    body: list[str] = []
    for line in lines[1:]:
        if line.strip() == "---":
            break
        body.append(line)
    else:
        # No closing delimiter — not a valid frontmatter block.
        return {}

    result: dict[str, str] = {}
    for line in body:
        if ":" not in line:
            continue
        # Skip indented continuation / nested lines — top-level keys only.
        if line[:1] in (" ", "\t"):
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        # Strip matching surrounding quotes.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            result[key] = value
    return result


def load_skill_index(skills_dir: str | None = None) -> list[dict]:
    """Scan skills/<name>/SKILL.md and build a keyword index.

    Args:
        skills_dir: Directory holding one subdirectory per skill. Defaults to
            <repo>/skills.

    Returns:
        A list of dicts, one per skill, each with:
            name        -> str  (frontmatter name, falling back to dir name)
            description -> str  (frontmatter description, may be "")
            keywords    -> list[str]  (deduped tokens from name + description)
        Sorted by name for deterministic output. Skills with no readable
        SKILL.md are skipped silently.
    """
    base = skills_dir or _DEFAULT_SKILLS_DIR
    index: list[dict] = []

    if not os.path.isdir(base):
        return index

    for entry in sorted(os.listdir(base)):
        skill_path = os.path.join(base, entry)
        if not os.path.isdir(skill_path):
            continue
        md_path = os.path.join(skill_path, "SKILL.md")
        if not os.path.isfile(md_path):
            continue
        try:
            with open(md_path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue

        fm = _parse_frontmatter(text)
        name = fm.get("name", "").strip() or entry
        description = fm.get("description", "").strip()

        keyword_set: set[str] = set()
        keyword_set.update(_tokenize(name))
        keyword_set.update(_tokenize(name.replace("-", " ")))
        keyword_set.update(_tokenize(description))

        index.append(
            {
                "name": name,
                "description": description,
                "keywords": sorted(keyword_set),
            }
        )

    index.sort(key=lambda s: s["name"])
    return index


def _fingerprint_terms(fingerprint: dict) -> list[str]:
    """Flatten a fingerprint into a deduped list of lowercase query tokens."""
    terms: list[str] = []
    for field in ("tech", "surface"):
        values = fingerprint.get(field) or []
        if isinstance(values, str):
            values = [values]
        for value in values:
            terms.extend(_tokenize(str(value)))
            # Keep the raw token too (e.g. "aspnet") for direct substring hits.
            cleaned = str(value).strip().lower()
            if cleaned and cleaned not in terms:
                terms.append(cleaned)

    terms.extend(_tokenize(str(fingerprint.get("notes", "") or "")))

    # Dedupe, preserve order.
    seen: set[str] = set()
    deduped: list[str] = []
    for term in terms:
        if term and term not in seen:
            seen.add(term)
            deduped.append(term)
    return deduped


def _score_one(terms: list[str], skill: dict) -> float:
    """Score a single skill against the flattened fingerprint terms."""
    name = skill.get("name", "")
    name_tokens = set(_tokenize(name) + _tokenize(name.replace("-", " ")))
    keyword_set = set(skill.get("keywords") or [])
    description = (skill.get("description") or "").lower()

    score = 0.0
    for term in terms:
        # Name match — strongest signal. Token equality OR substring within the
        # skill name (so "graphql" hits "hunt-graphql", "k8s" hits "hunt-k8s").
        if term in name_tokens or term in name.lower():
            score += NAME_MATCH_WEIGHT
            continue
        # Keyword index match (tokens drawn from name + description).
        if term in keyword_set:
            score += KEYWORD_MATCH_WEIGHT
            continue
        # Substring match anywhere in the description.
        if term in description:
            score += DESCRIPTION_MATCH_WEIGHT
    return score


def score_skills(fingerprint: dict, index: list[dict]) -> list[tuple[str, float]]:
    """Rank every skill in the index against the fingerprint.

    Args:
        fingerprint: {tech: [...], surface: [...], notes: str}
        index: output of load_skill_index().

    Returns:
        A list of (skill_name, score) tuples sorted by score descending, then
        by name ascending for stable tie-breaking. Baseline skills receive a
        small additive bonus so they never fall below zero-scoring skills.
        Every skill in the index appears in the result (including score 0.0).
    """
    terms = _fingerprint_terms(fingerprint)
    baseline = set(BASELINE_SKILLS)

    scored: list[tuple[str, float]] = []
    for skill in index:
        name = skill.get("name", "")
        score = _score_one(terms, skill)
        if name in baseline:
            score += BASELINE_BONUS
        scored.append((name, score))

    scored.sort(key=lambda pair: (-pair[1], pair[0]))
    return scored


def route(fingerprint: dict, top: int = 15, skills_dir: str | None = None) -> list[str]:
    """Return the top-N skill names to load for a fingerprint.

    Always includes the baseline skills (bb-methodology, web2-recon,
    triage-validation) even if they would otherwise fall outside the top-N
    cutoff — they are appended if missing. The relative order of the top-N is
    score-driven; appended baselines go at the end in their canonical order.

    Args:
        fingerprint: {tech: [...], surface: [...], notes: str}
        top: Maximum number of fingerprint-ranked skills to return.
        skills_dir: Optional override for the skills directory.

    Returns:
        Ordered list of skill names (no duplicates).
    """
    index = load_skill_index(skills_dir)
    ranked = score_skills(fingerprint, index)

    top_n = max(0, int(top))
    selected: list[str] = []
    seen: set[str] = set()
    for name, _score in ranked[:top_n]:
        if name not in seen:
            seen.add(name)
            selected.append(name)

    # Guarantee baseline coverage even if cut off by `top`, but only for
    # baselines that actually exist in the loaded index.
    available = {s["name"] for s in index}
    for name in BASELINE_SKILLS:
        if name not in seen and name in available:
            seen.add(name)
            selected.append(name)

    return selected


# ─── CLI ────────────────────────────────────────────────────────────────────

def _split_csv(values: list[str]) -> list[str]:
    """Expand repeated and/or comma-separated CLI args, preserving order."""
    out: list[str] = []
    for value in values or []:
        for part in value.split(","):
            part = part.strip()
            if part:
                out.append(part)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rank which hunt-*/domain skills to load for a target fingerprint."
    )
    parser.add_argument(
        "--tech",
        action="append",
        default=[],
        help="Tech stack tokens. Repeat or comma-separate, e.g. nextjs,graphql,nodejs",
    )
    parser.add_argument(
        "--surface",
        action="append",
        default=[],
        help="Attack surface tokens. Repeat or comma-separate, e.g. api,auth,upload",
    )
    parser.add_argument("--notes", default="", help="Free-text notes about the target")
    parser.add_argument("--top", type=int, default=15, help="Max skills to return (default 15)")
    parser.add_argument(
        "--skills-dir",
        default=None,
        help="Override the skills directory (default: <repo>/skills)",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args(argv)

    fingerprint = {
        "tech": _split_csv(args.tech),
        "surface": _split_csv(args.surface),
        "notes": args.notes or "",
    }

    index = load_skill_index(args.skills_dir)
    if not index:
        print(
            f"WARNING: no skills found under {args.skills_dir or _DEFAULT_SKILLS_DIR}",
            file=sys.stderr,
        )

    ranked = score_skills(fingerprint, index)
    top_n = max(0, int(args.top))
    selected = route(fingerprint, top=args.top, skills_dir=args.skills_dir)
    selected_set = set(selected)

    # Build the ranked-with-scores view limited to what we'd actually load.
    score_lookup = dict(ranked)
    ranked_view = [
        {"name": name, "score": round(score_lookup.get(name, 0.0), 2)}
        for name, _score in ranked[:top_n]
    ]
    # Append any baselines pulled in beyond the cutoff.
    shown = {item["name"] for item in ranked_view}
    for name in selected:
        if name not in shown:
            ranked_view.append({"name": name, "score": round(score_lookup.get(name, 0.0), 2)})

    if args.json:
        print(
            json.dumps(
                {
                    "fingerprint": fingerprint,
                    "top": top_n,
                    "skills_dir": args.skills_dir or _DEFAULT_SKILLS_DIR,
                    "baseline": BASELINE_SKILLS,
                    "routed": selected,
                    "ranked": ranked_view,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"Fingerprint: tech={fingerprint['tech']} surface={fingerprint['surface']}")
        if fingerprint["notes"]:
            print(f"Notes: {fingerprint['notes']}")
        print(f"Routing {len(selected)} skills (top={top_n}):")
        for item in ranked_view:
            marker = " *" if item["name"] in selected_set else "  "
            baseline_tag = " [baseline]" if item["name"] in BASELINE_SKILLS else ""
            print(f"{marker} {item['score']:6.2f}  {item['name']}{baseline_tag}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
