#!/usr/bin/env python3
"""
run_eval_code.py — white-box scorer for UBH's code-review (SAST) accuracy.

`eval/` was entirely black-box (drive a headless agent at a live target, read its
self-graded oracle). This module is the white-box counterpart: a committed corpus of
INTENTIONALLY-VULNERABLE source files with matched SAFE variants
(eval/code_corpus/{vulnerable,safe}/) plus a hand-labeled ground truth
(ground_truth.json). It runs the SAST engine over the corpus, compares the findings
against ground truth, and turns "is our code review any good?" into a measured number:
precision / recall / F1 per vuln class + overall, with a TP/FP/FN confusion summary.

Two ways to get findings (mirrors tools/secrets_hunter.sh graceful degradation):
  * live   — import tools/sast_runner.run_sast and scan the corpus. Uses semgrep when
             installed; the runner itself degrades to a regex fallback when it is not.
  * static — pass a pre-computed findings JSON via --findings (e.g. the committed
             eval/code_corpus/findings_sample.json). This is the path tests use, so
             the scorer is exercised WITHOUT semgrep installed.

Engine-label normalization (why the eval re-canonicalizes vuln_class):
  Different engines (and sast_runner's own coarse router) label the same bug
  differently — semgrep's auto ruleset routes JWT-alg-none to 'other', names command
  injection 'cmd-injection', weak crypto 'crypto', etc. The corpus ground truth uses
  one stable taxonomy (the 10 prompt classes). canonicalize_class() folds every engine
  label — using vuln_class first, then rule_id / message keywords — into that taxonomy
  so the score measures "did we flag the right bug at the right place", not "did the
  engine happen to use our exact class string". A finding that cannot be canonicalized
  to a corpus class is treated as out-of-taxonomy noise and ignored (it is neither a
  TP nor an FP) UNLESS it lands on a SAFE file, where ANY security finding is a FP.

Importable surface (tests import these directly):
    load_ground_truth(path) -> dict
    canonicalize_class(finding) -> str | None
    finding_file(finding) -> str            # path|file accessor
    normalize_findings(findings) -> list[dict]
    score(findings, ground_truth) -> dict   # <<< the scorer
    format_report(scored) -> str

score() signature / return shape:
    score(findings: list[dict], ground_truth: dict) -> dict
      findings:     normalized or raw SAST findings (dicts with file/path, line,
                    vuln_class, and optionally rule_id/message).
      ground_truth: the parsed ground_truth.json dict.
      returns: {
        "overall": {"tp","fp","fn","precision","recall","f1","support"},
        "per_class": { "<class>": {"tp","fp","fn","precision","recall","f1","support"} },
        "matched":   [ {expected..., "matched_line": int} ],     # TPs
        "missed":    [ expected... ],                            # FNs
        "false_positives": [ finding... ],                       # FPs
        "negatives": {"files": int, "clean": int, "violated": int,
                       "violations": [finding...]},
      }

Python 3, stdlib only (json + argparse + os + sys). No third-party imports.
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import json
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_THIS_DIR))  # eval/code_corpus -> eval -> repo

DEFAULT_GROUND_TRUTH = os.path.join(_THIS_DIR, "ground_truth.json")
DEFAULT_FINDINGS = os.path.join(_THIS_DIR, "findings_sample.json")
CORPUS_ROOT = _THIS_DIR  # ground-truth file paths are relative to eval/code_corpus/

# The corpus taxonomy (the 10 classes in the prompt / ground_truth.json). Every
# expected finding and every canonicalized SAST finding lives in this set.
CORPUS_CLASSES = [
    "sqli",
    "xss",
    "command-injection",
    "ssrf",
    "path-traversal",
    "insecure-deserialization",
    "ssti",
    "weak-crypto",
    "jwt-alg-none",
    "hardcoded-secret",
]

# Direct aliases from other taxonomies (notably tools/sast_runner.VULN_CLASSES) onto
# the corpus taxonomy. Anything not here falls through to keyword routing.
_CLASS_ALIASES = {
    "sqli": "sqli",
    "sql-injection": "sqli",
    "xss": "xss",
    "command-injection": "command-injection",
    "cmd-injection": "command-injection",  # sast_runner's label
    "os-command-injection": "command-injection",
    "ssrf": "ssrf",
    "path-traversal": "path-traversal",
    "lfi": "path-traversal",
    "insecure-deserialization": "insecure-deserialization",
    "deserialization": "insecure-deserialization",  # sast_runner's label
    "ssti": "ssti",
    "template-injection": "ssti",
    "weak-crypto": "weak-crypto",
    "crypto": "weak-crypto",  # sast_runner's label
    "jwt-alg-none": "jwt-alg-none",
    "hardcoded-secret": "hardcoded-secret",
    "secret": "hardcoded-secret",  # sast_runner's label
}

# Keyword routing for engine labels that don't alias cleanly (e.g. semgrep routes
# JWT-alg-none through sast_runner as 'other', but its rule id says 'jwt-none-alg').
# Ordered (corpus_class, [substrings]); matched against "rule_id + ' ' + message".
# JWT is listed FIRST so 'jwt-none-alg' / 'unverified-jwt' beat generic crypto words.
_KEYWORD_ROUTES: list[tuple[str, list[str]]] = [
    ("jwt-alg-none", ["jwt-none", "jwt-python-none", "none-alg", "unverified-jwt", "jwt_alg_none"]),
    ("sqli", ["sql-injection", "sqli", "raw-query", "rawsql", "formatted-sql", "cwe-89"]),
    ("command-injection", ["command-injection", "subprocess", "child-process", "child_process",
                            "os-command", "shell-true", "cwe-78", "cwe-77"]),
    ("ssti", ["template-injection", "ssti", "jinja", "cwe-1336"]),
    ("xss", ["xss", "cross-site-scripting", "innerhtml", "raw-html", "direct-response-write",
             "directly-returned-format-string", "cwe-79"]),
    ("ssrf", ["ssrf", "server-side-request-forgery", "tainted-url-host", "cwe-918"]),
    ("path-traversal", ["path-traversal", "directory-traversal", "tainted-path", "cwe-22", "cwe-23"]),
    ("insecure-deserialization", ["pickle", "deserial", "unpickle", "marshal", "cwe-502"]),
    ("weak-crypto", ["md5", "sha1", "weak-hash", "insecure-hash", "weak-cipher", "cwe-327",
                     "cwe-326", "cwe-328"]),
    ("hardcoded-secret", ["hardcoded", "generic-api-key", "stripe-api-key", "secret", "cwe-798",
                          "cwe-259"]),
]


def load_ground_truth(path: str = DEFAULT_GROUND_TRUTH) -> dict:
    """Load and lightly validate ground_truth.json.

    Raises:
        OSError: file unreadable.
        ValueError: malformed JSON or missing the required keys.
    """
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "expected" not in data:
        raise ValueError(f"{path}: ground truth must be an object with an 'expected' list")
    data.setdefault("negatives", [])
    data.setdefault("line_tolerance", 2)
    return data


def finding_file(finding: dict) -> str:
    """Return a finding's file path, tolerating both schemas.

    sast_runner emits findings keyed by 'path'; the ground truth (and some external
    findings JSONs) key by 'file'. Accept either.
    """
    return str(finding.get("path") or finding.get("file") or "")


def _corpus_rel(path: str) -> str:
    """Normalize a finding path to a corpus-relative key (matches ground_truth 'file').

    Findings may carry 'eval/code_corpus/vulnerable/sqli.py', an absolute path, or
    already-relative 'vulnerable/sqli.py'. All collapse to 'vulnerable/sqli.py'.
    """
    p = str(path).replace("\\", "/")
    marker = "code_corpus/"
    if marker in p:
        p = p.split(marker, 1)[1]
    p = os.path.normpath(p).replace("\\", "/")
    # Strip any leading './'
    return p[2:] if p.startswith("./") else p


def canonicalize_class(finding: dict) -> str | None:
    """Fold an engine's vuln label into the corpus taxonomy, or None if out-of-scope.

    Resolution order:
      1. alias of the finding's own vuln_class,
      2. keyword routing over rule_id + message.
    Returns one of CORPUS_CLASSES, or None when the finding can't be placed (e.g. a
    generic 'other' with no recognizable signal).
    """
    raw = str(finding.get("vuln_class", "")).strip().lower()
    if raw in _CLASS_ALIASES:
        return _CLASS_ALIASES[raw]
    if raw in CORPUS_CLASSES:
        return raw

    haystack = f"{finding.get('rule_id', '')} {finding.get('message', '')}".lower()
    for corpus_class, triggers in _KEYWORD_ROUTES:
        if any(t in haystack for t in triggers):
            return corpus_class
    return None


def normalize_findings(findings: list[dict]) -> list[dict]:
    """Project raw/engine findings onto the eval's comparison schema.

    Output dicts: {file, line, vuln_class (canonical or None), raw_class, rule_id,
    message}. file is corpus-relative. Findings that can't be canonicalized keep
    vuln_class=None (still tracked so they can count as FPs on SAFE files).
    """
    out: list[dict] = []
    for f in findings or []:
        out.append(
            {
                "file": _corpus_rel(finding_file(f)),
                "line": int(f.get("line", 0) or 0),
                "vuln_class": canonicalize_class(f),
                "raw_class": str(f.get("vuln_class", "")),
                "rule_id": str(f.get("rule_id", "")),
                "message": str(f.get("message", "")),
            }
        )
    return out


def _empty_counts() -> dict:
    return {"tp": 0, "fp": 0, "fn": 0, "support": 0}


def _prf(tp: int, fp: int, fn: int) -> dict:
    """Precision / recall / F1 from raw counts (0.0 when undefined)."""
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def score(findings: list[dict], ground_truth: dict) -> dict:
    """Score SAST findings against the corpus ground truth.

    Matching rule for a true positive: a normalized finding whose corpus-relative
    file equals an expected entry's file, whose canonical vuln_class equals the
    expected vuln_class, and whose line is within `line_tolerance` of the expected
    line. Each expected entry is matched at most once; each finding is consumed at
    most once (greedy, closest-line first).

    False positives:
      * a vulnerable-file finding (correct class) that matches no expected entry, OR
      * ANY security finding on a SAFE/negative file (negatives expect zero findings).
    Findings on vulnerable files that canonicalize to a class with no expected entry
    for that file are out-of-taxonomy noise and ignored (neither TP nor FP), so the
    eval doesn't punish an engine for flagging an unrelated true issue we didn't label.

    Returns the dict documented in the module docstring.
    """
    norm = normalize_findings(findings)
    expected = list(ground_truth.get("expected", []))
    negatives = list(ground_truth.get("negatives", []))
    tol = int(ground_truth.get("line_tolerance", 2))

    negative_files = {_corpus_rel(n["file"]) for n in negatives}
    # Map expected entries by (file -> list of expected for that file).
    per_class: dict[str, dict] = {c: _empty_counts() for c in CORPUS_CLASSES}

    # --- positives: match findings to expected on vulnerable files ----------------
    matched: list[dict] = []
    missed: list[dict] = []
    false_positives: list[dict] = []

    # Track which findings get consumed as TPs so they aren't double-counted as FPs.
    consumed = [False] * len(norm)
    # (file, class) -> [matched lines]. Used to suppress duplicate-rule hits: many
    # engines fire several rules for one bug on one line. The first is the TP; the
    # rest, if same file+class and within tolerance of the matched line, are the SAME
    # finding (a duplicate), not new false positives.
    tp_anchors: dict[tuple[str, str], list[int]] = {}

    for exp in expected:
        exp_file = _corpus_rel(exp["file"])
        exp_class = exp["vuln_class"]
        exp_line = int(exp.get("line", 0) or 0)
        per_class.setdefault(exp_class, _empty_counts())
        per_class[exp_class]["support"] += 1

        # Candidate findings: same file, same canonical class, unconsumed.
        candidates = [
            (i, abs(norm[i]["line"] - exp_line))
            for i in range(len(norm))
            if not consumed[i]
            and norm[i]["file"] == exp_file
            and norm[i]["vuln_class"] == exp_class
            and abs(norm[i]["line"] - exp_line) <= tol
        ]
        if candidates:
            best_i = min(candidates, key=lambda t: t[1])[0]
            consumed[best_i] = True
            per_class[exp_class]["tp"] += 1
            tp_anchors.setdefault((exp_file, exp_class), []).append(norm[best_i]["line"])
            matched.append({**exp, "file": exp_file, "matched_line": norm[best_i]["line"],
                            "rule_id": norm[best_i]["rule_id"]})
        else:
            per_class[exp_class]["fn"] += 1
            missed.append({**exp, "file": exp_file})

    # Expected files: every file that legitimately should carry findings.
    expected_pairs = {(_corpus_rel(e["file"]), e["vuln_class"]) for e in expected}

    # --- false positives ----------------------------------------------------------
    negatives_violations: list[dict] = []
    for i, nf in enumerate(norm):
        if consumed[i]:
            continue
        f_file = nf["file"]
        f_class = nf["vuln_class"]

        if f_file in negative_files:
            # Any (canonicalizable) security finding on a safe file is a false positive.
            if f_class is not None:
                per_class.setdefault(f_class, _empty_counts())
                per_class[f_class]["fp"] += 1
                false_positives.append(nf)
                negatives_violations.append(nf)
            continue

        # Vulnerable-file finding that did not match an expected entry.
        if f_class is None:
            continue  # out-of-taxonomy noise on a vuln file — ignore
        # Duplicate of an already-matched TP (same file+class, near the matched line)?
        # Engines routinely fire multiple rules for one bug on one line — that is one
        # finding, not a fresh false positive, so suppress it.
        anchors = tp_anchors.get((f_file, f_class), [])
        if any(abs(nf["line"] - a) <= tol for a in anchors):
            continue
        if (f_file, f_class) in expected_pairs:
            # Same file+class as an expected bug but at a different location (out of
            # tolerance of every TP) -> a genuine false positive for that class.
            per_class[f_class]["fp"] += 1
            false_positives.append(nf)
        # else: a different (real) class we didn't label on this vuln file — ignore.

    # --- aggregate ----------------------------------------------------------------
    for cls, c in per_class.items():
        c.update(_prf(c["tp"], c["fp"], c["fn"]))

    tot_tp = sum(c["tp"] for c in per_class.values())
    tot_fp = sum(c["fp"] for c in per_class.values())
    tot_fn = sum(c["fn"] for c in per_class.values())
    overall = {
        "tp": tot_tp,
        "fp": tot_fp,
        "fn": tot_fn,
        "support": sum(c["support"] for c in per_class.values()),
        **_prf(tot_tp, tot_fp, tot_fn),
    }

    clean_negatives = len(negative_files) - len({v["file"] for v in negatives_violations})

    return {
        "overall": overall,
        "per_class": per_class,
        "matched": matched,
        "missed": missed,
        "false_positives": false_positives,
        "negatives": {
            "files": len(negative_files),
            "clean": clean_negatives,
            "violated": len(negative_files) - clean_negatives,
            "violations": negatives_violations,
        },
    }


def format_report(scored: dict) -> str:
    """Render a scored result as a human-readable precision/recall/F1 table."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("  UBH code-review eval — white-box corpus (eval/code_corpus/)")
    lines.append("=" * 72)

    header = f"  {'class':<26} {'TP':>3} {'FP':>3} {'FN':>3} {'prec':>6} {'rec':>6} {'F1':>6}"
    lines.append("")
    lines.append("  Per class")
    lines.append("  " + "-" * 68)
    lines.append(header)
    pc = scored["per_class"]
    for cls in sorted(pc, key=lambda c: (-pc[c]["support"], c)):
        c = pc[cls]
        if c["support"] == 0 and c["tp"] == 0 and c["fp"] == 0:
            continue
        lines.append(
            f"  {cls:<26} {c['tp']:>3} {c['fp']:>3} {c['fn']:>3} "
            f"{c['precision']:>6.2f} {c['recall']:>6.2f} {c['f1']:>6.2f}"
        )

    o = scored["overall"]
    lines.append("  " + "-" * 68)
    lines.append(
        f"  {'OVERALL':<26} {o['tp']:>3} {o['fp']:>3} {o['fn']:>3} "
        f"{o['precision']:>6.2f} {o['recall']:>6.2f} {o['f1']:>6.2f}"
    )

    neg = scored["negatives"]
    lines.append("")
    lines.append("  Negative cases (SAFE variants — expect zero findings)")
    lines.append("  " + "-" * 68)
    lines.append(f"    files: {neg['files']}   clean: {neg['clean']}   violated: {neg['violated']}")
    for v in neg["violations"]:
        lines.append(f"      FP on safe file: {v['file']}:{v['line']} ({v['vuln_class']}) {v['rule_id']}")

    lines.append("")
    lines.append("  Confusion summary")
    lines.append("  " + "-" * 68)
    lines.append(f"    TP={o['tp']}  FP={o['fp']}  FN={o['fn']}  (support={o['support']})")
    if scored["missed"]:
        lines.append("    Missed (FN):")
        for m in scored["missed"]:
            lines.append(f"      {m['file']}:{m['line']} ({m['vuln_class']})")
    if scored["false_positives"]:
        lines.append("    False positives (FP):")
        for fp in scored["false_positives"]:
            lines.append(f"      {fp['file']}:{fp['line']} ({fp['vuln_class']}) {fp['rule_id']}")
    return "\n".join(lines)


def _gather_findings(args) -> tuple[list[dict], str]:
    """Resolve findings either from a --findings JSON or by running sast_runner."""
    if args.findings:
        with open(args.findings, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and "findings" in data:
            return data["findings"], f"findings file: {args.findings}"
        if isinstance(data, list):
            return data, f"findings file: {args.findings}"
        raise ValueError(f"{args.findings}: expected a list of findings or a run_sast result object")

    # Live: import the runner and scan the corpus. The runner degrades on its own if
    # semgrep is absent (semgrep -> regex fallback), so this path never hard-requires it.
    tools_dir = os.path.join(_REPO, "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    try:
        import sast_runner  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "could not import tools/sast_runner.py; pass --findings <json> instead"
        ) from exc
    result = sast_runner.run_sast(args.target)
    engine = result.get("summary", {}).get("engine_used", "unknown")
    return result.get("findings", []), f"sast_runner.run_sast ({engine})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score SAST findings against the white-box code corpus ground truth."
    )
    parser.add_argument(
        "--findings",
        help="Pre-computed findings JSON (a list, or a run_sast result with a 'findings' key). "
        "When omitted, tools/sast_runner.run_sast scans --target live.",
    )
    parser.add_argument(
        "--target",
        default=CORPUS_ROOT,
        help="Path to scan when running live (default: the code_corpus directory).",
    )
    parser.add_argument(
        "--ground-truth",
        default=DEFAULT_GROUND_TRUTH,
        help="Path to ground_truth.json (default: bundled).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the scored result as JSON.")
    parser.add_argument(
        "--min-f1",
        type=float,
        default=None,
        help="If set, exit non-zero when overall F1 is below this threshold (CI gate).",
    )
    args = parser.parse_args(argv)

    try:
        gt = load_ground_truth(args.ground_truth)
        findings, source = _gather_findings(args)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    scored = score(findings, gt)

    if args.json:
        print(json.dumps(scored, indent=2, sort_keys=True))
    else:
        print(f"[*] findings source: {source}")
        print(format_report(scored))

    if args.min_f1 is not None and scored["overall"]["f1"] < args.min_f1:
        print(
            f"\n[-] overall F1 {scored['overall']['f1']:.2f} < threshold {args.min_f1:.2f}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
