"""Engine-independent unit tests for the white-box SAST scorer's metric math.

Target under test: eval/code_corpus/run_eval_code.py::score(findings, ground_truth).

This file validates the SCORER ITSELF, not any SAST engine: it feeds hand-built
synthetic findings against a known ground truth and asserts the precision / recall /
F1 arithmetic. No semgrep, no sast_runner, no network — stdlib + pytest only.

Three core properties (the deliverable the task asks for):
  * findings that EXACTLY match the ground truth      -> precision == recall == f1 == 1.0
  * findings with an extra (spurious) hit             -> precision < 1.0
  * findings missing a labeled bug                    -> recall    < 1.0

Ground truth: prefer the committed eval/code_corpus/ground_truth.json when present
(so the test exercises the real corpus shape); otherwise fall back to a tiny inline
ground truth so the test still runs standalone.
"""

import importlib.util
import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CORPUS_DIR = os.path.join(REPO_ROOT, "eval", "code_corpus")
RUN_EVAL_PATH = os.path.join(CORPUS_DIR, "run_eval_code.py")
GROUND_TRUTH_PATH = os.path.join(CORPUS_DIR, "ground_truth.json")

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _load_run_eval():
    """Import run_eval_code.py from its explicit path (eval/ is not a package)."""
    spec = importlib.util.spec_from_file_location("run_eval_code", RUN_EVAL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rec = _load_run_eval()


# --- inline fallback ground truth ------------------------------------------------

def _inline_ground_truth():
    """A tiny self-contained ground truth used when ground_truth.json is absent.

    Two positive (vulnerable) labels and two negative (safe) files, drawn from the
    corpus taxonomy so canonicalize_class() treats the synthetic findings as in-scope.
    """
    return {
        "schema_version": 1,
        "line_tolerance": 2,
        "vuln_classes": ["sqli", "xss"],
        "expected": [
            {"file": "vulnerable/sqli.py", "line": 12, "vuln_class": "sqli"},
            {"file": "vulnerable/xss.py", "line": 12, "vuln_class": "xss"},
        ],
        "negatives": [
            {"file": "safe/sqli.py", "vuln_class": "sqli"},
            {"file": "safe/xss.py", "vuln_class": "xss"},
        ],
    }


@pytest.fixture
def gt():
    """Real corpus ground truth if committed, else the inline tiny one."""
    if os.path.isfile(GROUND_TRUTH_PATH):
        return rec.load_ground_truth(GROUND_TRUTH_PATH)
    return _inline_ground_truth()


def _perfect_findings(ground_truth):
    """Build one finding per expected label that lands exactly on its sink.

    Engine-independent: uses the corpus's own vuln_class strings and exact lines,
    so a correct scorer must return a perfect score.
    """
    return [
        {
            "file": exp["file"],
            "line": int(exp.get("line", 0) or 0),
            "vuln_class": exp["vuln_class"],
        }
        for exp in ground_truth["expected"]
    ]


# --- property 1: exact match -> perfect score ------------------------------------

def test_exact_match_scores_perfect(gt):
    findings = _perfect_findings(gt)
    scored = rec.score(findings, gt)
    o = scored["overall"]

    assert o["tp"] == len(gt["expected"])
    assert o["fp"] == 0
    assert o["fn"] == 0
    assert o["precision"] == 1.0
    assert o["recall"] == 1.0
    assert o["f1"] == 1.0
    # Every safe file stayed clean.
    assert scored["negatives"]["violated"] == 0
    assert scored["negatives"]["clean"] == scored["negatives"]["files"]


# --- property 2: a false positive drops precision below 1 ------------------------

def test_false_positive_drops_precision(gt):
    # All true labels matched (recall stays 1.0) PLUS one spurious hit on a SAFE file,
    # which the scorer must count as a false positive (any finding on a negative file).
    safe_file = rec._corpus_rel(gt["negatives"][0]["file"])
    safe_class = gt["negatives"][0]["vuln_class"]

    findings = _perfect_findings(gt) + [
        {"file": safe_file, "line": 9, "vuln_class": safe_class},
    ]
    scored = rec.score(findings, gt)
    o = scored["overall"]

    assert o["fp"] >= 1
    assert o["precision"] < 1.0
    # The extra hit is a false positive, not a missed label: recall is untouched.
    assert o["recall"] == 1.0
    # f1 < 1.0 follows from precision < 1.0 with recall == 1.0.
    assert o["f1"] < 1.0
    # precision == tp / (tp + fp): confirm the exact arithmetic, not just the inequality.
    expected_precision = round(o["tp"] / (o["tp"] + o["fp"]), 4)
    assert o["precision"] == expected_precision
    assert scored["negatives"]["violated"] >= 1


# --- property 3: a missing finding drops recall below 1 --------------------------

def test_missing_finding_drops_recall(gt):
    # Report every expected label EXCEPT one -> that label is a false negative.
    findings = _perfect_findings(gt)[1:]  # drop the first expected label's finding
    scored = rec.score(findings, gt)
    o = scored["overall"]

    assert o["fn"] >= 1
    assert o["recall"] < 1.0
    # Everything we did report was correct, so precision is unaffected.
    assert o["fp"] == 0
    assert o["precision"] == 1.0
    assert o["f1"] < 1.0
    # recall == tp / (tp + fn): confirm the exact arithmetic.
    expected_recall = round(o["tp"] / (o["tp"] + o["fn"]), 4)
    assert o["recall"] == expected_recall


# --- direct check of the precision/recall/f1 helper ------------------------------

def test_prf_arithmetic_is_correct():
    # Undefined (no predictions, no labels) -> all zero, never a ZeroDivisionError.
    assert rec._prf(0, 0, 0) == {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    # Perfect.
    assert rec._prf(2, 0, 0) == {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    # One FP: precision 0.5, recall 1.0, F1 = 2*.5*1/(.5+1) = 0.6667.
    fp_case = rec._prf(1, 1, 0)
    assert fp_case["precision"] == 0.5
    assert fp_case["recall"] == 1.0
    assert fp_case["f1"] == pytest.approx(0.6667, abs=1e-4)
    # One FN: precision 1.0, recall 0.5, symmetric F1.
    fn_case = rec._prf(1, 0, 1)
    assert fn_case["precision"] == 1.0
    assert fn_case["recall"] == 0.5
    assert fn_case["f1"] == pytest.approx(0.6667, abs=1e-4)


# --- empty input is all false negatives, no crash --------------------------------

def test_empty_findings_is_all_false_negatives(gt):
    scored = rec.score([], gt)
    o = scored["overall"]
    assert o["tp"] == 0
    assert o["fn"] == len(gt["expected"])
    assert o["precision"] == 0.0
    assert o["recall"] == 0.0
    assert o["f1"] == 0.0
    # Nothing was flagged, so no safe file was violated.
    assert scored["negatives"]["violated"] == 0
