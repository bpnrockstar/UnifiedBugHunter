"""Tests for eval/code_corpus/run_eval_code.py — the white-box SAST scorer.

Fully offline and semgrep-free: the scorer is driven from the committed
findings fixture (eval/code_corpus/findings_sample.json) and hand-built finding
lists, and the sast_runner fallback path is exercised with semgrep forced absent.
NEVER requires semgrep / osv-scanner to be installed. stdlib + pytest only.
"""

import importlib.util
import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_ROOT = os.path.join(REPO_ROOT, "tools")
CORPUS_DIR = os.path.join(REPO_ROOT, "eval", "code_corpus")
for _path in (REPO_ROOT, TOOLS_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)


def _load_module(name, path):
    """Import a module from an explicit file path (eval/ is not a package)."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rec = _load_module("run_eval_code", os.path.join(CORPUS_DIR, "run_eval_code.py"))

GROUND_TRUTH_PATH = os.path.join(CORPUS_DIR, "ground_truth.json")
FINDINGS_SAMPLE_PATH = os.path.join(CORPUS_DIR, "findings_sample.json")


@pytest.fixture
def gt():
    return rec.load_ground_truth(GROUND_TRUTH_PATH)


# --- ground truth ----------------------------------------------------------------

def test_ground_truth_loads_and_is_consistent(gt):
    assert gt["schema_version"] == 1
    assert gt["expected"], "ground truth must have positive cases"
    assert gt["negatives"], "ground truth must have negative (safe) cases"
    # Every expected/negative class is in the declared taxonomy.
    classes = set(gt["vuln_classes"])
    for e in gt["expected"]:
        assert e["vuln_class"] in classes
        assert e["vuln_class"] in rec.CORPUS_CLASSES
    for n in gt["negatives"]:
        assert n["vuln_class"] in classes


def test_every_vuln_class_has_a_positive_and_a_negative(gt):
    pos = {e["vuln_class"] for e in gt["expected"]}
    neg = {n["vuln_class"] for n in gt["negatives"]}
    for cls in rec.CORPUS_CLASSES:
        assert cls in pos, f"missing positive case for {cls}"
        assert cls in neg, f"missing negative (safe) case for {cls}"


def test_referenced_corpus_files_exist(gt):
    for entry in gt["expected"] + gt["negatives"]:
        full = os.path.join(CORPUS_DIR, entry["file"])
        assert os.path.isfile(full), f"missing corpus file: {entry['file']}"


def test_vulnerable_files_carry_the_marker(gt):
    marker = "INTENTIONALLY VULNERABLE"
    for e in gt["expected"]:
        full = os.path.join(CORPUS_DIR, e["file"])
        with open(full, encoding="utf-8") as fh:
            assert marker in fh.read(), f"{e['file']} missing the vulnerable marker"


# --- canonicalization ------------------------------------------------------------

def test_canonicalize_direct_class():
    assert rec.canonicalize_class({"vuln_class": "sqli"}) == "sqli"


def test_canonicalize_sast_runner_aliases():
    # sast_runner uses coarser labels than the corpus taxonomy.
    assert rec.canonicalize_class({"vuln_class": "cmd-injection"}) == "command-injection"
    assert rec.canonicalize_class({"vuln_class": "deserialization"}) == "insecure-deserialization"
    assert rec.canonicalize_class({"vuln_class": "crypto"}) == "weak-crypto"
    assert rec.canonicalize_class({"vuln_class": "secret"}) == "hardcoded-secret"


def test_canonicalize_jwt_recovered_from_rule_id_when_class_is_other():
    # semgrep routes jwt-alg-none through sast_runner as 'other'; the rule id saves it.
    f = {"vuln_class": "other", "rule_id": "python.jwt.security.jwt-none-alg.jwt-python-none-alg"}
    assert rec.canonicalize_class(f) == "jwt-alg-none"


def test_canonicalize_unroutable_returns_none():
    assert rec.canonicalize_class({"vuln_class": "other", "rule_id": "some.unrelated.rule"}) is None


def test_finding_file_accepts_path_or_file_key():
    assert rec.finding_file({"path": "a/b.py"}) == "a/b.py"
    assert rec.finding_file({"file": "c/d.py"}) == "c/d.py"


# --- scoring: the committed fixture ----------------------------------------------

def test_committed_fixture_scores_perfectly(gt):
    with open(FINDINGS_SAMPLE_PATH, encoding="utf-8") as fh:
        findings = json.load(fh)
    scored = rec.score(findings, gt)
    o = scored["overall"]
    assert o["tp"] == len(gt["expected"])
    assert o["fp"] == 0
    assert o["fn"] == 0
    assert o["precision"] == 1.0
    assert o["recall"] == 1.0
    assert o["f1"] == 1.0
    assert scored["negatives"]["violated"] == 0
    assert scored["negatives"]["clean"] == scored["negatives"]["files"]


# --- scoring: synthetic cases ----------------------------------------------------

def _tiny_gt():
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


def test_line_tolerance_allows_small_drift():
    gt = _tiny_gt()
    findings = [
        {"path": "vulnerable/sqli.py", "line": 13, "vuln_class": "sqli"},   # +1, within tol
        {"path": "vulnerable/xss.py", "line": 12, "vuln_class": "xss"},
    ]
    scored = rec.score(findings, gt)
    assert scored["overall"]["tp"] == 2
    assert scored["overall"]["fn"] == 0


def test_line_outside_tolerance_is_a_miss():
    gt = _tiny_gt()
    findings = [{"path": "vulnerable/sqli.py", "line": 20, "vuln_class": "sqli"}]  # +8
    scored = rec.score(findings, gt)
    assert scored["per_class"]["sqli"]["tp"] == 0
    assert scored["per_class"]["sqli"]["fn"] == 1


def test_finding_on_safe_file_is_a_false_positive():
    gt = _tiny_gt()
    findings = [{"path": "safe/sqli.py", "line": 9, "vuln_class": "sqli"}]
    scored = rec.score(findings, gt)
    assert scored["negatives"]["violated"] == 1
    assert scored["overall"]["fp"] == 1
    assert scored["per_class"]["sqli"]["fp"] == 1


def test_duplicate_rules_on_one_sink_count_once():
    gt = _tiny_gt()
    # Three rules fire for the same XSS bug on the same line; that is ONE finding.
    findings = [
        {"path": "vulnerable/xss.py", "line": 12, "vuln_class": "xss", "rule_id": "r1"},
        {"path": "vulnerable/xss.py", "line": 12, "vuln_class": "xss", "rule_id": "r2"},
        {"path": "vulnerable/xss.py", "line": 13, "vuln_class": "xss", "rule_id": "r3"},
    ]
    scored = rec.score(findings, gt)
    assert scored["per_class"]["xss"]["tp"] == 1
    assert scored["per_class"]["xss"]["fp"] == 0  # duplicates suppressed, not penalized


def test_wrong_class_on_vuln_file_is_ignored_not_penalized():
    gt = _tiny_gt()
    # A real but unlabeled class on a vuln file: neither TP nor FP (out of taxonomy here).
    findings = [{"path": "vulnerable/sqli.py", "line": 12, "vuln_class": "ssrf"}]
    scored = rec.score(findings, gt)
    assert scored["per_class"]["sqli"]["fn"] == 1   # sqli still missed
    assert scored["overall"]["fp"] == 0             # the ssrf hit is ignored


def test_same_class_wrong_line_on_vuln_file_is_a_false_positive():
    gt = _tiny_gt()
    findings = [
        {"path": "vulnerable/sqli.py", "line": 12, "vuln_class": "sqli"},  # TP
        {"path": "vulnerable/sqli.py", "line": 40, "vuln_class": "sqli"},  # far away -> FP
    ]
    scored = rec.score(findings, gt)
    assert scored["per_class"]["sqli"]["tp"] == 1
    assert scored["per_class"]["sqli"]["fp"] == 1


def test_empty_findings_is_all_false_negatives():
    gt = _tiny_gt()
    scored = rec.score([], gt)
    assert scored["overall"]["tp"] == 0
    assert scored["overall"]["fn"] == len(gt["expected"])
    assert scored["overall"]["precision"] == 0.0
    assert scored["overall"]["recall"] == 0.0
    assert scored["negatives"]["violated"] == 0  # nothing flagged -> safe files clean


def test_prf_math():
    assert rec._prf(0, 0, 0) == {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    out = rec._prf(1, 1, 0)  # precision .5, recall 1.0 -> f1 .6667
    assert out["precision"] == 0.5
    assert out["recall"] == 1.0
    assert out["f1"] == pytest.approx(0.6667, abs=1e-4)


def test_format_report_runs(gt):
    with open(FINDINGS_SAMPLE_PATH, encoding="utf-8") as fh:
        findings = json.load(fh)
    text = rec.format_report(rec.score(findings, gt))
    assert "OVERALL" in text
    assert "Negative cases" in text


# --- sast_runner: graceful degradation (semgrep forced absent) -------------------

def test_sast_runner_degrades_to_regex_when_semgrep_absent(monkeypatch):
    import sast_runner as sr

    # Force every engine off, mimicking a host with no SAST binary installed.
    monkeypatch.setattr(sr, "detect_engines", lambda: {e: False for e in sr.KNOWN_ENGINES})
    result = sr.run_sast(os.path.join(CORPUS_DIR, "vulnerable"))
    assert result["summary"]["engine_used"] == "regex-fallback"
    # The fallback still finds real sinks (e.g. the pickle / md5 / shell=True sinks).
    classes = {f["vuln_class"] for f in result["findings"]}
    assert classes, "regex fallback produced no findings on the vulnerable corpus"


def test_regex_fallback_findings_are_scorable(monkeypatch, gt):
    import sast_runner as sr

    monkeypatch.setattr(sr, "detect_engines", lambda: {e: False for e in sr.KNOWN_ENGINES})
    result = sr.run_sast(CORPUS_DIR)
    # The scorer must accept the fallback output and produce a coherent confusion summary.
    scored = rec.score(result["findings"], gt)
    o = scored["overall"]
    assert o["tp"] + o["fn"] == len(gt["expected"])  # every label is TP or FN
    assert o["tp"] >= 1  # the fallback catches at least one labeled sink


def test_run_sast_does_not_require_semgrep_import():
    # sast_runner must import and run with stdlib only — semgrep is a binary, not an import.
    import sast_runner as sr

    assert "semgrep" not in sys.modules or sys.modules.get("semgrep") is None
    # detect_engines is a pure PATH probe; calling it never raises.
    detected = sr.detect_engines()
    assert set(detected) == set(sr.KNOWN_ENGINES)
