"""Tests for tools/sast_runner.py — the SAST engine, fully offline.

semgrep is NEVER required. The parser is driven off a committed fixture (a real
`semgrep --json` sample, inline below AND mirrored by the bundled
tools/fixtures/semgrep_sample.json), and the fallback path is forced
deterministically — either by injecting an engines= dict into run_sast() or by
monkeypatching shutil.which / detect_engines so the test result does NOT depend on
whether semgrep happens to be on the host's PATH. stdlib + pytest only.

Covers:
  * normalize()        — maps the semgrep envelope (and a bare list) to the schema
  * map_rule_to_class()— classifies common rule ids into vuln classes
  * fingerprint()      — stable across runs, dedups duplicates, splits distinct hits
  * regex_fallback()   — finds an obvious sink in a tiny temp .py file, tags
                         tool='regex-fallback'
  * run_sast()         — returns the summary structure and, with semgrep forced
                         absent, uses the fallback without crashing (exits cleanly)
"""

import json
import os
import sys

import pytest

# Make tools/ importable (mirrors tests/conftest.py; kept self-contained so this
# module imports cleanly even if run in isolation).
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_ROOT = os.path.join(REPO_ROOT, "tools")
for _path in (REPO_ROOT, TOOLS_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import sast_runner as sast


# --- Committed offline fixture ---------------------------------------------------
# Inline `semgrep --json` sample: one result per common vuln class. The bundled
# tools/fixtures/semgrep_sample.json carries the same shape; a dedicated test below
# asserts the file exists and parses, so we never depend on semgrep to produce it.
SEMGREP_SAMPLE = {
    "version": "1.86.0",
    "results": [
        {
            "check_id": "python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use",
            "path": "app/handlers/run.py",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 60},
            "extra": {
                "message": "Detected subprocess function 'call' with user-controlled input. OS command injection.",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-78"], "category": "security"},
            },
        },
        {
            "check_id": "python.django.security.injection.sql.sql-injection-using-rawsql.sql-injection-using-rawsql",
            "path": "app/models/user.py",
            "start": {"line": 88, "col": 9},
            "end": {"line": 88, "col": 72},
            "extra": {
                "message": "User-controlled data is passed to RawSQL(). This could lead to a SQL injection.",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-89"], "category": "security"},
            },
        },
        {
            "check_id": "javascript.express.security.audit.xss.direct-response-write.direct-response-write",
            "path": "src/routes/profile.js",
            "start": {"line": 17, "col": 3},
            "end": {"line": 17, "col": 45},
            "extra": {
                "message": "Directly writing user input to the HTTP response may result in reflected XSS.",
                "severity": "WARNING",
                "metadata": {"cwe": ["CWE-79"], "category": "security"},
            },
        },
        {
            "check_id": "python.requests.security.ssrf.ssrf-requests-get.ssrf-requests-get",
            "path": "app/handlers/fetch.py",
            "start": {"line": 23, "col": 5},
            "end": {"line": 23, "col": 50},
            "extra": {
                "message": "Data from the request is passed to requests.get() — server-side request forgery (SSRF).",
                "severity": "WARNING",
                "metadata": {"cwe": ["CWE-918"], "category": "security"},
            },
        },
        {
            "check_id": "generic.secrets.security.detected-generic-api-key.detected-generic-api-key",
            "path": "config/settings.py",
            "start": {"line": 4, "col": 1},
            "end": {"line": 4, "col": 55},
            "extra": {
                "message": "Generic API Key detected. Hardcoded credentials should be in a secrets manager.",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-798"], "category": "security"},
            },
        },
        {
            "check_id": "python.lang.security.deserialization.pickle.avoid-pickle",
            "path": "app/cache.py",
            "start": {"line": 11, "col": 12},
            "end": {"line": 11, "col": 40},
            "extra": {
                "message": "Avoid using pickle, which deserializes and executes arbitrary code. RCE on untrusted input.",
                "severity": "INFO",
                "metadata": {"cwe": ["CWE-502"], "category": "security"},
            },
        },
    ],
    "errors": [],
    "paths": {"scanned": ["app", "src", "config"]},
}

SCHEMA_FIELDS = {
    "tool", "rule_id", "path", "line", "severity", "vuln_class", "message", "fingerprint",
}


@pytest.fixture
def sample():
    """Fresh deep copy of the inline semgrep envelope per test."""
    return json.loads(json.dumps(SEMGREP_SAMPLE))


# --- normalize() -----------------------------------------------------------------

def test_normalize_maps_envelope_to_schema(sample):
    findings = sast.normalize(sample)

    # One finding per result, every schema field present on each.
    assert len(findings) == len(sample["results"])
    for f in findings:
        assert set(f.keys()) == SCHEMA_FIELDS
        assert f["tool"] == "semgrep"
        assert isinstance(f["line"], int)
        assert f["severity"] in ("critical", "high", "medium", "low", "info")
        assert f["vuln_class"] in sast.VULN_CLASSES
        assert isinstance(f["fingerprint"], str) and len(f["fingerprint"]) == 12


def test_normalize_field_values_from_first_result(sample):
    findings = sast.normalize(sample)
    by_path = {f["path"]: f for f in findings}

    cmd = by_path["app/handlers/run.py"]
    assert cmd["rule_id"].endswith("dangerous-subprocess-use")
    assert cmd["line"] == 42
    assert cmd["severity"] == "high"          # semgrep ERROR -> high
    assert cmd["vuln_class"] == "cmd-injection"
    assert "command injection" in cmd["message"].lower()


def test_normalize_severity_mapping(sample):
    sev = {f["path"]: f["severity"] for f in sast.normalize(sample)}
    assert sev["app/handlers/run.py"] == "high"      # ERROR
    assert sev["src/routes/profile.js"] == "medium"  # WARNING
    assert sev["app/cache.py"] == "low"              # INFO


def test_normalize_accepts_bare_list(sample):
    # normalize() accepts the bare results list, not just the {"results": [...]} envelope.
    bare = sample["results"]
    assert sast.normalize(bare) == sast.normalize(sample)


def test_normalize_handles_empty_and_garbage():
    assert sast.normalize({"results": []}) == []
    assert sast.normalize([]) == []
    assert sast.normalize("not a dict or list") == []  # degrades, never raises
    # Malformed individual results are skipped, not fatal.
    mixed = {"results": [{"check_id": "x.y", "path": "a.py", "start": {"line": 1},
                          "extra": {"severity": "ERROR", "message": "m"}},
                         "garbage", 42, None]}
    out = sast.normalize(mixed)
    assert len(out) == 1
    assert out[0]["path"] == "a.py"


def test_normalize_missing_line_defaults_zero():
    out = sast.normalize({"results": [{"check_id": "r", "path": "p.py", "extra": {}}]})
    assert len(out) == 1
    assert out[0]["line"] == 0
    assert out[0]["severity"] == "info"  # unknown/blank severity degrades to info


# --- map_rule_to_class() ---------------------------------------------------------

@pytest.mark.parametrize("rule_id,message,expected", [
    ("python.django.security.injection.sql.sql-injection-using-rawsql", "RawSQL", "sqli"),
    ("python.lang.security.audit.dangerous-subprocess-use", "subprocess shell=True", "cmd-injection"),
    ("javascript.express.security.audit.xss.direct-response-write", "reflected XSS", "xss"),
    ("python.requests.security.ssrf.ssrf-requests-get", "SSRF", "ssrf"),
    ("generic.secrets.security.detected-generic-api-key", "hardcoded credentials", "secret"),
    ("python.lang.security.deserialization.pickle.avoid-pickle", "pickle RCE", "deserialization"),
    ("java.lang.security.audit.crypto.weak-hash.use-of-md5", "weak hash MD5", "crypto"),
    ("some.path.traversal.rule", "directory traversal", "path-traversal"),
    ("flask.ssti.jinja-template-injection", "server-side template injection", "ssti"),
    ("api.broken-object-level-authorization", "IDOR / BOLA", "idor"),
])
def test_map_rule_to_class_known(rule_id, message, expected):
    assert sast.map_rule_to_class(rule_id, message) == expected


def test_map_rule_to_class_via_cwe_number():
    # CWE numbers in the rule id / message route too.
    assert sast.map_rule_to_class("vendor.rule.cwe-89", "") == "sqli"
    assert sast.map_rule_to_class("", "CWE-918 detected") == "ssrf"


def test_map_rule_to_class_unknown_is_other():
    assert sast.map_rule_to_class("vendor.style.no-trailing-whitespace", "cosmetic") == "other"
    assert sast.map_rule_to_class("", "") == "other"


def test_normalize_classifies_all_sample_classes(sample):
    classes = {f["vuln_class"] for f in sast.normalize(sample)}
    assert {"cmd-injection", "sqli", "xss", "ssrf", "secret", "deserialization"} <= classes


# --- fingerprint() ---------------------------------------------------------------

def test_fingerprint_is_stable_and_12_hex():
    f = {"path": "a/b.py", "rule_id": "rule.x", "line": 10}
    fp1 = sast.fingerprint(f)
    fp2 = sast.fingerprint(dict(f))  # different object, same content
    assert fp1 == fp2
    assert len(fp1) == 12
    assert all(c in "0123456789abcdef" for c in fp1)


def test_fingerprint_ignores_severity_and_message():
    # Re-scanning unchanged code (same path/rule/line) must yield the same id even if
    # severity/message differ — that's what makes baselining work.
    a = {"path": "a.py", "rule_id": "r", "line": 5, "severity": "high", "message": "x"}
    b = {"path": "a.py", "rule_id": "r", "line": 5, "severity": "low", "message": "y"}
    assert sast.fingerprint(a) == sast.fingerprint(b)


def test_fingerprint_distinguishes_path_rule_line():
    base = {"path": "a.py", "rule_id": "r", "line": 5}
    assert sast.fingerprint(base) != sast.fingerprint({**base, "path": "b.py"})
    assert sast.fingerprint(base) != sast.fingerprint({**base, "rule_id": "r2"})
    assert sast.fingerprint(base) != sast.fingerprint({**base, "line": 6})


def test_fingerprint_dedups_duplicate_findings(sample):
    # Two identical results (same path/rule/line) collapse to one fingerprint;
    # downstream dedup keys on fingerprint.
    dup_env = {"results": [sample["results"][0], json.loads(json.dumps(sample["results"][0]))]}
    findings = sast.normalize(dup_env)
    assert len(findings) == 2  # normalize() does not itself dedup
    assert findings[0]["fingerprint"] == findings[1]["fingerprint"]
    assert len({f["fingerprint"] for f in findings}) == 1


def test_fingerprint_keeps_distinct_lines_separate(sample):
    r0 = sample["results"][0]
    r1 = json.loads(json.dumps(r0))
    r1["start"]["line"] = r0["start"]["line"] + 1  # same rule+file, different line
    findings = sast.normalize({"results": [r0, r1]})
    assert findings[0]["fingerprint"] != findings[1]["fingerprint"]


def test_normalize_full_sample_all_fingerprints_unique(sample):
    fps = [f["fingerprint"] for f in sast.normalize(sample)]
    assert len(fps) == len(set(fps))  # all 6 distinct (different files/lines)


# --- regex_fallback() ------------------------------------------------------------

def test_regex_fallback_finds_obvious_sink_in_temp_py(tmp_path):
    src = tmp_path / "vuln.py"
    src.write_text(
        "import os\n"
        "def handler(req):\n"
        "    os.system('ping ' + req['host'])\n"  # obvious cmd-injection sink (line 3)
    )
    findings = sast.regex_fallback(str(src))

    assert findings, "expected at least one finding for the os.system sink"
    hit = next(f for f in findings if f["vuln_class"] == "cmd-injection")
    assert hit["tool"] == "regex-fallback"
    assert hit["line"] == 3
    assert hit["rule_id"] == "regex-fallback.cmd-injection"
    assert hit["severity"] == "high"
    assert set(hit.keys()) == SCHEMA_FIELDS
    assert hit["fingerprint"] == sast.fingerprint(hit)


def test_regex_fallback_tags_every_finding_regex_fallback(tmp_path):
    src = tmp_path / "many.py"
    src.write_text(
        "import pickle, hashlib\n"
        "data = pickle.loads(blob)\n"           # deserialization
        "h = hashlib.md5(x).hexdigest()\n"      # crypto (weak hash)
    )
    findings = sast.regex_fallback(str(src))
    assert findings
    assert all(f["tool"] == "regex-fallback" for f in findings)
    assert all(f["rule_id"].startswith("regex-fallback.") for f in findings)
    classes = {f["vuln_class"] for f in findings}
    assert "deserialization" in classes


def test_regex_fallback_walks_directory(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("os.system(cmd)\n")
    (tmp_path / "pkg" / "b.js").write_text("el.innerHTML = userInput\n")
    findings = sast.regex_fallback(str(tmp_path))
    paths = {f["path"] for f in findings}
    # Paths are relative to the scanned root.
    assert any(p.endswith("a.py") for p in paths)
    assert any(p.endswith("b.js") for p in paths)
    assert all(not os.path.isabs(p) for p in paths)


def test_regex_fallback_skips_vendor_dirs(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("el.innerHTML = x\n")
    (tmp_path / "app.py").write_text("os.system(cmd)\n")
    findings = sast.regex_fallback(str(tmp_path))
    assert findings  # the app.py hit
    assert not any("node_modules" in f["path"] for f in findings)


def test_regex_fallback_clean_file_no_findings(tmp_path):
    src = tmp_path / "clean.py"
    src.write_text("def add(a, b):\n    return a + b\n")
    assert sast.regex_fallback(str(src)) == []


# --- run_sast() ------------------------------------------------------------------

def _force_no_semgrep(monkeypatch):
    """Deterministically remove every known engine from PATH for this test, so the
    result never depends on whether semgrep is actually installed on the host."""
    monkeypatch.setattr(sast.shutil, "which", lambda name: None)


def test_run_sast_summary_structure_fallback(tmp_path, monkeypatch):
    _force_no_semgrep(monkeypatch)
    (tmp_path / "app.py").write_text("os.system('ping ' + host)\n")

    result = sast.run_sast(str(tmp_path))  # engines=None -> detect_engines() -> no semgrep

    assert set(result.keys()) >= {"summary", "findings"}
    summary = result["summary"]
    assert set(summary.keys()) == {"by_severity", "by_class", "total", "engine_used"}
    assert summary["engine_used"] == "regex-fallback"
    assert summary["total"] == len(result["findings"])
    assert isinstance(summary["by_severity"], dict)
    assert isinstance(summary["by_class"], dict)
    # by_severity / by_class counts sum to the total.
    assert sum(summary["by_severity"].values()) == summary["total"]
    assert sum(summary["by_class"].values()) == summary["total"]
    # We planted a sink, so the fallback should have found it.
    assert summary["total"] >= 1
    assert all(f["tool"] == "regex-fallback" for f in result["findings"])


def test_run_sast_engines_injection_forces_fallback(tmp_path):
    # The engines= param is injectable: pass a detect_engines()-shaped dict with
    # semgrep False to force the fallback path WITHOUT touching PATH.
    (tmp_path / "x.py").write_text("subprocess.call(cmd, shell=True)\n")
    engines = {"semgrep": False, "bandit": False, "njsscan": False, "gosec": False}
    result = sast.run_sast(str(tmp_path), engines=engines)
    assert result["summary"]["engine_used"] == "regex-fallback"
    assert result["summary"]["total"] >= 1


def test_run_sast_empty_dir_does_not_crash(tmp_path, monkeypatch):
    _force_no_semgrep(monkeypatch)
    empty = tmp_path / "empty"
    empty.mkdir()
    result = sast.run_sast(str(empty))
    assert result["summary"]["total"] == 0
    assert result["summary"]["engine_used"] == "regex-fallback"
    assert result["findings"] == []


def test_run_sast_findings_sorted_worst_first(tmp_path, monkeypatch):
    _force_no_semgrep(monkeypatch)
    src = tmp_path / "mixed.py"
    src.write_text(
        "h = hashlib.md5(x)\n"          # crypto -> low
        "os.system('ping ' + host)\n"   # cmd-injection -> high
    )
    result = sast.run_sast(str(tmp_path))
    sevs = [f["severity"] for f in result["findings"]]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    assert sevs == sorted(sevs, key=lambda s: order[s])  # worst first
    assert sevs[0] == "high"


def test_run_sast_writes_out_path(tmp_path, monkeypatch):
    _force_no_semgrep(monkeypatch)
    target = tmp_path / "code"
    target.mkdir()
    (target / "app.py").write_text("os.system(cmd)\n")
    out = tmp_path / "out"

    result = sast.run_sast(str(target), out_dir=str(out))

    assert "out_path" in result
    out_path = result["out_path"]
    assert os.path.isfile(out_path)
    # Lands under <out>/findings/sast/<ts>/sast.json
    assert out_path.startswith(str(out))
    assert os.path.join("findings", "sast") in out_path
    assert os.path.basename(out_path) == "sast.json"
    with open(out_path, encoding="utf-8") as fh:
        on_disk = json.load(fh)
    assert on_disk["summary"]["engine_used"] == "regex-fallback"
    assert on_disk["summary"]["total"] == result["summary"]["total"]


def test_run_sast_no_out_dir_omits_out_path(tmp_path, monkeypatch):
    _force_no_semgrep(monkeypatch)
    (tmp_path / "app.py").write_text("os.system(cmd)\n")
    result = sast.run_sast(str(tmp_path))
    assert "out_path" not in result


# --- detect_engines() ------------------------------------------------------------

def test_detect_engines_shape_and_pure_path_probe(monkeypatch):
    # Never executes anything — pure shutil.which probe over KNOWN_ENGINES.
    monkeypatch.setattr(sast.shutil, "which", lambda name: "/usr/bin/" + name)
    detected = sast.detect_engines()
    assert set(detected.keys()) == set(sast.KNOWN_ENGINES)
    assert all(v is True for v in detected.values())

    monkeypatch.setattr(sast.shutil, "which", lambda name: None)
    detected = sast.detect_engines()
    assert all(v is False for v in detected.values())


# --- bundled fixture parity ------------------------------------------------------

def test_bundled_fixture_exists_and_normalizes():
    # The committed tools/fixtures/semgrep_sample.json is real semgrep --json shape
    # and drives normalize() with no semgrep installed.
    assert os.path.isfile(sast.BUNDLED_SEMGREP_SAMPLE)
    with open(sast.BUNDLED_SEMGREP_SAMPLE, encoding="utf-8") as fh:
        raw = json.load(fh)
    findings = sast.normalize(raw)
    assert findings
    for f in findings:
        assert set(f.keys()) == SCHEMA_FIELDS
        assert f["tool"] == "semgrep"
    classes = {f["vuln_class"] for f in findings}
    assert {"cmd-injection", "sqli", "xss", "ssrf", "secret", "deserialization"} <= classes
