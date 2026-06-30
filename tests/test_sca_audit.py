"""Tests for tools/sca_audit.py — software-composition analysis over lockfiles.

Fully offline: drives the importable functions against the committed fixture
(tools/fixtures/osv_scanner_sample.json) and the no-scanner fallback path. The
osv-scanner / pip-audit binaries are NEVER required — detect_scanners() is the
only thing that touches PATH, and it is monkeypatched where presence matters.
stdlib + pytest only.
"""

import json
import os
import sys

import pytest

# Make tools/ importable (mirrors tests/conftest.py, kept self-contained so this
# module imports cleanly even if run in isolation).
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_ROOT = os.path.join(REPO_ROOT, "tools")
for _path in (REPO_ROOT, TOOLS_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import sca_audit as sca


# --- find_lockfiles --------------------------------------------------------------

def _touch(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{}\n")


def test_find_lockfiles_detects_each_ecosystem(tmp_path):
    fixtures = {
        "package-lock.json": "npm",
        "yarn.lock":         "npm",
        "pnpm-lock.yaml":    "npm",
        "requirements.txt":  "PyPI",
        "poetry.lock":       "PyPI",
        "Pipfile.lock":      "PyPI",
        "go.sum":            "Go",
        "Cargo.lock":        "crates.io",
        "Gemfile.lock":      "RubyGems",
        "composer.lock":     "Packagist",
    }
    for name in fixtures:
        _touch(str(tmp_path / name))

    found = sca.find_lockfiles(str(tmp_path))
    by_name = {os.path.basename(f["file"]): f["ecosystem"] for f in found}
    assert by_name == fixtures


def test_find_lockfiles_skips_node_modules_and_vendor(tmp_path):
    _touch(str(tmp_path / "package-lock.json"))
    _touch(str(tmp_path / "node_modules" / "dep" / "package-lock.json"))
    _touch(str(tmp_path / "vendor" / "pkg" / "Gemfile.lock"))
    _touch(str(tmp_path / ".git" / "Cargo.lock"))

    found = sca.find_lockfiles(str(tmp_path))
    files = [f["file"] for f in found]
    assert len(found) == 1
    assert files[0].endswith("package-lock.json")
    assert "node_modules" not in files[0]


def test_find_lockfiles_accepts_single_file(tmp_path):
    p = tmp_path / "Cargo.lock"
    _touch(str(p))
    found = sca.find_lockfiles(str(p))
    assert found == [{"ecosystem": "crates.io", "file": str(p)}]


def test_find_lockfiles_ignores_unknown_files(tmp_path):
    _touch(str(tmp_path / "README.md"))
    _touch(str(tmp_path / "main.py"))
    assert sca.find_lockfiles(str(tmp_path)) == []


def test_find_lockfiles_missing_path_returns_empty():
    assert sca.find_lockfiles("/nonexistent-path-xyz-123") == []
    assert sca.find_lockfiles("") == []


def test_find_lockfiles_returns_absolute_sorted(tmp_path):
    _touch(str(tmp_path / "go.sum"))
    _touch(str(tmp_path / "package-lock.json"))
    found = sca.find_lockfiles(str(tmp_path))
    assert all(os.path.isabs(f["file"]) for f in found)
    # Sorted by (ecosystem, file): Go < npm.
    assert [f["ecosystem"] for f in found] == ["Go", "npm"]


# --- detect_scanners -------------------------------------------------------------

def test_detect_scanners_shape():
    detected = sca.detect_scanners()
    for tool in ("osv-scanner", "pip-audit", "npm", "govulncheck"):
        assert tool in detected
        entry = detected[tool]
        assert set(entry) == {"available", "path", "ecosystems"}
        assert isinstance(entry["available"], bool)
        assert isinstance(entry["ecosystems"], list)


def test_detect_scanners_no_side_effects(monkeypatch):
    # detect_scanners must only consult PATH (shutil.which), never run binaries.
    import subprocess as _sp

    def _boom(*a, **k):
        raise AssertionError("detect_scanners must not invoke subprocess")

    monkeypatch.setattr(_sp, "run", _boom)
    monkeypatch.setattr(_sp, "Popen", _boom)
    sca.detect_scanners()  # must not raise


def test_preferred_scanner_prefers_osv():
    scanners = {
        "osv-scanner": {"available": True, "path": "/x/osv-scanner", "ecosystems": []},
        "pip-audit":   {"available": True, "path": "/x/pip-audit", "ecosystems": []},
    }
    assert sca._preferred_scanner(scanners) == "osv-scanner"


def test_preferred_scanner_falls_back_to_pip_audit():
    scanners = {
        "osv-scanner": {"available": False, "path": None, "ecosystems": []},
        "pip-audit":   {"available": True, "path": "/x/pip-audit", "ecosystems": []},
    }
    assert sca._preferred_scanner(scanners) == "pip-audit"


def test_preferred_scanner_none_when_absent():
    scanners = {
        "osv-scanner": {"available": False, "path": None, "ecosystems": []},
        "pip-audit":   {"available": False, "path": None, "ecosystems": []},
    }
    assert sca._preferred_scanner(scanners) is None


# --- normalize (against committed fixture) ---------------------------------------

@pytest.fixture
def osv_raw():
    return sca.load_osv_file(sca.BUNDLED_OSV_SAMPLE)


def test_load_osv_file_returns_results(osv_raw):
    assert isinstance(osv_raw, list)
    assert osv_raw and "packages" in osv_raw[0]


def test_load_osv_file_invalid_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        sca.load_osv_file(str(p))


def test_normalize_schema(osv_raw):
    advisories = sca.normalize(osv_raw)
    assert advisories, "fixture must yield advisories"
    for adv in advisories:
        assert set(adv) == {
            "ecosystem", "package", "version",
            "vuln_id", "severity", "fixed_version", "summary",
        }
        assert adv["ecosystem"]
        assert adv["package"]
        assert adv["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def test_normalize_prefers_cve_id(osv_raw):
    advisories = sca.normalize(osv_raw)
    # The lodash GHSA-29mw-wpgm-hmr9 advisory aliases CVE-2020-28500.
    lodash = [a for a in advisories if a["package"] == "lodash"]
    assert lodash
    assert any(a["vuln_id"] == "CVE-2020-28500" for a in lodash)


def test_normalize_extracts_fixed_version(osv_raw):
    advisories = sca.normalize(osv_raw)
    lodash = [a for a in advisories if a["package"] == "lodash" and a["vuln_id"] == "CVE-2020-28500"]
    assert lodash
    assert lodash[0]["fixed_version"] == "4.17.21"


def test_normalize_maps_severity_band(osv_raw):
    advisories = sca.normalize(osv_raw)
    # MODERATE in the fixture must normalize to MEDIUM.
    assert any(a["severity"] == "MEDIUM" for a in advisories)


def test_normalize_severity_sorted_most_severe_first(osv_raw):
    advisories = sca.normalize(osv_raw)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    ranks = [order[a["severity"]] for a in advisories]
    assert ranks == sorted(ranks)


def test_normalize_dedups(osv_raw):
    advisories = sca.normalize(osv_raw)
    keys = [(a["ecosystem"], a["package"], a["version"], a["vuln_id"]) for a in advisories]
    assert len(keys) == len(set(keys))


def test_normalize_empty_and_malformed():
    assert sca.normalize([]) == []
    assert sca.normalize(None) == []
    # Malformed entries are skipped, not raised.
    assert sca.normalize([{"packages": [{"package": {}, "vulnerabilities": [None, 5]}]}]) == []


# --- run_sca: no-scanner graceful degradation ------------------------------------

def _no_scanners():
    return {
        "osv-scanner": {"available": False, "path": None, "ecosystems": []},
        "pip-audit":   {"available": False, "path": None, "ecosystems": []},
        "npm":         {"available": False, "path": None, "ecosystems": []},
        "govulncheck": {"available": False, "path": None, "ecosystems": []},
    }


def test_run_sca_no_scanner_with_lockfiles(tmp_path, monkeypatch):
    _touch(str(tmp_path / "package-lock.json"))
    monkeypatch.setattr(sca, "detect_scanners", _no_scanners)

    result = sca.run_sca(str(tmp_path))
    assert result["scanner"] is None
    assert result["scanner_available"] is False
    assert result["advisories"] == []
    assert result["lockfiles"] and result["lockfiles"][0]["ecosystem"] == "npm"
    assert "no scanner installed" in result["note"]
    assert "osv-scanner" in result["note"] and "pip-audit" in result["note"]


def test_run_sca_no_scanner_no_lockfiles(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "detect_scanners", _no_scanners)
    result = sca.run_sca(str(tmp_path))
    assert result["scanner"] is None
    assert result["lockfiles"] == []
    assert "no scanner installed" in result["note"]


def test_run_sca_no_scanner_does_not_invoke_subprocess(tmp_path, monkeypatch):
    _touch(str(tmp_path / "go.sum"))
    monkeypatch.setattr(sca, "detect_scanners", _no_scanners)

    import subprocess as _sp

    def _boom(*a, **k):
        raise AssertionError("run_sca must not run a scanner when none is present")

    monkeypatch.setattr(_sp, "run", _boom)
    result = sca.run_sca(str(tmp_path))  # must not raise
    assert result["scanner"] is None


def test_run_sca_result_schema(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "detect_scanners", _no_scanners)
    result = sca.run_sca(str(tmp_path))
    for key in ("path", "scanner", "scanner_available", "lockfiles", "note", "summary", "advisories"):
        assert key in result
    summary = result["summary"]
    for key in ("total_advisories", "vulnerable_packages", "by_severity"):
        assert key in summary
    assert set(summary["by_severity"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


# --- run_sca: scanner present, fed via run_osv monkeypatch -----------------------

def test_run_sca_with_scanner_normalizes(tmp_path, monkeypatch, osv_raw):
    _touch(str(tmp_path / "package-lock.json"))

    def _osv_present():
        return {
            "osv-scanner": {"available": True, "path": "/x/osv-scanner", "ecosystems": []},
            "pip-audit":   {"available": False, "path": None, "ecosystems": []},
            "npm":         {"available": False, "path": None, "ecosystems": []},
            "govulncheck": {"available": False, "path": None, "ecosystems": []},
        }

    monkeypatch.setattr(sca, "detect_scanners", _osv_present)
    # Feed the committed fixture in place of an actual osv-scanner run.
    monkeypatch.setattr(sca, "run_osv", lambda path: osv_raw)

    result = sca.run_sca(str(tmp_path))
    assert result["scanner"] == "osv-scanner"
    assert result["scanner_available"] is True
    assert result["advisories"], "advisories should be normalized from fixture"
    assert result["summary"]["total_advisories"] == len(result["advisories"])
    assert "osv-scanner scanned" in result["note"]


def test_run_sca_writes_out_dir(tmp_path, monkeypatch, osv_raw):
    _touch(str(tmp_path / "package-lock.json"))
    out = tmp_path / "out"

    def _osv_present():
        d = _no_scanners()
        d["osv-scanner"] = {"available": True, "path": "/x/osv-scanner", "ecosystems": []}
        return d

    monkeypatch.setattr(sca, "detect_scanners", _osv_present)
    monkeypatch.setattr(sca, "run_osv", lambda path: osv_raw)

    result = sca.run_sca(str(tmp_path), out_dir=str(out))
    assert (out / "sca_advisories.json").is_file()
    assert (out / "osv_raw.json").is_file()
    written = json.loads((out / "sca_advisories.json").read_text())
    assert written["advisories"] == result["advisories"]


# --- run_osv: absent binary returns empty (no crash) -----------------------------

def test_run_osv_absent_returns_empty(monkeypatch):
    monkeypatch.setattr(sca.shutil, "which", lambda name: None)
    assert sca.run_osv("/tmp") == []


def test_run_osv_bad_json_returns_empty(monkeypatch):
    monkeypatch.setattr(sca.shutil, "which", lambda name: "/x/osv-scanner")

    class _Proc:
        stdout = "not json {"
        stderr = ""
        returncode = 1

    monkeypatch.setattr(sca.subprocess, "run", lambda *a, **k: _Proc())
    assert sca.run_osv("/tmp") == []


# --- render + CLI ----------------------------------------------------------------

def test_render_table_no_scanner(tmp_path, monkeypatch):
    _touch(str(tmp_path / "package-lock.json"))
    monkeypatch.setattr(sca, "detect_scanners", _no_scanners)
    result = sca.run_sca(str(tmp_path))
    text = sca.render_table(result)
    assert "Software Composition Analysis" in text
    assert "no scanner installed" in text


def test_render_table_with_advisories(osv_raw):
    advisories = sca.normalize(osv_raw)
    result = {
        "path": "/tmp/x",
        "scanner": "osv-scanner",
        "scanner_available": True,
        "lockfiles": [{"ecosystem": "npm", "file": "/tmp/x/package-lock.json"}],
        "note": "osv-scanner scanned 1 lockfile(s)",
        "summary": sca._summarize(advisories),
        "advisories": advisories,
    }
    text = sca.render_table(result)
    assert "lodash" in text
    assert "CVE-2020-28500" in text


def test_cli_json_no_scanner(tmp_path, monkeypatch, capsys):
    _touch(str(tmp_path / "go.sum"))
    monkeypatch.setattr(sca, "detect_scanners", _no_scanners)
    rc = sca.main(["--path", str(tmp_path), "--json"])
    assert rc == 0  # graceful degrade — always exit 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["scanner"] is None
    assert payload["lockfiles"][0]["ecosystem"] == "Go"


def test_cli_exit_zero_even_with_findings(tmp_path, monkeypatch, osv_raw):
    _touch(str(tmp_path / "package-lock.json"))

    def _osv_present():
        d = _no_scanners()
        d["osv-scanner"] = {"available": True, "path": "/x/osv-scanner", "ecosystems": []}
        return d

    monkeypatch.setattr(sca, "detect_scanners", _osv_present)
    monkeypatch.setattr(sca, "run_osv", lambda path: osv_raw)
    rc = sca.main(["--path", str(tmp_path)])
    assert rc == 0


def test_cli_lockfile_filter_missing_warns(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sca, "detect_scanners", _no_scanners)
    rc = sca.main(["--path", str(tmp_path), "--lockfile", "package-lock.json"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "not found" in err
