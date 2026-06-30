"""Tests for tools/sca_audit.py — software-composition analysis over lockfiles.

Fully offline. The osv-scanner / pip-audit binaries are NEVER required: these
tests drive the importable functions against a committed scanner fixture
(tools/fixtures/osv_scanner_sample.json) and monkeypatch the scanner-detection
path so the no-scanner fallback can be exercised regardless of what is on PATH.

Covers exactly:
  * find_lockfiles() detects a temp requirements.txt / package-lock.json
  * detect_scanners() returns a dict (one entry per known tool)
  * normalize() maps the committed sample osv-scanner JSON to the advisory schema
  * run_sca() on a temp dir with NO scanner returns the graceful "no scanner"
    result, listing the lockfiles it found, without crashing

stdlib + pytest only.
"""

import os
import sys

import pytest

# Make tools/ importable (mirrors tests/conftest.py, kept self-contained so this
# module imports cleanly even when run in isolation).
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_ROOT = os.path.join(REPO_ROOT, "tools")
for _path in (REPO_ROOT, TOOLS_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import sca_audit as sca


# The exact advisory keys produced by normalize() / run_sca()["advisories"].
ADVISORY_KEYS = {
    "ecosystem", "package", "version", "vuln_id",
    "severity", "fixed_version", "summary",
}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def _touch(path, body="{}\n"):
    """Create an (optionally non-empty) file, making parent dirs as needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)


@pytest.fixture
def no_scanner(monkeypatch):
    """Force the 'no scanner installed' branch regardless of the real PATH.

    detect_scanners() is the only function that touches PATH (via shutil.which),
    so reporting every known tool as unavailable is enough to drive run_sca()
    down its graceful-degradation path without requiring/forbidding any binary.
    """
    fake = {
        tool: {"available": False, "path": None, "ecosystems": list(ecos)}
        for tool, ecos in sca.SCANNERS.items()
    }
    monkeypatch.setattr(sca, "detect_scanners", lambda: fake)
    return fake


# --- find_lockfiles --------------------------------------------------------------

def test_find_lockfiles_detects_requirements_and_package_lock(tmp_path):
    _touch(str(tmp_path / "requirements.txt"), "flask==2.0.0\n")
    _touch(str(tmp_path / "package-lock.json"))

    found = sca.find_lockfiles(str(tmp_path))

    by_name = {os.path.basename(r["file"]): r["ecosystem"] for r in found}
    assert by_name == {
        "requirements.txt": "PyPI",
        "package-lock.json": "npm",
    }


def test_find_lockfiles_rows_have_ecosystem_and_abspath_file(tmp_path):
    _touch(str(tmp_path / "requirements.txt"))
    _touch(str(tmp_path / "package-lock.json"))

    found = sca.find_lockfiles(str(tmp_path))

    assert len(found) == 2
    for row in found:
        assert set(row.keys()) == {"ecosystem", "file"}
        assert os.path.isabs(row["file"])
        assert os.path.isfile(row["file"])
    # Deterministic ordering: sorted by (ecosystem, file). "PyPI" < "npm".
    assert found == sorted(found, key=lambda r: (r["ecosystem"], r["file"]))


def test_find_lockfiles_empty_dir_returns_empty_list(tmp_path):
    assert sca.find_lockfiles(str(tmp_path)) == []


# --- detect_scanners -------------------------------------------------------------

def test_detect_scanners_returns_dict_for_each_known_tool():
    detected = sca.detect_scanners()

    assert isinstance(detected, dict)
    # One entry per scanner the tool knows how to reason about.
    assert set(detected.keys()) == set(sca.SCANNERS.keys())
    assert "osv-scanner" in detected and "pip-audit" in detected

    for tool, info in detected.items():
        assert set(info.keys()) == {"available", "path", "ecosystems"}
        assert isinstance(info["available"], bool)
        assert info["path"] is None or isinstance(info["path"], str)
        assert isinstance(info["ecosystems"], list)
        # available <=> a path was resolved on PATH.
        assert info["available"] == (info["path"] is not None)


# --- normalize -------------------------------------------------------------------

def test_normalize_maps_sample_fixture_to_advisory_schema():
    raw = sca.load_osv_file(sca.BUNDLED_OSV_SAMPLE)
    advisories = sca.normalize(raw)

    # lodash x2 + minimist x2 in the committed sample.
    assert len(advisories) == 4
    for adv in advisories:
        assert set(adv.keys()) == ADVISORY_KEYS
        for value in adv.values():
            assert isinstance(value, str)
        assert adv["severity"] in VALID_SEVERITIES
        assert adv["ecosystem"] == "npm"

    # CVE id is preferred over the raw GHSA/OSV id.
    assert all(adv["vuln_id"].startswith("CVE-") for adv in advisories)

    # Spot-check one fully-resolved row (the CRITICAL minimist prototype pollution).
    by_vuln = {adv["vuln_id"]: adv for adv in advisories}
    crit = by_vuln["CVE-2021-44906"]
    assert crit["package"] == "minimist"
    assert crit["version"] == "1.2.0"
    assert crit["severity"] == "CRITICAL"
    assert crit["fixed_version"] == "1.2.6"
    assert "Prototype Pollution" in crit["summary"]


def test_normalize_sorts_most_severe_first():
    advisories = sca.normalize(sca.load_osv_file(sca.BUNDLED_OSV_SAMPLE))

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    ranks = [order[adv["severity"]] for adv in advisories]
    assert ranks == sorted(ranks)
    # The sample's worst finding is the CRITICAL minimist CVE.
    assert advisories[0]["severity"] == "CRITICAL"


def test_normalize_empty_input_returns_empty_list():
    assert sca.normalize([]) == []


# --- run_sca (no scanner, graceful degradation) ----------------------------------

def test_run_sca_no_scanner_lists_lockfiles_without_crashing(tmp_path, no_scanner):
    _touch(str(tmp_path / "requirements.txt"), "django==3.0\n")
    _touch(str(tmp_path / "package-lock.json"))

    result = sca.run_sca(str(tmp_path))

    # No scanner -> graceful, advisory-only result.
    assert result["scanner"] is None
    assert result["scanner_available"] is False
    assert result["advisories"] == []
    assert result["summary"]["total_advisories"] == 0

    # The lockfiles it found are still enumerated.
    found_names = {os.path.basename(lf["file"]) for lf in result["lockfiles"]}
    assert found_names == {"requirements.txt", "package-lock.json"}

    # The note clearly states no scanner is installed and what to install.
    assert "no scanner installed" in result["note"]
    assert "osv-scanner" in result["note"]
    # It mentions the lockfile count it degraded over.
    assert "2 lockfile" in result["note"]


def test_run_sca_no_scanner_result_has_full_schema(tmp_path, no_scanner):
    _touch(str(tmp_path / "package-lock.json"))

    result = sca.run_sca(str(tmp_path))

    assert set(result.keys()) == {
        "path", "scanner", "scanner_available",
        "lockfiles", "note", "summary", "advisories",
    }
    assert result["path"] == os.path.abspath(str(tmp_path))
    assert set(result["summary"].keys()) == {
        "total_advisories", "vulnerable_packages", "by_severity",
    }
    assert set(result["summary"]["by_severity"].keys()) == VALID_SEVERITIES


def test_run_sca_no_scanner_no_lockfiles_still_graceful(tmp_path, no_scanner):
    # Empty dir, no scanner: must not crash, must say so, must return clean.
    result = sca.run_sca(str(tmp_path))

    assert result["scanner"] is None
    assert result["lockfiles"] == []
    assert result["advisories"] == []
    assert "no scanner installed" in result["note"]
    assert "no lockfiles found" in result["note"]
