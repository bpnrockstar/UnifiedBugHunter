"""Tests for tools/pr_diff_review.py — diff-scoped PR review, fully hermetic.

These tests build a REAL but throwaway git repository under pytest's tmp_path
(``subprocess git init`` -> commit a clean base file -> branch + commit that
introduces a vulnerable line) and drive the public surface of pr_diff_review
against it. Nothing here touches the developer's real repo, the network, or any
global git config: every ``git`` invocation is scoped with ``-C <tmp>`` and the
committing identity is forced via ``-c user.*`` flags so the suite runs on a
machine with no git identity configured.

semgrep is OPTIONAL. The two load-bearing guarantees we assert hold regardless of
whether semgrep is installed:
  * the deterministic diff plumbing (changed_files / changed_line_ranges /
    parse_unified_diff / filter_to_diff) is pure git + text and never needs an
    engine;
  * review_pr() always returns the documented structure and exits cleanly. The
    cmd-injection line is caught by sast_runner's built-in regex fallback when
    semgrep is absent, and the added-line secret pass (pure stdlib regex) catches
    the planted credential unconditionally — so a NEW vulnerable finding scoped to
    the diff is asserted without requiring semgrep. A guarded extra assertion
    confirms the cmd-injection partition when an engine is actually present.

If git itself is unavailable, the whole module skips (there is nothing to review
without git, which the tool already handles, but the temp-repo fixtures cannot be
built). stdlib + pytest only.
"""

import os
import shutil
import subprocess
import sys

import pytest

# Make tools/ importable directly (mirrors tests/conftest.py, but kept fully
# self-contained: this module must import even when conftest cannot be collected).
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_ROOT = os.path.join(REPO_ROOT, "tools")
for _path in (REPO_ROOT, TOOLS_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import pr_diff_review as pr  # noqa: E402

# git is required to build the hermetic temp repos. Without it there is nothing to
# diff, so skip the whole module (the tool's own no-git degradation is covered by
# the unit-level tests below that need no repo at all... but those still build a
# repo, so we gate the module).
pytestmark = pytest.mark.skipif(
    shutil.which("git") is None, reason="git binary not available"
)


# --- temp git repo plumbing ------------------------------------------------------

# A clean base file: no sinks, no secrets. This is the pre-existing code the PR
# branches from.
BASE_SRC = """\
def add(a, b):
    return a + b


def greet(name):
    return "hello " + name
"""

# The vulnerable line the PR introduces. os.system(<concatenated user input>) is
# matched by sast_runner's regex-fallback cmd-injection pattern (so it is found
# even with no semgrep) and by semgrep when present.
VULN_LINE = 'os.system("rm -rf /tmp/" + user_input)'

# A hardcoded credential the PR also introduces. The added-line secret pass is pure
# stdlib regex and ALWAYS runs, so this guarantees at least one NEW finding scoped
# to the diff independent of any SAST engine.
SECRET_LINE = 'api_key = "AKIAIOSFODNN7EXAMPLE12"'


def _git(repo, *args):
    """Run a git command inside `repo` with a forced, hermetic identity."""
    cmd = [
        "git",
        "-C",
        str(repo),
        "-c",
        "user.email=test@example.com",
        "-c",
        "user.name=Test",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "init.defaultBranch=main",
        *args,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, check=True)


@pytest.fixture
def pr_repo(tmp_path):
    """Build a throwaway git repo with a clean base commit and a PR commit.

    Returns a dict:
      repo        -> pathlib.Path repo root
      base        -> base commit SHA (the merge target to diff against)
      src_rel     -> repo-relative path of the modified source file
      vuln_line   -> 1-based line number of the introduced cmd-injection line
      secret_line -> 1-based line number of the introduced secret line
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")

    src = repo / "app" / "handler.py"
    src.parent.mkdir(parents=True)
    src.write_text(BASE_SRC, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base: clean handlers")
    base_sha = _git(repo, "rev-parse", "HEAD").stdout.strip()

    # Branch off and introduce the vulnerable code + a hardcoded secret.
    _git(repo, "checkout", "-q", "-b", "feature")
    new_src = (
        BASE_SRC
        + "\n"
        + "\n".join(
            [
                "def run(user_input):",
                "    " + VULN_LINE,
                "",
                "",
                SECRET_LINE,
                "",
            ]
        )
    )
    src.write_text(new_src, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "feature: add run() and config")

    # Compute the 1-based line numbers of the two introduced lines from the final
    # file content, so the assertions do not hard-code offsets.
    lines = new_src.splitlines()
    vuln_no = lines.index("    " + VULN_LINE) + 1
    secret_no = lines.index(SECRET_LINE) + 1

    return {
        "repo": repo,
        "base": base_sha,
        "src_rel": "app/handler.py",
        "vuln_line": vuln_no,
        "secret_line": secret_no,
    }


# --- changed_files / changed_line_ranges ----------------------------------------

def test_changed_files_detects_the_modified_file(pr_repo):
    files = pr.changed_files(pr_repo["base"], str(pr_repo["repo"]))
    assert files == [pr_repo["src_rel"]]


def test_changed_files_empty_when_base_equals_head(pr_repo):
    # Diffing HEAD against HEAD: no changes, no crash, empty list.
    head = _git(pr_repo["repo"], "rev-parse", "HEAD").stdout.strip()
    assert pr.changed_files(head, str(pr_repo["repo"])) == []


def test_changed_line_ranges_covers_the_added_lines(pr_repo):
    ranges = pr.changed_line_ranges(pr_repo["base"], str(pr_repo["repo"]))
    assert pr_repo["src_rel"] in ranges

    file_ranges = ranges[pr_repo["src_rel"]]
    assert file_ranges, "expected at least one added-line range"

    # Both the vulnerable line and the secret line must fall inside a reported range.
    assert pr.line_in_ranges(pr_repo["vuln_line"], file_ranges)
    assert pr.line_in_ranges(pr_repo["secret_line"], file_ranges)

    # An untouched base line (line 1: `def add(a, b):`) must NOT be in any range.
    assert not pr.line_in_ranges(1, file_ranges)


# --- filter_to_diff: keep on changed line, drop on unchanged line ----------------

def test_filter_to_diff_keeps_changed_line_drops_unchanged_line(pr_repo):
    ranges = pr.changed_line_ranges(pr_repo["base"], str(pr_repo["repo"]))
    src = pr_repo["src_rel"]

    on_diff = {
        "tool": "regex-fallback",
        "rule_id": "regex-fallback.cmd-injection",
        "path": src,
        "line": pr_repo["vuln_line"],  # an added line
        "severity": "high",
        "vuln_class": "cmd-injection",
        "message": "command injection",
        "fingerprint": "deadbeef0001",
    }
    off_diff = {
        "tool": "regex-fallback",
        "rule_id": "regex-fallback.cmd-injection",
        "path": src,
        "line": 1,  # `def add(...)` — present in base, never touched by the PR
        "severity": "high",
        "vuln_class": "cmd-injection",
        "message": "pre-existing legacy finding",
        "fingerprint": "deadbeef0002",
    }

    kept = pr.filter_to_diff([on_diff, off_diff], ranges)

    assert on_diff in kept
    assert off_diff not in kept
    assert [f["fingerprint"] for f in kept] == ["deadbeef0001"]


def test_filter_to_diff_drops_finding_in_untouched_file(pr_repo):
    ranges = pr.changed_line_ranges(pr_repo["base"], str(pr_repo["repo"]))
    other = {
        "tool": "regex-fallback",
        "rule_id": "regex-fallback.cmd-injection",
        "path": "app/untouched.py",  # not in the diff at all
        "line": 2,
        "severity": "high",
        "vuln_class": "cmd-injection",
        "message": "x",
        "fingerprint": "ff00",
    }
    assert pr.filter_to_diff([other], ranges) == []


# --- review_pr: new vulnerable finding scoped to the diff ------------------------

def test_review_pr_returns_documented_structure(pr_repo):
    result = pr.review_pr(pr_repo["base"], str(pr_repo["repo"]))

    # Structure / status contract — holds with or without semgrep.
    assert result["status"] == "ok"
    assert result["base_ref"] == pr_repo["base"]
    assert result["files_changed"] == [pr_repo["src_rel"]]
    assert isinstance(result["new_findings"], list)
    assert isinstance(result["preexisting_count"], int)
    assert result["sast_engine"] in {"semgrep", "regex-fallback", "unavailable"}

    summary = result["summary"]
    assert summary["files_changed"] == 1
    assert summary["new"] == len(result["new_findings"])
    assert set(summary) >= {"new", "preexisting", "files_changed", "by_severity", "by_class"}


def test_review_pr_surfaces_a_new_finding_scoped_to_the_diff(pr_repo):
    """The PR introduces a secret on an added line; the always-on secret pass must
    surface it as a NEW finding located exactly on that added line.

    This assertion does NOT depend on semgrep: the added-line secret scan is pure
    stdlib regex and always runs.
    """
    result = pr.review_pr(pr_repo["base"], str(pr_repo["repo"]))

    assert result["new_findings"], "expected at least one NEW finding from the diff"

    src = pr_repo["src_rel"]
    secrets = [
        f
        for f in result["new_findings"]
        if f.get("vuln_class") == "secret" and f.get("path") == src
    ]
    assert secrets, "the added-line secret pass should have flagged the planted credential"

    secret = secrets[0]
    assert secret["line"] == pr_repo["secret_line"]
    assert secret["tool"] == "diff-secret-regex"
    # Every NEW finding must be located inside the diff's changed ranges.
    ranges = pr.changed_line_ranges(pr_repo["base"], str(pr_repo["repo"]))
    for f in result["new_findings"]:
        assert f.get("path") in ranges
        assert pr.line_in_ranges(int(f.get("line") or 0), ranges[f["path"]])

    # The planted secret VALUE is never echoed back into review output.
    assert "AKIAIOSFODNN7EXAMPLE12" not in secret.get("message", "")


def test_review_pr_runs_without_crashing_when_engine_absent(pr_repo, monkeypatch):
    """Force the SAST engine absent and confirm review_pr still returns the full
    structure (semgrep optional). The secret pass keeps surfacing the NEW finding.
    """
    # Drop the engine module reference the tool imported at load time.
    monkeypatch.setattr(pr, "_sast", None, raising=False)

    result = pr.review_pr(pr_repo["base"], str(pr_repo["repo"]))

    assert result["status"] == "ok"
    assert result["sast_engine"] == "unavailable"
    # With no engine, the SAST partition is empty -> no pre-existing SAST debt.
    assert result["preexisting_count"] == 0
    # The added-line secret pass is engine-independent, so the secret is still NEW.
    secrets = [f for f in result["new_findings"] if f.get("vuln_class") == "secret"]
    assert secrets, "secret pass must still run when the SAST engine is unavailable"


class _MockSast:
    """Minimal stand-in for tools/sast_runner with a deterministic finding set.

    Implements the only surface pr_diff_review consumes: ``run_sast(path)`` ->
    {"summary": {"engine_used": ...}, "findings": [...]} and ``fingerprint(f)``.
    This lets us assert the NEW-vs-pre-existing partition deterministically, with no
    dependence on whether semgrep is installed or on which constructs it happens to
    flag (stock semgrep does not flag a bare os.system(...) the way the regex
    fallback does — so a partition test must drive the engine, not the host).
    """

    def __init__(self, vuln_line, src_rel):
        self.vuln_line = vuln_line
        self.src_rel = src_rel

    def fingerprint(self, finding):
        return "fp-{}-{}".format(finding.get("rule_id"), finding.get("line"))

    def run_sast(self, path):
        # sast_runner reports paths relative to the scanned root (basename for a
        # single file); pr_diff_review re-keys them to the repo-relative diff path.
        base = os.path.basename(path)
        findings = [
            {
                "tool": "semgrep",
                "rule_id": "py.cmd-injection",
                "path": base,
                "line": self.vuln_line,  # an ADDED line -> must be NEW
                "severity": "high",
                "vuln_class": "cmd-injection",
                "message": "OS command injection via concatenated input.",
            },
            {
                "tool": "semgrep",
                "rule_id": "py.legacy-smell",
                "path": base,
                "line": 1,  # base line `def add(...)` -> must be PRE-EXISTING
                "severity": "low",
                "vuln_class": "other",
                "message": "pre-existing legacy finding on an untouched line.",
            },
        ]
        return {"summary": {"engine_used": "semgrep"}, "findings": findings}


def test_review_pr_partitions_engine_findings_new_vs_preexisting(pr_repo, monkeypatch):
    """With a deterministic injected engine, the cmd-injection on an ADDED line lands
    in NEW while a finding on an untouched base line is counted as PRE-EXISTING.

    This is the NEW-vs-pre-existing partition contract, exercised without semgrep.
    """
    monkeypatch.setattr(
        pr, "_sast", _MockSast(pr_repo["vuln_line"], pr_repo["src_rel"]), raising=False
    )

    result = pr.review_pr(pr_repo["base"], str(pr_repo["repo"]))

    assert result["sast_engine"] == "semgrep"

    cmd_findings = [
        f
        for f in result["new_findings"]
        if f.get("vuln_class") == "cmd-injection"
        and f.get("path") == pr_repo["src_rel"]
    ]
    assert cmd_findings, "the engine's cmd-injection on an added line should be NEW"
    assert cmd_findings[0]["line"] == pr_repo["vuln_line"]

    # The legacy finding on line 1 is real but untouched by the PR -> pre-existing,
    # never surfaced in new_findings.
    assert result["preexisting_count"] >= 1
    assert all(f.get("rule_id") != "py.legacy-smell" for f in result["new_findings"])


# --- degradation: review_pr on inputs that have nothing to review ----------------

def test_review_pr_on_non_repo_directory_is_clean(tmp_path):
    plain = tmp_path / "not_a_repo"
    plain.mkdir()
    result = pr.review_pr("main", str(plain))
    assert result["status"] == "not-a-git-repo"
    assert result["new_findings"] == []
    assert result["files_changed"] == []
    assert "summary" in result


def test_review_pr_on_bad_ref_is_clean(pr_repo):
    result = pr.review_pr("does-not-exist-ref", str(pr_repo["repo"]))
    assert result["status"] == "bad-ref"
    assert result["new_findings"] == []
    assert result["files_changed"] == []


# --- parse_unified_diff: pure-text unit (no git) ---------------------------------

def test_parse_unified_diff_new_file_added_lines():
    diff = (
        "diff --git a/new.py b/new.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/new.py\n"
        "@@ -0,0 +1,3 @@\n"
        "+import os\n"
        "+def f(x):\n"
        "+    os.system(x)\n"
    )
    ranges = pr.parse_unified_diff(diff)
    assert ranges == {"new.py": [(1, 3)]}


def test_parse_unified_diff_ignores_removed_and_context_lines():
    diff = (
        "--- a/m.py\n"
        "+++ b/m.py\n"
        "@@ -1,4 +1,4 @@\n"
        " import os\n"        # context: line 1
        "-old = 1\n"          # removed: does not advance new counter
        "+new = 2\n"          # added: line 2
        " trailing = 3\n"     # context: line 3
    )
    ranges = pr.parse_unified_diff(diff)
    assert ranges == {"m.py": [(2, 2)]}
