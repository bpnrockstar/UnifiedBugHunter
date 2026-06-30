"""Tests for tools/secrets_ingest.py — the secrets_hunter.sh → findings-DB bridge.

`secrets_ingest` parses trufflehog (JSONL) and gitleaks (JSON) scanner output,
normalizes each hit, and writes it into the findings DB as a `bug_class='secret'`
finding. This is privacy-critical plumbing: the raw credential must NEVER be
persisted — the DB's `_scrub` hook (tools/redact.py) redacts every free-text
field, including the PoC, before it lands on disk.

What is covered:
  1. parse_trufflehog / parse_gitleaks return normalized hit dicts (detector,
     file, line, verified, match, endpoint, description), are resilient to
     malformed/missing input, and never carry a raw secret in `match`.
  2. ingest() into a TEMP DB creates findings with bug_class='secret',
     severity HIGH for live-verified hits and MEDIUM otherwise, source
     'secrets-hunter', and a REDACTED poc (the raw secret is not present).
  3. Duplicate hits are deduped (within a single ingest batch, and — for hits
     with no line number, whose stored endpoint round-trips — across runs).

Imports the module bare (``import secrets_ingest``); the shared conftest.py
adds ``tools/`` to ``sys.path``. The DB is redirected to a throwaway sqlite
file via the same DB_PATH/DB_DIR monkeypatch pattern the persistence tests use,
so nothing touches the real dashboard database. Stdlib + pytest only.
"""

import json

import pytest

import secrets_ingest
from secrets_ingest import ingest, parse_gitleaks, parse_trufflehog

# ─── Secret literals, assembled at runtime ──────────────────────────────────────
# Built by concatenation so the literal contiguous tokens never appear verbatim
# in source (GitHub push-protection flags real-looking secrets in commits). These
# are fake but match the redactor's patterns, so _scrub turns them into
# [REDACTED:...] placeholders.
AWS_KEY = "AKIA" + "QWERTYUIOP123456"          # -> [REDACTED:AWS_KEY]
GITHUB_TOKEN = "ghp_" + "a" * 36               # -> [REDACTED:GITHUB_TOKEN]
SLACK_TOKEN = "xox" + "b-123456789012-abcdefghij"  # -> [REDACTED:SLACK_TOKEN]
GENERIC_SECRET = "AKIA" + "ZZZZZZZZZZZZ1234"   # -> [REDACTED:AWS_KEY] (no line case)


# ─── DB fixture: point the database at a throwaway sqlite file ──────────────────
@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Redirect secrets_ingest's database module to a temp sqlite DB.

    ingest() writes through ``secrets_ingest.database`` (the module object the
    tool resolved at import time), so we monkeypatch DB_DIR/DB_PATH on *that*
    object and call init_db() against it. Yields the live database module so
    tests can read findings straight back out.
    """
    db = secrets_ingest.database
    assert db is not None, "secrets_ingest could not load the database module"
    data_dir = tmp_path / "dbdata"
    data_dir.mkdir()
    monkeypatch.setattr(db, "DB_DIR", data_dir)
    monkeypatch.setattr(db, "DB_PATH", data_dir / "test_findings.db")
    db.init_db()
    return db


# ─── Fixture writers for inline tiny scanner outputs ────────────────────────────
def _write_trufflehog(dirpath, objs):
    """Write a trufflehog v3 JSONL file (one JSON object per line)."""
    p = dirpath / "trufflehog.jsonl"
    p.write_text("\n".join(json.dumps(o) for o in objs) + "\n", encoding="utf-8")
    return p


def _write_gitleaks(dirpath, payload):
    """Write a gitleaks JSON report (array of finding objects, or wrapper)."""
    p = dirpath / "gitleaks.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


@pytest.fixture
def trufflehog_file(tmp_path):
    """Tiny trufflehog.jsonl: one verified AWS hit + one unverified Slack hit."""
    objs = [
        {
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": AWS_KEY,
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": "/app/config.py", "line": 12}}
            },
        },
        {
            "DetectorName": "Slack",
            "Verified": False,
            "Raw": SLACK_TOKEN,
            "SourceMetadata": {
                "Data": {"Git": {"file": "src/notify.js", "line": 88}}
            },
        },
    ]
    return _write_trufflehog(tmp_path, objs)


@pytest.fixture
def gitleaks_file(tmp_path):
    """Tiny gitleaks.json: one github-pat hit (gitleaks never live-verifies)."""
    payload = [
        {
            "RuleID": "github-pat",
            "File": "deploy/.env",
            "StartLine": 3,
            "Secret": GITHUB_TOKEN,
        }
    ]
    return _write_gitleaks(tmp_path, payload)


# ─── parse_trufflehog ───────────────────────────────────────────────────────────
class TestParseTrufflehog:
    def test_returns_normalized_hits(self, trufflehog_file):
        hits = parse_trufflehog(str(trufflehog_file))
        assert len(hits) == 2
        first, second = hits
        # Normalized shape.
        for h in hits:
            assert set(h) >= {
                "detector",
                "file",
                "line",
                "verified",
                "match",
                "endpoint",
                "description",
            }
        assert first["detector"] == "AWS"
        assert first["file"] == "/app/config.py"
        assert first["line"] == 12
        assert first["verified"] is True
        assert first["endpoint"] == "/app/config.py"
        assert second["detector"] == "Slack"
        assert second["verified"] is False
        assert second["line"] == 88

    def test_verified_is_coerced_to_bool(self, trufflehog_file):
        for h in parse_trufflehog(str(trufflehog_file)):
            assert isinstance(h["verified"], bool)

    def test_match_is_redacted_at_parse_time(self, trufflehog_file):
        # Even in parse-only land the raw credential must not survive in `match`.
        hits = parse_trufflehog(str(trufflehog_file))
        joined = " ".join(str(h["match"]) for h in hits)
        assert AWS_KEY not in joined
        assert SLACK_TOKEN not in joined
        assert "[REDACTED:" in hits[0]["match"]

    def test_description_includes_detector_and_verified_flag(self, trufflehog_file):
        hits = parse_trufflehog(str(trufflehog_file))
        assert "AWS" in hits[0]["description"]
        assert "yes" in hits[0]["description"].lower()  # live-verified: yes
        assert "no" in hits[1]["description"].lower()   # live-verified: no

    def test_malformed_lines_are_skipped(self, tmp_path):
        p = tmp_path / "trufflehog.jsonl"
        p.write_text(
            "not json at all\n"
            + json.dumps({"DetectorName": "AWS", "Verified": False, "Raw": "x"})
            + "\n"
            + "[]\n"      # valid JSON but not an object -> skipped
            + "\n",       # blank line -> skipped
            encoding="utf-8",
        )
        hits = parse_trufflehog(str(p))
        assert len(hits) == 1
        assert hits[0]["detector"] == "AWS"

    def test_missing_file_returns_empty_list(self, tmp_path):
        hits = parse_trufflehog(str(tmp_path / "does_not_exist.jsonl"))
        assert hits == []

    def test_detector_falls_back_when_absent(self, tmp_path):
        p = tmp_path / "trufflehog.jsonl"
        p.write_text(json.dumps({"Verified": False, "Raw": "y"}) + "\n", encoding="utf-8")
        hits = parse_trufflehog(str(p))
        assert len(hits) == 1
        assert hits[0]["detector"]  # non-empty fallback


# ─── parse_gitleaks ─────────────────────────────────────────────────────────────
class TestParseGitleaks:
    def test_returns_normalized_hits(self, gitleaks_file):
        hits = parse_gitleaks(str(gitleaks_file))
        assert len(hits) == 1
        h = hits[0]
        assert h["detector"] == "github-pat"
        assert h["file"] == "deploy/.env"
        assert h["line"] == 3
        assert h["endpoint"] == "deploy/.env"

    def test_gitleaks_hits_are_never_verified(self, gitleaks_file):
        # gitleaks has no live-verify step -> verified must always be False.
        for h in parse_gitleaks(str(gitleaks_file)):
            assert h["verified"] is False

    def test_match_is_redacted_at_parse_time(self, gitleaks_file):
        hits = parse_gitleaks(str(gitleaks_file))
        assert GITHUB_TOKEN not in str(hits[0]["match"])
        assert "[REDACTED:" in hits[0]["match"]

    def test_accepts_wrapper_object_with_findings_key(self, tmp_path):
        p = _write_gitleaks(
            tmp_path,
            {"findings": [{"RuleID": "r1", "File": "a.py", "StartLine": 1, "Secret": "s"}]},
        )
        hits = parse_gitleaks(str(p))
        assert len(hits) == 1
        assert hits[0]["detector"] == "r1"

    def test_malformed_json_returns_empty_list(self, tmp_path):
        p = tmp_path / "gitleaks.json"
        p.write_text("{not valid json", encoding="utf-8")
        assert parse_gitleaks(str(p)) == []

    def test_missing_file_returns_empty_list(self, tmp_path):
        assert parse_gitleaks(str(tmp_path / "nope.json")) == []


# ─── ingest() into a temp DB ────────────────────────────────────────────────────
class TestIngest:
    def test_writes_secret_findings(self, tmp_db, trufflehog_file, gitleaks_file):
        # Both fixture files live in the same tmp dir (tmp_path); ingest reads both.
        results_dir = trufflehog_file.parent
        written = ingest(str(results_dir), "api.target.com")
        assert written == 3  # 2 trufflehog + 1 gitleaks, all distinct

        rows, _total = tmp_db.get_findings(bug_class="secret", limit=100)
        assert len(rows) == 3
        for r in rows:
            assert r["bug_class"] == "secret"
            assert r["source"] == "secrets-hunter"
            assert r["title"].startswith("Leaked secret:")

    def test_verified_hit_is_high_others_medium(self, tmp_db, trufflehog_file, gitleaks_file):
        results_dir = trufflehog_file.parent
        ingest(str(results_dir), "api.target.com")
        rows, _ = tmp_db.get_findings(bug_class="secret", limit=100)
        severities = sorted(r["severity"] for r in rows)
        # 1 verified (AWS) -> high; 2 unverified (Slack, github-pat) -> medium.
        assert severities == ["high", "medium", "medium"]
        high_rows = [r for r in rows if r["severity"] == "high"]
        assert len(high_rows) == 1
        assert high_rows[0]["endpoint"] == "/app/config.py"  # the AWS hit

    def test_stored_poc_is_redacted(self, tmp_db, trufflehog_file, gitleaks_file):
        results_dir = trufflehog_file.parent
        ingest(str(results_dir), "api.target.com")
        rows, _ = tmp_db.get_findings(bug_class="secret", limit=100)
        blob = " ".join(str(r["poc"]) for r in rows)
        # The raw secrets must not be present anywhere in the persisted PoCs.
        assert AWS_KEY not in blob
        assert GITHUB_TOKEN not in blob
        assert SLACK_TOKEN not in blob
        # And the redaction placeholder must be present (scrub actually ran).
        assert "[REDACTED:" in blob

    def test_returns_zero_when_dir_empty(self, tmp_db, tmp_path):
        empty = tmp_path / "empty_results"
        empty.mkdir()
        assert ingest(str(empty), "api.target.com") == 0
        rows, _ = tmp_db.get_findings(bug_class="secret", limit=100)
        assert rows == []


# ─── Dedup ──────────────────────────────────────────────────────────────────────
class TestDedup:
    def test_within_batch_duplicates_collapse(self, tmp_db, tmp_path):
        # Two byte-identical (detector, file, line) hits in one batch -> 1 finding.
        objs = [
            {
                "DetectorName": "AWS",
                "Verified": True,
                "Raw": AWS_KEY,
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "/app/config.py", "line": 12}}
                },
            },
            {
                "DetectorName": "AWS",
                "Verified": True,
                "Raw": AWS_KEY,
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "/app/config.py", "line": 12}}
                },
            },
        ]
        _write_trufflehog(tmp_path, objs)
        written = ingest(str(tmp_path), "api.target.com")
        assert written == 1
        rows, _ = tmp_db.get_findings(bug_class="secret", limit=100)
        assert len(rows) == 1

    def test_distinct_lines_are_not_deduped(self, tmp_db, tmp_path):
        # Same detector + file but different lines -> two distinct findings.
        objs = [
            {
                "DetectorName": "AWS",
                "Verified": False,
                "Raw": AWS_KEY,
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "/app/config.py", "line": 1}}
                },
            },
            {
                "DetectorName": "AWS",
                "Verified": False,
                "Raw": AWS_KEY,
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "/app/config.py", "line": 2}}
                },
            },
        ]
        _write_trufflehog(tmp_path, objs)
        assert ingest(str(tmp_path), "api.target.com") == 2

    def test_rerun_does_not_duplicate_existing(self, tmp_db, tmp_path):
        # Hit with no line number -> stored endpoint == file, so the (detector,
        # file, line) key round-trips and a second ingest writes nothing new.
        objs = [
            {
                "DetectorName": "Generic",
                "Verified": False,
                "Raw": GENERIC_SECRET,
                "SourceMetadata": {"Data": {"Filesystem": {"file": "noline.txt"}}},
            }
        ]
        _write_trufflehog(tmp_path, objs)
        first = ingest(str(tmp_path), "api.target.com")
        second = ingest(str(tmp_path), "api.target.com")
        assert first == 1
        assert second == 0
        rows, _ = tmp_db.get_findings(bug_class="secret", limit=100)
        assert len(rows) == 1
