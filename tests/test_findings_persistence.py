"""Tests for the findings-persistence DB layer + the retest-from-DB loop.

Exercises the new/extended functions in ``dashboard/database.py``:

  * ``add_finding(..., poc_spec={...})``  — the appended ``poc_spec`` column
    round-trips through SQLite as JSON, while the free-text ``poc`` evidence
    column is preserved.
  * ``set_finding_status``                — updates a row, returns True/False
    on hit/miss, and raises ValueError on a status outside the CHECK enum.
  * ``get_retest_specs``                  — returns dicts in retest.py's
    ``load_findings()`` shape: the DB row ``id`` is injected, ``previous_status``
    is mapped from the DB status ('fixed' -> "FIXED", else "STILL-VULN"), only
    rows that actually carry a ``poc_spec`` are returned, and malformed /
    non-object ``poc_spec`` rows are skipped (one bad row can't break a batch).

Plus an end-to-end retest-from-DB integration test: a finding whose stored
``poc_spec`` points at a LOCAL threaded ``http.server`` is loaded via
``database.get_retest_specs`` and replayed through ``retest.retest_batch``.
The verdict flips STILL-VULN -> FIXED as the live server is toggled from
vulnerable to patched, and the ``--write-back`` path (``set_finding_status``)
is asserted to persist the new status.

Hermetic by construction: every test uses a throwaway SQLite file (the module's
``DB_DIR`` / ``DB_PATH`` globals are monkeypatched to a tmp_path), the HTTP
server binds 127.0.0.1 on an OS-assigned ephemeral port, and both are torn down
in fixtures. Loopback GET/POST only — nothing destructive. The module under test
is loaded straight from its file path so the test never mutates ``sys.path`` or
touches the real ``dashboard/data/bughunter.db``.

Stdlib + requests + pytest only.
"""

import importlib.util
import json
import os
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

# ─── Load the module under test directly from its file path ─────────────────────
# dashboard/ is not an importable package (no __init__.py), so resolve the file
# explicitly. This keeps the test independent of sys.path ordering and of the
# real on-disk DB.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_DB_MODULE_PATH = os.path.join(_REPO_ROOT, "dashboard", "database.py")


def _load_database_module():
    spec = importlib.util.spec_from_file_location("ubh_dashboard_database", _DB_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# retest.py is reachable via the tools/ entry conftest.py adds to sys.path.
from retest import FIXED, STILL_VULN, retest_batch  # noqa: E402


# ─── DB fixture: a throwaway SQLite file with the schema initialized ─────────────

@pytest.fixture
def db(tmp_path, monkeypatch):
    """Fresh database module pointed at a tmp SQLite file, schema initialized.

    Monkeypatches the module-level ``DB_DIR`` / ``DB_PATH`` that ``get_db()``
    reads on every call, so no test ever opens the real bughunter.db. Yields the
    loaded module; ``init_db()`` has already run (tables + the additive poc_spec
    migration).
    """
    module = _load_database_module()
    db_dir = tmp_path / "data"
    db_path = db_dir / "test_bughunter.db"
    monkeypatch.setattr(module, "DB_DIR", db_dir, raising=True)
    monkeypatch.setattr(module, "DB_PATH", db_path, raising=True)
    module.init_db()
    return module


@pytest.fixture
def target_id(db):
    """Seed a single target and return its row id (findings need a target_id)."""
    db.add_target("api.target.com", program="Acme BBP", platform="hackerone")
    targets = db.get_targets()
    assert targets, "expected the seeded target to be present"
    return targets[0]["id"]


def _poc_spec(base_url):
    """A retest.py-shape PoC spec whose 'match' is the vulnerable condition."""
    return {
        "target": "127.0.0.1",
        "url": f"{base_url}/vuln",
        "method": "GET",
        "headers": {"X-Foo": "bar"},
        "match": {
            "status": 200,
            "body_contains": VULN_MARKER,
            "header_contains": {"X-Vuln": "yes"},
        },
    }


def _insert_raw_poc_spec(module, target_id, *, title, raw_poc_spec, status="open"):
    """Insert a findings row with a hand-crafted raw poc_spec TEXT value.

    Bypasses add_finding so we can store deliberately malformed JSON (or a
    non-object JSON value) to prove get_retest_specs skips it.
    """
    conn = module.get_db()
    try:
        cur = conn.execute(
            "INSERT INTO findings (target_id, title, severity, bug_class, status, poc_spec) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target_id, title, "high", "idor", status, raw_poc_spec),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# ─── Local test server (vulnerable / patched, toggleable at runtime) ─────────────

VULN_MARKER = "SECRET_TOKEN_abc123"  # marker emitted by the vulnerable response


class _ServerState:
    """Thread-safe mutable state shared with the request handler."""

    def __init__(self):
        self._lock = threading.Lock()
        self._vulnerable = True
        self.hits = 0

    @property
    def vulnerable(self):
        with self._lock:
            return self._vulnerable

    @vulnerable.setter
    def vulnerable(self, value):
        with self._lock:
            self._vulnerable = bool(value)

    def bump(self):
        with self._lock:
            self.hits += 1

    @property
    def count(self):
        with self._lock:
            return self.hits


def _make_handler(state):
    """BaseHTTPRequestHandler bound to ``state``.

    GET/POST /vuln:
      * vulnerable  -> 200, body contains VULN_MARKER, header X-Vuln: yes
      * patched     -> 403, benign body, no marker, no X-Vuln header
    Any other path -> 404.
    """

    class Handler(BaseHTTPRequestHandler):
        def _respond(self):
            state.bump()
            path = self.path.split("?", 1)[0]
            if path == "/vuln":
                if state.vulnerable:
                    body = (
                        "user=admin&" + VULN_MARKER + "&id=42 leaked here"
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("X-Vuln", "yes")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    body = b"403 forbidden: access denied, ownership enforced"
                    self.send_response(403)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

        def do_GET(self):  # noqa: N802 (http.server naming)
            self._respond()

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            self._respond()

        def log_message(self, *args, **kwargs):  # silence test noise
            pass

    return Handler


@pytest.fixture
def server():
    """Loopback HTTP server on a random high port; torn down after the test.

    Yields an object exposing ``.base`` (http://127.0.0.1:PORT) and ``.state``
    (toggle ``.state.vulnerable`` to simulate a fix landing).
    """
    state = _ServerState()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    class _Srv:
        def __init__(self):
            self.host = "127.0.0.1"
            self.port = httpd.server_address[1]
            self.base = f"http://127.0.0.1:{httpd.server_address[1]}"
            self.state = state

    try:
        yield _Srv()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


# ─── 1. add_finding(..., poc_spec=...) round-trips ───────────────────────────────

class TestAddFindingPocSpec:

    def test_poc_spec_round_trips(self, db, target_id):
        spec = {
            "url": "https://api.target.com/users/1",
            "method": "GET",
            "headers": {"X-Foo": "bar"},
            "body": "a=1&b=2",
            "match": {"status": 200, "body_contains": "secret"},
        }
        fid = db.add_finding(
            target_id, "IDOR on /users/{id}", "high", "idor",
            endpoint="/users/1", poc="curl evidence here", poc_spec=spec,
        )
        assert isinstance(fid, int) and fid > 0

        # The structured spec round-trips through the JSON TEXT column intact.
        specs = db.get_retest_specs(target_id=target_id)
        assert len(specs) == 1
        got = specs[0]
        # Everything we stored survived (id + previous_status are injected on top).
        for key, value in spec.items():
            assert got[key] == value

        # Raw column holds JSON-encoded dict; the free-text poc is preserved too.
        row = db.get_finding(fid)
        assert json.loads(row["poc_spec"]) == spec
        assert row["poc"] == "curl evidence here"

    def test_legacy_call_without_poc_spec_stores_null(self, db, target_id):
        # The poc_spec param is optional; legacy callers must still work and the
        # row must NOT surface in get_retest_specs (no spec to replay).
        fid = db.add_finding(target_id, "No-spec finding", "low", "info")
        row = db.get_finding(fid)
        assert row["poc_spec"] is None
        assert db.get_retest_specs(target_id=target_id) == []

    def test_poc_spec_not_scrubbed(self, db, target_id):
        # poc_spec is machine-replayable config, intentionally NOT run through
        # _scrub. Force a redactor that would mangle any string, and prove the
        # structured spec passes through verbatim.
        def _mangle(_text):
            return "REDACTED"

        # Patch the scrub hook on the loaded module instance.
        original = db._redact_text
        db._redact_text = _mangle
        try:
            spec = {"url": "https://api.target.com/x", "match": {"status": 200}}
            fid = db.add_finding(
                target_id, "title-with-secret", "high", "idor",
                poc="leak token=AKIA123", poc_spec=spec,
            )
        finally:
            db._redact_text = original

        row = db.get_finding(fid)
        # Structured spec untouched...
        assert json.loads(row["poc_spec"]) == spec
        # ...but the free-text fields WERE scrubbed.
        assert row["title"] == "REDACTED"
        assert row["poc"] == "REDACTED"


# ─── 2. set_finding_status ───────────────────────────────────────────────────────

class TestSetFindingStatus:

    def test_updates_status_and_returns_true(self, db, target_id):
        fid = db.add_finding(target_id, "f", "high", "idor")
        assert db.get_finding(fid)["status"] == "open"

        assert db.set_finding_status(fid, "fixed") is True
        assert db.get_finding(fid)["status"] == "fixed"

        # A second, distinct valid status sticks too.
        assert db.set_finding_status(fid, "verified") is True
        assert db.get_finding(fid)["status"] == "verified"

    def test_returns_false_for_unknown_id(self, db, target_id):
        # No row with id 999999 -> rowcount 0 -> False, and no exception.
        assert db.set_finding_status(999999, "fixed") is False

    @pytest.mark.parametrize("bad", ["closed", "FIXED", "", "vuln", "resolved"])
    def test_rejects_invalid_status(self, db, target_id, bad):
        fid = db.add_finding(target_id, "f", "high", "idor")
        with pytest.raises(ValueError):
            db.set_finding_status(fid, bad)
        # Rejected update must NOT have mutated the row.
        assert db.get_finding(fid)["status"] == "open"

    def test_all_enum_values_accepted(self, db, target_id):
        fid = db.add_finding(target_id, "f", "high", "idor")
        for status in db.FINDING_STATUSES:
            assert db.set_finding_status(fid, status) is True
            assert db.get_finding(fid)["status"] == status


# ─── 3. get_retest_specs shape / id injection / previous_status mapping ──────────

class TestGetRetestSpecs:

    def test_injects_id_and_maps_previous_status(self, db, target_id, server):
        # status 'fixed' -> previous_status "FIXED"
        fixed_id = db.add_finding(
            target_id, "fixed one", "high", "idor",
            poc_spec=_poc_spec(server.base),
        )
        assert db.set_finding_status(fixed_id, "fixed") is True

        # any other status -> "STILL-VULN"; 'verified' here
        open_id = db.add_finding(
            target_id, "open one", "high", "idor",
            poc_spec=_poc_spec(server.base),
        )
        assert db.set_finding_status(open_id, "verified") is True

        specs = {s["id"]: s for s in db.get_retest_specs(target_id=target_id)}
        assert set(specs) == {fixed_id, open_id}
        assert specs[fixed_id]["previous_status"] == FIXED
        assert specs[open_id]["previous_status"] == STILL_VULN

        # The id is the DB row id (injected), and the retest.py-shape keys are
        # present so the dict can feed retest_one directly.
        s = specs[open_id]
        assert s["id"] == open_id
        assert s["url"] == f"{server.base}/vuln"
        assert s["method"] == "GET"
        assert s["match"]["status"] == 200

    def test_open_status_maps_to_still_vuln(self, db, target_id, server):
        fid = db.add_finding(
            target_id, "default-open", "high", "idor",
            poc_spec=_poc_spec(server.base),
        )
        # default status is 'open'
        (spec,) = db.get_retest_specs(target_id=target_id)
        assert spec["id"] == fid
        assert spec["previous_status"] == STILL_VULN

    def test_only_rows_with_poc_spec_returned(self, db, target_id, server):
        with_spec = db.add_finding(
            target_id, "has spec", "high", "idor",
            poc_spec=_poc_spec(server.base),
        )
        db.add_finding(target_id, "no spec", "low", "info")  # poc_spec NULL

        specs = db.get_retest_specs(target_id=target_id)
        assert [s["id"] for s in specs] == [with_spec]

    def test_malformed_poc_spec_rows_are_skipped(self, db, target_id, server):
        good_id = db.add_finding(
            target_id, "good", "high", "idor",
            poc_spec=_poc_spec(server.base),
        )
        # Not valid JSON at all.
        _insert_raw_poc_spec(db, target_id, title="bad-json", raw_poc_spec="{not json")
        # Valid JSON but not an object (a JSON array / string / number).
        _insert_raw_poc_spec(db, target_id, title="json-array", raw_poc_spec="[1, 2, 3]")
        _insert_raw_poc_spec(db, target_id, title="json-string", raw_poc_spec='"just a string"')
        _insert_raw_poc_spec(db, target_id, title="json-number", raw_poc_spec="42")

        specs = db.get_retest_specs(target_id=target_id)
        # Only the single well-formed object spec survives the skip filter.
        assert [s["id"] for s in specs] == [good_id]

    def test_status_and_ids_filters(self, db, target_id, server):
        a = db.add_finding(target_id, "a", "high", "idor", poc_spec=_poc_spec(server.base))
        b = db.add_finding(target_id, "b", "high", "idor", poc_spec=_poc_spec(server.base))
        c = db.add_finding(target_id, "c", "high", "idor", poc_spec=_poc_spec(server.base))
        db.set_finding_status(b, "fixed")

        # status filter
        fixed_only = db.get_retest_specs(target_id=target_id, status="fixed")
        assert [s["id"] for s in fixed_only] == [b]

        # ids filter
        subset = db.get_retest_specs(target_id=target_id, ids=[a, c])
        assert sorted(s["id"] for s in subset) == sorted([a, c])


# ─── 4. retest-from-DB integration ───────────────────────────────────────────────

class TestRetestFromDB:

    def test_still_vuln_then_fixed_with_write_back(self, db, target_id, server):
        """End-to-end: seed -> load specs from DB -> retest -> write verdict back.

        1. Server vulnerable: get_retest_specs + retest_batch -> STILL-VULN.
        2. Flip server to patched: same specs replay -> FIXED.
        3. --write-back: set_finding_status('fixed') persists; the row is now
           'fixed' and the next get_retest_specs maps previous_status -> FIXED.
        """
        fid = db.add_finding(
            target_id, "IDOR on /vuln", "high", "idor",
            endpoint="/vuln", poc="manual repro", poc_spec=_poc_spec(server.base),
        )

        # ── 1. Still vulnerable ──
        assert server.state.vulnerable is True
        specs = db.get_retest_specs(target_id=target_id)
        assert len(specs) == 1 and specs[0]["id"] == fid

        report = retest_batch(specs, timeout=10, verify_tls=False)
        (result,) = report["results"]
        assert result["id"] == fid
        assert result["verdict"] == STILL_VULN
        assert result["status"] == 200
        assert report["summary"]["still_vuln"] == 1
        assert server.state.count > 0  # the live server was actually hit

        # ── 2. Fix lands — flip the server, replay the same DB specs ──
        server.state.vulnerable = False
        specs = db.get_retest_specs(target_id=target_id)  # status still 'open'
        report = retest_batch(specs, timeout=10, verify_tls=False)
        (result,) = report["results"]
        assert result["id"] == fid
        assert result["verdict"] == FIXED
        assert report["summary"]["fixed"] == 1

        # ── 3. Write-back path: persist the FIXED verdict ──
        for r in report["results"]:
            if r["verdict"] == FIXED:
                assert db.set_finding_status(r["id"], "fixed") is True

        row = db.get_finding(fid)
        assert row["status"] == "fixed"
        # And the mapping now reflects the persisted status.
        (spec_after,) = db.get_retest_specs(target_id=target_id)
        assert spec_after["previous_status"] == FIXED

    def test_regressed_detection_after_write_back(self, db, target_id, server):
        """A finding marked 'fixed' that is vulnerable again -> REGRESSED.

        After write-back marks the bug fixed, a spec loaded from the DB carries
        previous_status="FIXED". If the server becomes vulnerable again, the
        retest verdict is REGRESSED, not plain STILL-VULN.
        """
        from retest import REGRESSED

        fid = db.add_finding(
            target_id, "IDOR on /vuln", "high", "idor",
            poc_spec=_poc_spec(server.base),
        )
        # Mark it fixed (as a prior retest would have).
        assert db.set_finding_status(fid, "fixed") is True

        # Server is (still) vulnerable — the "fix" did not hold.
        assert server.state.vulnerable is True
        (spec,) = db.get_retest_specs(target_id=target_id)
        assert spec["previous_status"] == FIXED

        report = retest_batch([spec], timeout=10, verify_tls=False)
        (result,) = report["results"]
        assert result["verdict"] == REGRESSED
        assert report["summary"]["regressed"] == 1
