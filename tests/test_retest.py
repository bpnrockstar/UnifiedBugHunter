"""Tests for tools/retest.py — the scope-safe PoC-replay + regression-verdict engine.

Imports retest's public functions directly (bare module name, resolved via the
tools/ entry that conftest.py adds to sys.path). Covers:

  1. evaluate_match — every matcher type (status, body_contains, body_regex,
     header_contains), true + false cases, and combined (ANDed) matchers.
  2. decide_verdict — the full truth table (STILL-VULN / FIXED / REGRESSED).
  3. retest_one against a real LOCAL http.server stood up in a background
     thread (a '/vuln' route emitting a marker, a '/fixed' route that does not)
     to assert STILL-VULN vs FIXED end-to-end.
  4. Scope gating — fail-closed: an out-of-scope host yields ERROR/'out-of-scope'
     and sends NO request (asserted via the server's request counter).
  5. Request failure (unreachable port) -> ERROR, and a batch keeps going.

Hermetic: the server binds 127.0.0.1 on an OS-assigned high port and is torn
down by a fixture. Nothing destructive runs (loopback GET/POST only).
Stdlib + requests + pytest only.
"""

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from retest import (
    ERROR,
    FIXED,
    REGRESSED,
    STILL_VULN,
    decide_verdict,
    evaluate_match,
    load_findings,
    retest_batch,
    retest_one,
)
from scope_checker import ScopeChecker


# ─── Local test server ────────────────────────────────────────────────────────

VULN_MARKER = "SECRET_TOKEN_abc123"  # marker string the '/vuln' route emits


class _Counter:
    """Thread-safe hit counter shared with the request handler."""

    def __init__(self):
        self._lock = threading.Lock()
        self.hits = 0

    def bump(self):
        with self._lock:
            self.hits += 1

    @property
    def count(self):
        with self._lock:
            return self.hits


def _make_handler(counter):
    """Build a BaseHTTPRequestHandler class bound to a shared hit counter.

      GET/POST /vuln   -> 200, body contains VULN_MARKER, header X-Vuln: yes
      GET/POST /fixed  -> 200, benign body, no marker
      anything else    -> 404
    """

    class Handler(BaseHTTPRequestHandler):
        def _respond(self):
            counter.bump()
            path = self.path.split("?", 1)[0]
            if path == "/vuln":
                body = (
                    "user=admin&" + VULN_MARKER + "&id=42 leaked here"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("X-Vuln", "yes")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path == "/fixed":
                body = b"access denied: nothing to see here"
                self.send_response(200)
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
            # Drain any request body so the connection closes cleanly.
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            self._respond()

        def log_message(self, *args, **kwargs):  # silence test noise
            pass

    return Handler


@pytest.fixture
def server():
    """Stand up a loopback HTTP server on a random high port; tear it down after.

    Yields an object exposing `.base` (http://127.0.0.1:PORT) and `.counter`
    (request hit count). Bound on an OS-assigned ephemeral port for hermeticity.
    """
    counter = _Counter()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(counter))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    class _Srv:
        def __init__(self):
            self.host = "127.0.0.1"
            self.port = httpd.server_address[1]
            self.base = f"http://127.0.0.1:{httpd.server_address[1]}"
            self.counter = counter

    try:
        yield _Srv()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _free_port():
    """Reserve and immediately release a port so connecting to it refuses."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ─── Fake transport for scope/no-request assertions ─────────────────────────────

class _Resp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class _RecordingSession:
    """Minimal requests-like transport that records every .request() call.

    Used to prove the fail-closed scope gate sends ZERO requests, and to drive
    evaluate logic without touching the network.
    """

    def __init__(self, response=None, exc=None):
        self.calls = []
        self._response = response if response is not None else _Resp()
        self._exc = exc

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self._exc is not None:
            raise self._exc
        return self._response


# ─── 1. evaluate_match ──────────────────────────────────────────────────────────

class TestEvaluateMatchStatus:

    def test_status_true(self):
        assert evaluate_match(200, "", {}, {"status": 200}) is True

    def test_status_false(self):
        assert evaluate_match(404, "", {}, {"status": 200}) is False

    def test_status_string_coerced(self):
        # int(response_status) == int(match["status"]) — string statuses coerce.
        assert evaluate_match("200", "", {}, {"status": "200"}) is True

    def test_status_non_numeric_is_false(self):
        assert evaluate_match("nope", "", {}, {"status": 200}) is False


class TestEvaluateMatchBodyContains:

    def test_body_contains_true(self):
        assert evaluate_match(200, "leaked: secret here", {}, {"body_contains": "secret"}) is True

    def test_body_contains_false(self):
        assert evaluate_match(200, "all good", {}, {"body_contains": "secret"}) is False


class TestEvaluateMatchBodyRegex:

    def test_body_regex_true(self):
        assert evaluate_match(200, "row id=42 found", {}, {"body_regex": r"id=\d+"}) is True

    def test_body_regex_false(self):
        assert evaluate_match(200, "no numbers", {}, {"body_regex": r"id=\d+"}) is False

    def test_uncompilable_regex_is_no_match_not_exception(self):
        # An invalid pattern must read as "no match" rather than raising.
        assert evaluate_match(200, "anything", {}, {"body_regex": "([unterminated"}) is False


class TestEvaluateMatchHeaderContains:

    def test_header_contains_true(self):
        assert evaluate_match(200, "", {"Server": "nginx/1.25"}, {"header_contains": {"Server": "nginx"}}) is True

    def test_header_name_case_insensitive(self):
        assert evaluate_match(200, "", {"server": "nginx"}, {"header_contains": {"SERVER": "nginx"}}) is True

    def test_header_value_case_insensitive_substring(self):
        assert evaluate_match(200, "", {"X-Powered-By": "Express"}, {"header_contains": {"x-powered-by": "express"}}) is True

    def test_header_value_mismatch_false(self):
        assert evaluate_match(200, "", {"Server": "apache"}, {"header_contains": {"Server": "nginx"}}) is False

    def test_missing_header_false(self):
        assert evaluate_match(200, "", {"Server": "nginx"}, {"header_contains": {"X-Absent": "x"}}) is False


class TestEvaluateMatchCombined:

    def test_all_conditions_hold_true(self):
        match = {
            "status": 200,
            "body_contains": "secret",
            "body_regex": r"id=\d+",
            "header_contains": {"X-Vuln": "yes"},
        }
        assert evaluate_match(200, "secret id=7", {"X-Vuln": "yes"}, match) is True

    def test_one_condition_fails_whole_false(self):
        # status ok, body ok, regex ok, but header missing -> ANDed result False
        match = {
            "status": 200,
            "body_contains": "secret",
            "body_regex": r"id=\d+",
            "header_contains": {"X-Vuln": "yes"},
        }
        assert evaluate_match(200, "secret id=7", {"Server": "nginx"}, match) is False

    def test_status_mismatch_makes_combined_false(self):
        match = {"status": 200, "body_contains": "secret"}
        assert evaluate_match(500, "secret", {}, match) is False


class TestEvaluateMatchFailClosed:

    def test_empty_match_is_false(self):
        assert evaluate_match(200, "secret", {"Server": "nginx"}, {}) is False

    def test_non_dict_match_is_false(self):
        assert evaluate_match(200, "secret", {}, None) is False


# ─── 2. decide_verdict truth table ──────────────────────────────────────────────

class TestDecideVerdict:

    def test_matched_no_previous_is_still_vuln(self):
        assert decide_verdict(True, None) == STILL_VULN

    def test_matched_previous_still_vuln_is_still_vuln(self):
        assert decide_verdict(True, "STILL-VULN") == STILL_VULN

    def test_matched_previous_fixed_is_regressed(self):
        assert decide_verdict(True, "FIXED") == REGRESSED

    def test_matched_previous_fixed_case_insensitive(self):
        # previous_status compared after .strip().upper()
        assert decide_verdict(True, "  fixed  ") == REGRESSED

    def test_not_matched_is_fixed_regardless_of_previous(self):
        assert decide_verdict(False, None) == FIXED
        assert decide_verdict(False, "FIXED") == FIXED
        assert decide_verdict(False, "STILL-VULN") == FIXED

    def test_matched_unknown_previous_is_still_vuln(self):
        assert decide_verdict(True, "whatever") == STILL_VULN


# ─── 3. retest_one against the local server ─────────────────────────────────────

class TestRetestOneLive:

    def test_still_vuln_when_marker_present(self, server):
        finding = {
            "id": "BUG-VULN",
            "url": f"{server.base}/vuln",
            "match": {"status": 200, "body_contains": VULN_MARKER},
        }
        result = retest_one(finding)
        assert result["verdict"] == STILL_VULN
        assert result["id"] == "BUG-VULN"
        assert result["status"] == 200
        assert result["url"].endswith("/vuln")
        assert server.counter.count == 1

    def test_fixed_when_marker_absent(self, server):
        finding = {
            "id": "BUG-FIXED",
            "url": f"{server.base}/fixed",
            "match": {"status": 200, "body_contains": VULN_MARKER},
        }
        result = retest_one(finding)
        assert result["verdict"] == FIXED
        assert result["status"] == 200
        assert server.counter.count == 1

    def test_regressed_when_previously_fixed_but_now_vulnerable(self, server):
        finding = {
            "id": "BUG-REGRESS",
            "url": f"{server.base}/vuln",
            "match": {"body_contains": VULN_MARKER},
            "previous_status": "FIXED",
        }
        result = retest_one(finding)
        assert result["verdict"] == REGRESSED
        assert server.counter.count == 1

    def test_header_and_regex_match_live(self, server):
        finding = {
            "id": "BUG-HDR",
            "url": f"{server.base}/vuln",
            "match": {
                "header_contains": {"X-Vuln": "yes"},
                "body_regex": r"id=\d+",
            },
        }
        result = retest_one(finding)
        assert result["verdict"] == STILL_VULN

    def test_post_method_with_body_live(self, server):
        finding = {
            "id": "BUG-POST",
            "url": f"{server.base}/vuln",
            "method": "POST",
            "body": "payload=1",
            "match": {"body_contains": VULN_MARKER},
        }
        result = retest_one(finding)
        assert result["verdict"] == STILL_VULN
        assert server.counter.count == 1

    def test_missing_url_is_error_no_request(self, server):
        result = retest_one({"id": "BUG-NOURL", "match": {"status": 200}})
        assert result["verdict"] == ERROR
        assert "url" in result["detail"].lower()
        assert server.counter.count == 0


# ─── 4. Scope gating (fail-closed: no request sent) ─────────────────────────────

class TestRetestOneScopeGating:

    def test_out_of_scope_is_error_and_sends_no_request(self, server):
        # In-scope only target.com; the loopback host is NOT in scope.
        scope = ScopeChecker(["target.com", "*.target.com"])
        sess = _RecordingSession(response=_Resp(200, VULN_MARKER))
        finding = {
            "id": "BUG-OOS",
            "target": "evil.example.org",
            "url": f"{server.base}/vuln",
            "match": {"body_contains": VULN_MARKER},
        }
        result = retest_one(finding, scope=scope, session=sess)
        assert result["verdict"] == ERROR
        assert result["detail"] == "out-of-scope"
        # Fail-closed: zero requests on the injected transport AND zero server hits.
        assert sess.calls == []
        assert server.counter.count == 0

    def test_in_scope_target_passes_gate_and_sends_request(self, server):
        # Treat the loopback host as in-scope via an explicit target override.
        scope = ScopeChecker(["api.internal.test"])
        finding = {
            "id": "BUG-INS",
            "target": "api.internal.test",  # in scope; routed to local server url
            "url": f"{server.base}/vuln",
            "match": {"body_contains": VULN_MARKER},
        }
        result = retest_one(finding, scope=scope)
        assert result["verdict"] == STILL_VULN
        assert server.counter.count == 1

    def test_scope_uses_url_host_when_no_explicit_target(self, server):
        scope = ScopeChecker(["target.com"])
        sess = _RecordingSession(response=_Resp(200, VULN_MARKER))
        finding = {
            "id": "BUG-URLHOST",
            "url": "https://attacker.com/leak",  # host attacker.com not in scope
            "match": {"body_contains": VULN_MARKER},
        }
        result = retest_one(finding, scope=scope, session=sess)
        assert result["verdict"] == ERROR
        assert result["detail"] == "out-of-scope"
        assert sess.calls == []


# ─── 5. Request failure -> ERROR; batch keeps going ─────────────────────────────

class TestRetestFailureHandling:

    def test_unreachable_port_is_error(self):
        port = _free_port()  # nothing is listening here -> connection refused
        finding = {
            "id": "BUG-DEAD",
            "url": f"http://127.0.0.1:{port}/vuln",
            "match": {"body_contains": VULN_MARKER},
            "timeout": 2,
        }
        result = retest_one(finding, timeout=2)
        assert result["verdict"] == ERROR
        assert "request failed" in result["detail"].lower()
        assert result["status"] is None

    def test_injected_transport_exception_is_error(self):
        sess = _RecordingSession(exc=RuntimeError("boom"))
        finding = {"id": "BUG-EXC", "url": "https://x.test/p", "match": {"status": 200}}
        result = retest_one(finding, session=sess)
        assert result["verdict"] == ERROR
        assert "request failed" in result["detail"].lower()
        assert len(sess.calls) == 1

    def test_batch_continues_past_failure(self, server):
        dead_port = _free_port()
        findings = [
            {  # 1: still vulnerable
                "id": "OK-1",
                "url": f"{server.base}/vuln",
                "match": {"body_contains": VULN_MARKER},
            },
            {  # 2: unreachable -> ERROR, must not abort the batch
                "id": "DEAD-2",
                "url": f"http://127.0.0.1:{dead_port}/vuln",
                "match": {"body_contains": VULN_MARKER},
            },
            {  # 3: fixed (runs only if the batch survived #2)
                "id": "OK-3",
                "url": f"{server.base}/fixed",
                "match": {"body_contains": VULN_MARKER},
            },
        ]
        report = retest_batch(findings, timeout=2)
        results = report["results"]
        assert len(results) == 3
        verdicts = {r["id"]: r["verdict"] for r in results}
        assert verdicts["OK-1"] == STILL_VULN
        assert verdicts["DEAD-2"] == ERROR
        assert verdicts["OK-3"] == FIXED
        assert report["summary"] == {
            "still_vuln": 1,
            "fixed": 1,
            "regressed": 0,
            "error": 1,
        }


# ─── Batch + scope integration ──────────────────────────────────────────────────

class TestRetestBatchScope:

    def test_batch_scope_gate_blocks_out_of_scope_finding(self, server):
        scope = ScopeChecker(["in.scope.test"])
        findings = [
            {  # in scope -> retested
                "id": "IN",
                "target": "in.scope.test",
                "url": f"{server.base}/vuln",
                "match": {"body_contains": VULN_MARKER},
            },
            {  # out of scope -> ERROR, no request
                "id": "OUT",
                "target": "out.of.scope.test",
                "url": f"{server.base}/vuln",
                "match": {"body_contains": VULN_MARKER},
            },
        ]
        report = retest_batch(findings, scope=scope)
        verdicts = {r["id"]: r["verdict"] for r in report["results"]}
        assert verdicts["IN"] == STILL_VULN
        assert verdicts["OUT"] == ERROR
        details = {r["id"]: r["detail"] for r in report["results"]}
        assert details["OUT"] == "out-of-scope"
        # Only the in-scope finding ever reached the server.
        assert server.counter.count == 1

    def test_batch_rejects_non_list(self):
        with pytest.raises(ValueError):
            retest_batch({"id": "X"})


# ─── load_findings ──────────────────────────────────────────────────────────────

class TestLoadFindings:

    def test_loads_json_array(self, tmp_path):
        p = tmp_path / "findings.json"
        p.write_text('[{"id": "A", "url": "https://x.test/1"}, {"id": "B", "url": "https://x.test/2"}]')
        findings = load_findings(str(p))
        assert isinstance(findings, list)
        assert [f["id"] for f in findings] == ["A", "B"]

    def test_loads_single_object_as_one_element_list(self, tmp_path):
        p = tmp_path / "one.json"
        p.write_text('{"id": "SOLO", "url": "https://x.test/1"}')
        findings = load_findings(str(p))
        assert len(findings) == 1
        assert findings[0]["id"] == "SOLO"

    def test_loads_wrapped_findings_key(self, tmp_path):
        p = tmp_path / "wrapped.json"
        p.write_text('{"findings": [{"id": "W1", "url": "https://x.test/1"}]}')
        findings = load_findings(str(p))
        assert [f["id"] for f in findings] == ["W1"]

    def test_missing_file_raises_value_error(self, tmp_path):
        with pytest.raises(ValueError):
            load_findings(str(tmp_path / "nope.json"))

    def test_invalid_json_raises_value_error(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json")
        with pytest.raises(ValueError):
            load_findings(str(p))

    def test_non_object_element_raises_value_error(self, tmp_path):
        p = tmp_path / "mixed.json"
        p.write_text('[{"id": "A", "url": "https://x.test"}, "oops"]')
        with pytest.raises(ValueError):
            load_findings(str(p))
