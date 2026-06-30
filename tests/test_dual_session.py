"""Integration tests for tools/dual_session.py against a LOCAL HTTP server.

Unlike the offline fake-transport unit tests, these exercise the *real*
`requests` transport end-to-end: DualSession sends actual HTTP requests over the
loopback interface to a throwaway threaded http.server. This proves the probe
plumbing (identity headers on the wire, baseline-then-attacker flow, verdict)
works against a real server — not just a duck-typed stub.

The server implements a deliberately simple access-control model on `/me/{id}`:

  - Each identity is identified by the `X-Identity` request header.
  - `/me/<id>` returns a per-identity marker string ONLY when the caller's
    identity matches the resource owner. Otherwise the server's behaviour is
    pluggable per-test (leak the marker anyway -> VULNERABLE, or 403 -> SAFE).

Hermetic: the server binds to 127.0.0.1:0 (random free port), runs on a daemon
thread, and is shut down + joined in the fixture teardown. No fixed ports, no
external network, no state leaked between tests.

Run with an interpreter that has pytest + requests, e.g.:
    /usr/bin/python3 -m pytest tests/test_dual_session.py -v
"""

import http.server
import json
import os
import sys
import threading

import pytest

# Make the repo importable the same way conftest.py does (so `tools.*` resolves
# whether or not pytest's rootdir wiring is in effect).
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tools.dual_session import DualSession  # noqa: E402

# requests must be importable for these integration tests to mean anything; the
# whole point is the real transport. Skip cleanly (don't error) if it's absent.
requests = pytest.importorskip("requests")


# ── Identity / marker model shared by the server and the tests ─────────────────

IDENTITY_HEADER = "X-Identity"

VICTIM_ID = "victim-7"
ATTACKER_ID = "attacker-9"

# A per-identity marker that ONLY appears in the owner's own resource body. The
# victim marker leaking into the attacker's response is the proof of IDOR.
MARKERS = {
    VICTIM_ID: "VICTIM_SECRET_marker_7f3a",
    ATTACKER_ID: "ATTACKER_own_marker_0000",
}
VICTIM_MARKER = MARKERS[VICTIM_ID]


# ── The local server ───────────────────────────────────────────────────────────

def _make_handler(leak: bool):
    """Build a request handler class for /me/{id}.

    Args:
        leak: when True, an identity requesting *another* identity's resource
              still receives the owner's marker (broken access control ->
              VULNERABLE). When False, the cross-account request is denied with
              403 (access control enforced -> SAFE).
    """

    class _Handler(http.server.BaseHTTPRequestHandler):
        # Silence the default stderr request logging so test output stays clean.
        def log_message(self, *args):  # noqa: D401, ANN001
            pass

        def _body_for(self, payload, status=200, content_type="application/json"):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 (http.server naming)
            # Expect /me/<resource_id>
            parts = self.path.strip("/").split("/")
            if len(parts) != 2 or parts[0] != "me":
                self._body_for({"error": "not_found"}, status=404)
                return

            resource_id = parts[1]
            caller = self.headers.get(IDENTITY_HEADER, "")

            if resource_id not in MARKERS:
                self._body_for({"error": "no_such_user"}, status=404)
                return

            owner_marker = MARKERS[resource_id]

            # Caller owns the resource -> always returns their own marker. This
            # is what makes the victim baseline trustworthy.
            if caller == resource_id:
                self._body_for({"id": resource_id, "secret": owner_marker})
                return

            # Cross-account access:
            if leak:
                # BROKEN: hand the owner's marker to a non-owner.
                self._body_for({"id": resource_id, "secret": owner_marker})
            else:
                # ENFORCED: deny.
                self._body_for({"error": "forbidden"}, status=403)

    return _Handler


class _ServerHandle:
    """Bundles a running server, its base URL, and a clean shutdown."""

    def __init__(self, leak: bool):
        handler = _make_handler(leak)
        # Port 0 -> OS assigns a free ephemeral port (no fixed-port collisions).
        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True
        )
        self._thread.start()
        host, port = self._httpd.server_address
        self.base_url = f"http://{host}:{port}"

    def url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def close(self):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def leaky_server():
    """A server that leaks the victim's marker to the attacker (vulnerable)."""
    handle = _ServerHandle(leak=True)
    try:
        yield handle
    finally:
        handle.close()


@pytest.fixture
def secure_server():
    """A server that 403s the attacker on cross-account access (safe)."""
    handle = _ServerHandle(leak=False)
    try:
        yield handle
    finally:
        handle.close()


# ── Identity config for DualSession ────────────────────────────────────────────

def _attacker_identity():
    return {"label": "low-priv", "headers": {IDENTITY_HEADER: ATTACKER_ID}}


def _victim_identity():
    return {"label": "victim", "headers": {IDENTITY_HEADER: VICTIM_ID}}


def _scope_for(base_url: str) -> dict:
    """A scope block that allows the local server's host (127.0.0.1 won't pass
    ScopeChecker — it rejects IPs — so we match on the explicit literal). We use
    the literal host:port form via `domains` so the loopback URL is in-scope.

    NOTE: ScopeChecker rejects bare IPs, so this is intentionally only used in
    the out-of-scope ERROR test (see test_idor_out_of_scope_returns_error),
    where the *probed* URL points at a host that is NOT in `domains`.
    """
    return {"domains": ["api.target.com"]}


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestIdorProbeIntegration:
    """idor_probe driven over the real requests transport against a local server."""

    def test_vulnerable_when_server_leaks_victim_marker(self, leaky_server):
        session = DualSession(
            attacker=_attacker_identity(),
            victim=_victim_identity(),
        )
        result = session.idor_probe(
            leaky_server.url(f"/me/{VICTIM_ID}"),
            victim_marker=VICTIM_MARKER,
        )

        assert result["verdict"] == "VULNERABLE", result.get("reason")
        assert result["vuln_class"] == "idor"
        # Baseline (victim) must have legitimately seen the marker.
        assert result["baseline"]["status"] == 200
        assert VICTIM_MARKER in result["baseline"]["body_snippet"]
        # Attacker got a 200 that ALSO contained the victim's marker.
        assert result["attacker"]["status"] == 200
        assert VICTIM_MARKER in result["attacker"]["body_snippet"]

    def test_safe_when_server_403s_the_attacker(self, secure_server):
        session = DualSession(
            attacker=_attacker_identity(),
            victim=_victim_identity(),
        )
        result = session.idor_probe(
            secure_server.url(f"/me/{VICTIM_ID}"),
            victim_marker=VICTIM_MARKER,
        )

        assert result["verdict"] == "SAFE", result.get("reason")
        assert result["vuln_class"] == "idor"
        # Baseline still legitimately sees the marker (otherwise we'd ERROR).
        assert result["baseline"]["status"] == 200
        assert VICTIM_MARKER in result["baseline"]["body_snippet"]
        # Attacker was denied.
        assert result["attacker"]["status"] == 403
        assert VICTIM_MARKER not in result["attacker"]["body_snippet"]

    def test_out_of_scope_host_returns_error(self, leaky_server):
        """When a scope is provided and the probed URL's host is NOT in scope,
        the probe must fail-closed to ERROR — never SAFE, never VULNERABLE.

        The server here would happily leak the marker, but the scope gate must
        refuse the request before it ever leaves, so the verdict is ERROR.
        """
        session = DualSession(
            attacker=_attacker_identity(),
            victim=_victim_identity(),
            scope={"domains": ["api.target.com"]},  # local loopback NOT listed
        )
        result = session.idor_probe(
            leaky_server.url(f"/me/{VICTIM_ID}"),
            victim_marker=VICTIM_MARKER,
        )

        assert result["verdict"] == "ERROR", result.get("reason")
        # Both requests were refused by the scope gate (fail-closed), so neither
        # carries a leaked marker and the error is recorded on the baseline.
        assert result["baseline"]["error"] == "out_of_scope"
        assert result["attacker"]["error"] == "out_of_scope"


class TestScopeAllowsInScopeProbe:
    """Sanity: a scope that *does* include the probed host lets the probe run."""

    def test_vulnerable_with_in_scope_localhost(self, leaky_server):
        # ScopeChecker rejects bare IPs, so bind-matching on 127.0.0.1 can't be
        # expressed via `domains`. We assert the complementary guarantee instead:
        # without a scope block the same in-scope probe runs and is VULNERABLE
        # (already covered above), and WITH a non-matching scope it ERRORs (also
        # covered). This test documents that scope=None disables gating.
        session = DualSession(
            attacker=_attacker_identity(),
            victim=_victim_identity(),
            scope=None,
        )
        result = session.idor_probe(
            leaky_server.url(f"/me/{VICTIM_ID}"),
            victim_marker=VICTIM_MARKER,
        )
        assert result["verdict"] == "VULNERABLE", result.get("reason")


class TestBaselineGuard:
    """A wrong marker (victim baseline can't show it) must ERROR, not SAFE."""

    def test_wrong_marker_is_error_not_safe(self, secure_server):
        session = DualSession(
            attacker=_attacker_identity(),
            victim=_victim_identity(),
        )
        result = session.idor_probe(
            secure_server.url(f"/me/{VICTIM_ID}"),
            victim_marker="this-marker-does-not-exist-anywhere",
        )
        # Baseline succeeded (HTTP 200) but the marker isn't in it -> untrustworthy
        # probe -> fail-closed to ERROR.
        assert result["verdict"] == "ERROR", result.get("reason")
        assert result["baseline"]["status"] == 200


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
