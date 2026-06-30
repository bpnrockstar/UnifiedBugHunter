"""Tests for tools/secret_validate.py — cross-engine reconciliation, org-pattern
scanning, and keyhacks-style liveness validation.

`secret_validate` supplies three importable, deterministic functions:

  * reconcile(hits_lists)  — merge + dedup hits from the trufflehog / gitleaks /
    noseyparker engines (keyed on file+line+normalized value). A verified copy
    wins over an unverified one, detector labels are unioned, and a redacted /
    empty value at the same (file, line) folds into a raw-valued copy instead of
    spawning a duplicate.

  * scan_custom(text)      — run the org regexes from custom_secret_patterns.py
    over a blob of text. Must MATCH on text shaped like the placeholder
    Lenskart / Valyoo formats, and must NOT match on benign text.

  * validate(provider, value, *, network=False) — liveness check. With the
    DEFAULT network=False it must ALWAYS return "unknown" and make NO network
    call whatsoever (importing `requests` is itself part of "touching the wire"
    and must not happen on the default path).

NETWORK DISCIPLINE: the offline tests assert that `requests` is never imported
on the default path. The handful of tests that exercise the network=True branch
inject a FAKE `requests` module into sys.modules via monkeypatch, so a real HTTP
request is never made — the fake records every call and lets us assert verdicts
(verified / invalid / unknown), that the AWS stub makes NO call, and that an
ambiguous 500 degrades to "unknown" rather than a false "invalid".

Imports the module bare (``import secret_validate``); the shared conftest.py adds
``tools/`` to ``sys.path``. Stdlib + pytest only.
"""

import sys

import pytest

import secret_validate
from secret_validate import (
    INVALID,
    UNKNOWN,
    VERIFIED,
    infer_provider,
    reconcile,
    scan_custom,
    validate,
)

# ─── Secret-shaped literals, assembled at runtime ───────────────────────────────
# Built by concatenation so a contiguous real-looking token never appears verbatim
# in source (GitHub push-protection flags those). All are FAKE but match the
# *shape* the detectors / org patterns key on.
GITHUB_TOKEN = "ghp_" + "a" * 36
SLACK_TOKEN = "xox" + "b-123456789012-abcdefghijklmnopqrstuvwx"
AWS_KEY = "AKIA" + "QWERTYUIOP123456"
STRIPE_KEY = "sk_" + "live_" + "B" * 24

# Org-pattern-shaped fakes (must match custom_secret_patterns.py placeholders).
LK_API_KEY = "lk_" + "live_" + "Z" * 26
VALYOO_TOKEN = "valyoo_" + "billing_" + "Q" * 24
INTERNAL_JWT_ISS = '{"iss": "https://auth.lenskart.com/realms/internal"}'
INTERNAL_DB_DSN = "postgres://svcuser:s3cretpw99@db01.valyoo.internal"


# ════════════════════════════════════════════════════════════════════════════════
#  reconcile()
# ════════════════════════════════════════════════════════════════════════════════

class TestReconcileBasics:
    def test_empty_inputs_return_empty_list(self):
        assert reconcile([]) == []
        assert reconcile([[], [], []]) == []
        assert reconcile([None, None]) == []

    def test_single_hit_passes_through_normalized(self):
        out = reconcile([[{"detector": "Stripe", "file": "a.py", "line": 3,
                           "value": STRIPE_KEY, "verified": True}]])
        assert len(out) == 1
        hit = out[0]
        # Normalized schema keys are present.
        for k in ("detectors", "provider", "file", "line", "value",
                  "verified", "severity", "description"):
            assert k in hit
        assert hit["detectors"] == ["Stripe"]
        assert hit["provider"] == "stripe"
        assert hit["file"] == "a.py"
        assert hit["line"] == 3
        assert hit["verified"] is True

    def test_flat_hit_list_is_accepted(self):
        # A single flat list (not list-of-lists) is treated as one engine's output.
        out = reconcile([{"detector": "GitHub", "file": "x", "line": 1,
                          "value": GITHUB_TOKEN}])
        assert len(out) == 1
        assert out[0]["provider"] == "github"

    def test_non_dict_entries_are_ignored(self):
        out = reconcile([["not a dict", 42, None,
                          {"detector": "Slack", "file": "f", "line": 2,
                           "value": SLACK_TOKEN}]])
        assert len(out) == 1
        assert out[0]["provider"] == "slack"


class TestReconcileDedup:
    def test_three_engines_same_secret_collapse_to_one(self):
        """The same key found by all three engines at the same file+line merges
        into ONE hit with all three detector labels unioned."""
        th = [{"detector": "Stripe", "file": "cfg.py", "line": 10,
               "value": STRIPE_KEY, "verified": False}]
        gl = [{"RuleID": "stripe-access-token", "File": "cfg.py", "StartLine": 10,
               "Secret": STRIPE_KEY, "Verified": False}]
        npk = [{"detector": "stripe", "file": "cfg.py", "line": 10,
                "value": STRIPE_KEY, "verified": False}]
        out = reconcile([th, gl, npk])
        assert len(out) == 1
        assert out[0]["detectors"] == sorted(
            ["Stripe", "stripe-access-token", "stripe"])

    def test_verified_copy_wins(self):
        """If any merged copy is verified, the merged hit is verified=True."""
        unverified = {"detector": "GitHub", "file": "f.py", "line": 5,
                      "value": GITHUB_TOKEN, "verified": False}
        verified = {"detector": "github-pat", "file": "f.py", "line": 5,
                    "value": GITHUB_TOKEN, "verified": True}
        out = reconcile([[unverified], [verified]])
        assert len(out) == 1
        assert out[0]["verified"] is True

    def test_verified_order_independent(self):
        """Verified-wins holds regardless of which engine reported first."""
        unverified = {"detector": "GitHub", "file": "f.py", "line": 5,
                      "value": GITHUB_TOKEN, "verified": False}
        verified = {"detector": "github-pat", "file": "f.py", "line": 5,
                    "value": GITHUB_TOKEN, "verified": True}
        out = reconcile([[verified], [unverified]])
        assert len(out) == 1
        assert out[0]["verified"] is True

    def test_distinct_secrets_not_merged(self):
        out = reconcile([[
            {"detector": "GitHub", "file": "f", "line": 1, "value": GITHUB_TOKEN},
            {"detector": "Slack", "file": "f", "line": 2, "value": SLACK_TOKEN},
        ]])
        assert len(out) == 2

    def test_same_value_different_line_not_merged(self):
        out = reconcile([[
            {"detector": "GitHub", "file": "f", "line": 1, "value": GITHUB_TOKEN},
            {"detector": "GitHub", "file": "f", "line": 9, "value": GITHUB_TOKEN},
        ]])
        assert len(out) == 2

    def test_value_normalization_collapses_quoted_and_cased(self):
        """Surrounding quotes / whitespace / case differences collapse together."""
        a = {"detector": "GitHub", "file": "f", "line": 3, "value": GITHUB_TOKEN}
        b = {"detector": "github", "file": "f", "line": 3,
             "value": '  "' + GITHUB_TOKEN + '"  '}
        out = reconcile([[a], [b]])
        assert len(out) == 1
        assert out[0]["detectors"] == sorted(["GitHub", "github"])

    def test_worst_severity_is_kept(self):
        a = {"detector": "x", "file": "f", "line": 1, "value": "v", "severity": "low"}
        b = {"detector": "y", "file": "f", "line": 1, "value": "v", "severity": "critical"}
        out = reconcile([[a], [b]])
        assert len(out) == 1
        assert out[0]["severity"] == "critical"


class TestReconcileRedactionFold:
    """The subtle case: secrets_ingest redacts trufflehog/gitleaks values at parse
    time, but parse_noseyparker keeps the raw snippet. The redacted placeholder and
    the raw value at the SAME file+line are the same secret and must NOT split."""

    def test_redacted_and_raw_fold_into_one(self):
        redacted = {"detector": "Slack", "file": "app.js", "line": 7,
                    "value": "[REDACTED:SLACK_TOKEN]", "verified": True}
        raw = {"detector": "slack-token", "file": "app.js", "line": 7,
               "value": SLACK_TOKEN, "verified": False}
        out = reconcile([[redacted], [raw]])
        assert len(out) == 1, "redacted + raw at same loc must collapse"
        # Verified flag survives the fold.
        assert out[0]["verified"] is True
        # Both detector labels are unioned.
        assert out[0]["detectors"] == sorted(["Slack", "slack-token"])
        # The comparable (raw) value is preferred as the representative.
        assert out[0]["value"] == SLACK_TOKEN

    def test_raw_then_redacted_also_folds(self):
        # Both orderings must collapse to one verified hit with unioned detectors.
        # (The representative VALUE that survives is ordering-dependent here: when
        # a verified-but-redacted copy folds onto an unverified raw copy, the
        # verified copy becomes the representative — so the value may be the
        # placeholder. The load-bearing guarantees are the single hit + verified
        # flag + unioned labels; the value is one of the two known forms.)
        raw = {"detector": "slack-token", "file": "app.js", "line": 7,
               "value": SLACK_TOKEN, "verified": False}
        redacted = {"detector": "Slack", "file": "app.js", "line": 7,
                    "value": "[REDACTED:SLACK_TOKEN]", "verified": True}
        out = reconcile([[raw], [redacted]])
        assert len(out) == 1
        assert out[0]["verified"] is True
        assert out[0]["detectors"] == sorted(["Slack", "slack-token"])
        assert out[0]["value"] in (SLACK_TOKEN, "[REDACTED:SLACK_TOKEN]")

    def test_redacted_without_known_loc_does_not_overfold(self):
        """Without file+line we cannot safely fold; distinct entries stay distinct."""
        a = {"detector": "Slack", "file": None, "line": None,
             "value": "[REDACTED:SLACK_TOKEN]"}
        b = {"detector": "github", "file": None, "line": None, "value": GITHUB_TOKEN}
        out = reconcile([[a], [b]])
        assert len(out) == 2


# ════════════════════════════════════════════════════════════════════════════════
#  scan_custom()
# ════════════════════════════════════════════════════════════════════════════════

class TestScanCustomMatches:
    def test_lenskart_api_key_matches(self):
        hits = scan_custom("config: api_key = " + LK_API_KEY + "\n")
        names = [d for h in hits for d in h["detectors"]]
        assert "lenskart_api_key" in names
        hit = next(h for h in hits if "lenskart_api_key" in h["detectors"])
        assert hit["value"] == LK_API_KEY
        assert hit["severity"] == "high"
        assert hit["verified"] is False
        assert hit["line"] == 1

    def test_valyoo_internal_token_matches(self):
        hits = scan_custom("export TOKEN=" + VALYOO_TOKEN)
        names = [d for h in hits for d in h["detectors"]]
        assert "valyoo_internal_token" in names

    def test_valyoo_internal_jwt_issuer_matches(self):
        hits = scan_custom(INTERNAL_JWT_ISS)
        names = [d for h in hits for d in h["detectors"]]
        assert "valyoo_internal_jwt_issuer" in names

    def test_lenskart_internal_db_dsn_matches(self):
        hits = scan_custom("DATABASE_URL=" + INTERNAL_DB_DSN + "/prod")
        names = [d for h in hits for d in h["detectors"]]
        assert "lenskart_internal_db_dsn" in names

    def test_line_number_is_one_based(self):
        text = "line1\nline2\nkey=" + LK_API_KEY + "\n"
        hits = scan_custom(text)
        hit = next(h for h in hits if "lenskart_api_key" in h["detectors"])
        assert hit["line"] == 3

    def test_multiple_matches_across_lines(self):
        text = "a = " + LK_API_KEY + "\nb = " + VALYOO_TOKEN + "\n"
        hits = scan_custom(text)
        names = sorted({d for h in hits for d in h["detectors"]})
        assert "lenskart_api_key" in names
        assert "valyoo_internal_token" in names


class TestScanCustomBenign:
    @pytest.mark.parametrize("text", [
        "",
        "just a normal config file with nothing secret in it",
        "lk_live_short",                                  # too short for the floor
        "valyoo_token_without_underscore_service_split",  # wrong shape
        '{"iss": "https://accounts.google.com"}',         # external IdP, not internal
        "postgres://localhost:5432/devdb",                # no creds, no org host
        "API_KEY=changeme  # placeholder, not a real key",
    ])
    def test_benign_text_produces_no_hits(self, text):
        assert scan_custom(text) == []

    def test_non_string_input_is_safe(self):
        assert scan_custom(None) == []
        assert scan_custom(12345) == []


# ════════════════════════════════════════════════════════════════════════════════
#  validate() — OFFLINE (default network=False): never touches the wire
# ════════════════════════════════════════════════════════════════════════════════

class TestValidateOffline:
    def test_module_import_does_not_pull_in_requests(self):
        # Importing the module (done at top of file) must not import requests.
        # We can't un-import what other modules may have loaded, but we CAN assert
        # secret_validate never bound a module-level `requests` name.
        assert not hasattr(secret_validate, "requests")

    @pytest.mark.parametrize("provider", ["github", "slack", "google", "stripe", "aws"])
    def test_default_is_unknown_and_offline(self, provider, monkeypatch):
        """Default network=False ALWAYS returns 'unknown' and makes no call.

        We poison the lazy import so that if validate() ever tried to import
        requests on the default path, the test would error loudly."""
        sentinel = {"called": False}

        class _Boom:
            def __getattr__(self, _name):
                sentinel["called"] = True
                raise AssertionError("requests must NOT be imported on the offline path")

        monkeypatch.setitem(sys.modules, "requests", _Boom())
        assert validate(provider, "anything-" + provider) == UNKNOWN
        assert sentinel["called"] is False

    def test_unknown_provider_is_unknown(self):
        assert validate("not-a-real-provider", "x", network=True) == UNKNOWN

    def test_empty_value_is_unknown(self):
        assert validate("github", "", network=True) == UNKNOWN
        assert validate("github", None, network=True) == UNKNOWN

    def test_label_provider_is_inferred(self):
        # A human label like "Stripe" still maps to the stripe slug -> still
        # offline-unknown without network.
        assert validate("Stripe", STRIPE_KEY) == UNKNOWN


# ════════════════════════════════════════════════════════════════════════════════
#  validate() — NETWORK path with a MOCKED requests (no real HTTP ever)
# ════════════════════════════════════════════════════════════════════════════════

class _FakeResponse:
    def __init__(self, status_code, json_body=None):
        self.status_code = status_code
        self._json_body = json_body

    def json(self):
        if self._json_body is None:
            raise ValueError("no json body")
        return self._json_body


class _FakeRequests:
    """Stand-in for the `requests` module. Records every call; returns a queued
    response. Asserts (via the recorded log) that the AWS path never reaches here."""

    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, headers=None, timeout=None):
        self.calls.append({"method": method, "url": url,
                           "headers": headers or {}, "timeout": timeout})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.fixture
def fake_requests(monkeypatch):
    """Install a fake `requests` into sys.modules so validate()'s lazy
    `import requests` resolves to our stub. No real network call is possible."""
    def _install(response):
        fake = _FakeRequests(response)
        monkeypatch.setitem(sys.modules, "requests", fake)
        return fake
    return _install


class TestValidateNetworkMocked:
    def test_github_200_is_verified(self, fake_requests):
        fake = fake_requests(_FakeResponse(200))
        assert validate("github", GITHUB_TOKEN, network=True) == VERIFIED
        assert len(fake.calls) == 1
        assert fake.calls[0]["url"] == "https://api.github.com/user"

    def test_github_401_is_invalid(self, fake_requests):
        fake_requests(_FakeResponse(401))
        assert validate("github", GITHUB_TOKEN, network=True) == INVALID

    def test_github_403_is_invalid(self, fake_requests):
        fake_requests(_FakeResponse(403))
        assert validate("github", GITHUB_TOKEN, network=True) == INVALID

    def test_ambiguous_500_is_unknown_not_invalid(self, fake_requests):
        """A 5xx is ambiguous (server error / outage) -> 'unknown', never a false
        'invalid'."""
        fake_requests(_FakeResponse(500))
        assert validate("github", GITHUB_TOKEN, network=True) == UNKNOWN

    def test_rate_limit_429_is_unknown(self, fake_requests):
        fake_requests(_FakeResponse(429))
        assert validate("github", GITHUB_TOKEN, network=True) == UNKNOWN

    def test_slack_ok_true_is_verified(self, fake_requests):
        fake_requests(_FakeResponse(200, {"ok": True}))
        assert validate("slack", SLACK_TOKEN, network=True) == VERIFIED

    def test_slack_ok_false_is_unknown(self, fake_requests):
        # Slack returns 200 with {"ok": false} for a dead token; the predicate
        # fails but 200 is not 401/403, so the verdict degrades to unknown.
        fake_requests(_FakeResponse(200, {"ok": False}))
        assert validate("slack", SLACK_TOKEN, network=True) == UNKNOWN

    def test_stripe_200_is_verified(self, fake_requests):
        fake_requests(_FakeResponse(200))
        assert validate("stripe", STRIPE_KEY, network=True) == VERIFIED

    def test_stripe_401_is_invalid(self, fake_requests):
        fake_requests(_FakeResponse(401))
        assert validate("stripe", STRIPE_KEY, network=True) == INVALID

    def test_google_200_is_verified(self, fake_requests):
        fake = fake_requests(_FakeResponse(200))
        assert validate("google", "AIza" + "x" * 35, network=True) == VERIFIED
        assert "googleapis.com" in fake.calls[0]["url"]

    def test_network_exception_is_unknown(self, fake_requests):
        fake_requests(ConnectionError("dns blew up"))
        assert validate("github", GITHUB_TOKEN, network=True) == UNKNOWN

    def test_aws_stub_makes_no_call_and_is_unknown(self, fake_requests):
        """AWS liveness needs the paired SECRET to SigV4-sign, so it is a
        documented stub: it returns 'unknown' and must make NO request — the fake
        requests must record zero calls."""
        fake = fake_requests(_FakeResponse(200))
        assert validate("aws", AWS_KEY, network=True) == UNKNOWN
        assert fake.calls == [], "AWS path must not hit the network"


# ════════════════════════════════════════════════════════════════════════════════
#  infer_provider() — supporting surface
# ════════════════════════════════════════════════════════════════════════════════

class TestInferProvider:
    @pytest.mark.parametrize("detector,value,expected", [
        ("AWS", "", "aws"),
        ("", "AKIA" + "X" * 16, "aws"),
        ("GitHub", "", "github"),
        ("", "ghp_" + "y" * 36, "github"),
        ("Slack", "", "slack"),
        ("", "xoxb-1-2", "slack"),
        ("Stripe", "", "stripe"),
        ("Google", "", "google"),
        ("totally-unknown-detector", "plain-value", ""),
    ])
    def test_inference(self, detector, value, expected):
        assert infer_provider(detector, value) == expected
