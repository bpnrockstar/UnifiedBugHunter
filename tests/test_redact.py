"""Tests for redact.py — evidence-hygiene secret/PII redaction.

This is privacy-critical code: every secret category must be redacted, and the
allowlist of obvious non-secrets (canonical EXAMPLE keys, loopback IPs) must be
preserved verbatim. ``redact_finding`` must deep-redact nested structures while
never mutating its input.

Imports the module bare (``import redact`` / ``from redact import ...``); the
shared conftest.py adds ``tools/`` to ``sys.path``.
"""

import copy

import pytest

import redact
from redact import (
    CATEGORIES,
    PLACEHOLDERS,
    redact_finding,
    redact_text,
    redaction_report,
)

# A canonical, well-formed JWT (HS256). Not preceded by a ``token:`` key, so the
# narrow JWT rule — not the generic secret-KV rule — is the one that fires.
JWT = (
    "eyJhbGciOiJIUzI1NiJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
# A realistic (fake) AWS access key id — NOT the allowlisted EXAMPLE one.
AWS_KEY = "AKIA1234567890ABCDEF"
GITHUB_TOKEN = "ghp_" + "A" * 36
GOOGLE_KEY = "AIza" + "B" * 35
# Assembled at runtime so the literal token never appears in source
# (GitHub push-protection flags a contiguous xoxb-... string as a real secret).
SLACK_TOKEN = "xox" + "b-123456789012-abcdefghijklmno"
OPENAI_KEY = "sk-" + "C" * 40
PEM_BLOCK = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAxFakeKeyMaterialForTestingOnlyNotARealKey1234567890\n"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/==\n"
    "-----END RSA PRIVATE KEY-----"
)


# ─── Per-category redaction ──────────────────────────────────────────────────


class TestEachCategoryRedacted:
    """Every supported secret/PII category is replaced by its placeholder."""

    def test_jwt(self):
        out = redact_text(JWT)
        assert out == PLACEHOLDERS["jwt"]
        assert "eyJ" not in out

    def test_jwt_embedded_in_text(self):
        out = redact_text(f"callback?token_value={JWT}&next=/")
        assert PLACEHOLDERS["jwt"] in out
        assert "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" not in out

    def test_aws_access_key(self):
        out = redact_text(f"aws_key={AWS_KEY}")
        assert PLACEHOLDERS["aws_key"] in out
        assert AWS_KEY not in out

    @pytest.mark.parametrize("prefix", ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"])
    def test_github_token_prefixes(self, prefix):
        token = prefix + "Z" * 36
        # Neutral context: a secret-like key (token/secret/...) would trip the
        # broader generic-secret rule first and mask this as [REDACTED:SECRET].
        out = redact_text(f"found {token} in bundle.js")
        assert PLACEHOLDERS["github_token"] in out
        assert token not in out

    def test_google_api_key(self):
        out = redact_text(f"&key={GOOGLE_KEY}")
        assert PLACEHOLDERS["google_api_key"] in out
        assert GOOGLE_KEY not in out

    @pytest.mark.parametrize(
        "token",
        [
            "xox" + "b-123456789012-abcdefghijklmno",
            "xox" + "p-987654321098-zyxwvutsrqponml",
            "xox" + "a-111111111111-aaaaaaaaaaaaaaa",
        ],
    )
    def test_slack_token(self, token):
        out = redact_text(f"slack: {token}")
        assert PLACEHOLDERS["slack_token"] in out
        assert token not in out

    @pytest.mark.parametrize(
        "key",
        ["sk-" + "C" * 40, "sk-proj-" + "D" * 40, "sk-ant-" + "E" * 40],
    )
    def test_openai_style_key(self, key):
        out = redact_text(f"OPENAI_API_KEY was leaked: {key} end")
        assert PLACEHOLDERS["openai_key"] in out
        assert key not in out

    def test_bearer_authorization_header(self):
        out = redact_text("Authorization: Bearer abcdef0123456789xyz")
        # Scheme/label preserved, value gone.
        assert out.startswith("Authorization: Bearer ")
        assert PLACEHOLDERS["authorization"] in out
        assert "abcdef0123456789xyz" not in out

    def test_bare_bearer_token(self):
        out = redact_text("sent Bearer abcdef0123456789xyz to server")
        assert "Bearer " in out
        assert PLACEHOLDERS["authorization"] in out
        assert "abcdef0123456789xyz" not in out

    def test_cookie_header(self):
        out = redact_text("Cookie: session=secretval123; theme=dark")
        assert out.startswith("Cookie: ")
        assert PLACEHOLDERS["cookie"] in out
        assert "secretval123" not in out

    def test_set_cookie_header(self):
        out = redact_text("Set-Cookie: auth=topsecretvalue; HttpOnly")
        assert out.lower().startswith("set-cookie: ")
        assert PLACEHOLDERS["cookie"] in out
        assert "topsecretvalue" not in out

    def test_pem_private_key_block(self):
        out = redact_text(PEM_BLOCK)
        assert out == PLACEHOLDERS["private_key"]
        assert "PRIVATE KEY" not in out
        assert "MIIEpAIB" not in out

    def test_pem_private_key_block_inline(self):
        text = f"key follows:\n{PEM_BLOCK}\nend"
        out = redact_text(text)
        assert PLACEHOLDERS["private_key"] in out
        assert "BEGIN RSA PRIVATE KEY" not in out

    def test_email(self):
        out = redact_text("reach me at bob@corp.io please")
        assert PLACEHOLDERS["email"] in out
        assert "bob@corp.io" not in out

    def test_ipv4(self):
        out = redact_text("origin was 198.51.100.23 today")
        assert PLACEHOLDERS["ip"] in out
        assert "198.51.100.23" not in out

    def test_generic_secret_kv(self):
        out = redact_text('password="hunter2longpass"')
        assert PLACEHOLDERS["secret"] in out
        assert "hunter2longpass" not in out


# ─── Allowlist preservation ──────────────────────────────────────────────────


class TestAllowlistPreserved:
    """Obvious non-secrets must survive redaction untouched."""

    def test_aws_example_key_untouched(self):
        # AWS's canonical published fake key — never a live secret.
        assert redact_text("AKIAIOSFODNN7EXAMPLE") == "AKIAIOSFODNN7EXAMPLE"

    def test_aws_example_key_inline_untouched(self):
        text = "use AKIAIOSFODNN7EXAMPLE in docs"
        assert redact_text(text) == text
        assert PLACEHOLDERS["aws_key"] not in redact_text(text)

    def test_loopback_ip_untouched(self):
        assert redact_text("127.0.0.1") == "127.0.0.1"

    def test_loopback_ip_inline_untouched(self):
        text = "bound to 127.0.0.1:8080 locally"
        out = redact_text(text)
        assert "127.0.0.1" in out
        assert PLACEHOLDERS["ip"] not in out

    @pytest.mark.parametrize("ip", ["0.0.0.0", "255.255.255.255"])
    def test_other_allowlisted_ips_untouched(self, ip):
        assert redact_text(ip) == ip

    def test_example_email_untouched(self):
        # Contains the "example" allowlist substring.
        text = "alice@example.org"
        assert redact_text(text) == text

    @pytest.mark.parametrize(
        "placeholder_value",
        ["your_api_key_here", "changeme", "placeholder", "dummy", "<token>"],
    )
    def test_placeholder_secret_values_untouched(self, placeholder_value):
        text = f"api_key={placeholder_value}"
        out = redact_text(text)
        assert PLACEHOLDERS["secret"] not in out
        assert placeholder_value in out

    def test_allowlist_is_case_insensitive(self):
        # "EXAMPLE" substring still suppresses redaction.
        text = "AKIAEXAMPLE000000000"
        out = redact_text(text)
        assert PLACEHOLDERS["aws_key"] not in out


# ─── redact_finding: deep recursion + no mutation ────────────────────────────


class TestRedactFinding:

    def _sample(self):
        return {
            "id": "FND-1",
            "severity": "high",
            "evidence": GITHUB_TOKEN,
            "request": {
                "headers": {
                    "Authorization": "Authorization: Bearer abcdef0123456789longtoken",
                    "Cookie": "Cookie: session=secretcookieval; a=b",
                },
                "tokens": [JWT, OPENAI_KEY],
            },
            "ips_seen": ["198.51.100.23", "203.0.113.5"],
            "count": 7,
            "verified": True,
            "score": 9.1,
            "notes": None,
        }

    def test_deep_redacts_nested_dict_values(self):
        out = redact_finding(self._sample())
        assert out["evidence"] == PLACEHOLDERS["github_token"]
        auth = out["request"]["headers"]["Authorization"]
        assert PLACEHOLDERS["authorization"] in auth
        assert "abcdef0123456789longtoken" not in auth
        cookie = out["request"]["headers"]["Cookie"]
        assert PLACEHOLDERS["cookie"] in cookie
        assert "secretcookieval" not in cookie

    def test_deep_redacts_nested_list_values(self):
        out = redact_finding(self._sample())
        assert out["request"]["tokens"][0] == PLACEHOLDERS["jwt"]
        assert out["request"]["tokens"][1] == PLACEHOLDERS["openai_key"]
        assert out["ips_seen"] == [PLACEHOLDERS["ip"], PLACEHOLDERS["ip"]]

    def test_dict_keys_are_not_redacted(self):
        # Field names are structure, not evidence — keys must be preserved
        # even when they look like secrets.
        finding = {"Authorization": "Bearer abcdef0123456789longtoken"}
        out = redact_finding(finding)
        assert "Authorization" in out

    def test_non_string_scalars_preserved(self):
        out = redact_finding(self._sample())
        assert out["count"] == 7
        assert out["verified"] is True
        assert out["score"] == 9.1
        assert out["notes"] is None

    def test_does_not_mutate_input(self):
        finding = self._sample()
        before = copy.deepcopy(finding)
        redact_finding(finding)
        assert finding == before, "redact_finding must not mutate its argument"

    def test_returns_new_object(self):
        finding = self._sample()
        out = redact_finding(finding)
        assert out is not finding
        assert out["request"] is not finding["request"]
        assert out["request"]["tokens"] is not finding["request"]["tokens"]

    def test_tuple_values_redacted_and_stay_tuples(self):
        finding = {"pair": (GITHUB_TOKEN, "harmless")}
        out = redact_finding(finding)
        assert isinstance(out["pair"], tuple)
        assert out["pair"][0] == PLACEHOLDERS["github_token"]
        assert out["pair"][1] == "harmless"

    def test_clean_finding_unchanged_in_value(self):
        finding = {"title": "IDOR on /orders", "severity": "medium"}
        out = redact_finding(finding)
        assert out == finding
        assert out is not finding


# ─── keep_ips flag ───────────────────────────────────────────────────────────


class TestKeepIpsFlag:

    def test_keep_ips_preserves_ipv4(self):
        text = "callback from 198.51.100.23 received"
        out = redact_text(text, keep_ips=True)
        assert "198.51.100.23" in out
        assert PLACEHOLDERS["ip"] not in out

    def test_keep_ips_false_redacts_ipv4(self):
        out = redact_text("198.51.100.23", keep_ips=False)
        assert out == PLACEHOLDERS["ip"]

    def test_keep_ips_still_redacts_other_categories(self):
        text = f"ip 198.51.100.23 token {GITHUB_TOKEN}"
        out = redact_text(text, keep_ips=True)
        assert "198.51.100.23" in out
        assert PLACEHOLDERS["github_token"] in out

    def test_keep_ips_in_redact_finding(self):
        finding = {"ip": "198.51.100.23", "key": GITHUB_TOKEN}
        out = redact_finding(finding, keep_ips=True)
        assert out["ip"] == "198.51.100.23"
        assert out["key"] == PLACEHOLDERS["github_token"]

    def test_keep_ips_report_reports_zero_ips(self):
        report = redaction_report("198.51.100.23", keep_ips=True)
        assert report["ip"] == 0

    def test_default_report_counts_ip(self):
        report = redaction_report("198.51.100.23")
        assert report["ip"] == 1


# ─── redaction_report ────────────────────────────────────────────────────────


class TestRedactionReport:

    def test_report_has_entry_for_every_category(self):
        report = redaction_report("nothing sensitive here")
        assert set(report.keys()) == set(CATEGORIES)
        assert all(v == 0 for v in report.values())

    def test_report_counts_multiple_same_category(self):
        text = f"{GITHUB_TOKEN} and {('gho_' + 'B' * 36)}"
        assert redaction_report(text)["github_token"] == 2

    def test_report_excludes_allowlisted_matches(self):
        # The EXAMPLE key matches the AWS pattern but is allowlisted.
        assert redaction_report("AKIAIOSFODNN7EXAMPLE")["aws_key"] == 0

    def test_report_total_matches_number_of_placeholders(self):
        text = (
            f"{AWS_KEY} {GITHUB_TOKEN} {OPENAI_KEY} "
            f"bob@corp.io 198.51.100.23"
        )
        report = redaction_report(text)
        redacted = redact_text(text)
        total = sum(report.values())
        placeholder_count = redacted.count("[REDACTED:")
        assert total == placeholder_count == 5

    def test_report_empty_string(self):
        report = redaction_report("")
        assert set(report.keys()) == set(CATEGORIES)
        assert sum(report.values()) == 0


# ─── Robustness / non-string inputs ──────────────────────────────────────────


class TestRobustness:

    @pytest.mark.parametrize("value", ["", None, 123, 4.5, True])
    def test_redact_text_non_string_returns_unchanged(self, value):
        assert redact_text(value) == value

    def test_clean_text_unchanged(self):
        text = "A perfectly ordinary sentence with no secrets."
        assert redact_text(text) == text

    def test_idempotent_redaction(self):
        text = f"{GITHUB_TOKEN} and bob@corp.io and 198.51.100.23"
        once = redact_text(text)
        twice = redact_text(once)
        assert once == twice

    def test_multiple_categories_in_one_string(self):
        text = (
            f"key={AWS_KEY} mail bob@corp.io ip 198.51.100.23 gh {GITHUB_TOKEN}"
        )
        out = redact_text(text)
        for cat in ("aws_key", "email", "ip", "github_token"):
            assert PLACEHOLDERS[cat] in out

    def test_placeholders_cover_all_categories(self):
        # Guard against a category being added without a placeholder.
        for cat in CATEGORIES:
            assert cat in PLACEHOLDERS


class TestSessionCookieValues:
    """Inline cookie / session-token name=value pairs (not just Cookie: headers)
    must be scrubbed, while ordinary query params are left intact."""

    @pytest.mark.parametrize("text,secret", [
        ("cookie=deadbeefdeadbeef", "deadbeefdeadbeef"),
        ("PHPSESSID=ab12cd34ef5678", "ab12cd34ef5678"),
        ("JSESSIONID: 9F8E7D6C5B4A3210", "9F8E7D6C5B4A3210"),
        ("sessionid=0123456789abcdef", "0123456789abcdef"),
        ("connect.sid=abcd1234efgh5678", "abcd1234efgh5678"),
    ])
    def test_session_values_redacted(self, text, secret):
        out = redact_text(text)
        assert "[REDACTED:" in out      # redaction fired
        assert secret not in out        # the secret value itself is gone

    def test_normal_query_param_preserved(self):
        # A benign search param must NOT be redacted (no over-redaction).
        assert redact_text("q=normalsearch&page=2") == "q=normalsearch&page=2"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
