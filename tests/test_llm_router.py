"""Tests for tools/llm_router.py — the multi-provider LLM router.

stdlib + pytest only. NO real network call is ever made: availability/chain
resolution are pure config reads, and the one success-path test stubs the
`requests` transport on the module so `complete()` exercises its happy path
without touching the network.
"""

import pytest

from llm_router import (
    DEFAULT_ORDER,
    PROVIDERS,
    Provider,
    available_providers,
    complete,
    is_available,
    ollama_host,
    provider_credential,
    resolve_chain,
    resolve_model,
)
import llm_router


# ─── Fixtures ──────────────────────────────────────────────────────────────────

# Every env var the router consults. Tests start from a clean slate so a key
# leaking in from the developer's real shell can't make availability flaky.
ALL_ENV_KEYS = [
    "ANTHROPIC_API_KEY",
    "GROQ_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
    "OLLAMA_HOST",
]


@pytest.fixture
def clean_env(monkeypatch):
    """Remove every provider env var so each test sets only what it needs."""
    for key in ALL_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


class _FakeResponse:
    """Minimal stand-in for a requests.Response (json + status_code + text)."""

    def __init__(self, payload, status_code=200, text=""):
        self._payload = payload
        self.status_code = status_code
        self.text = text

    def json(self):
        return self._payload


class _RecordingRequests:
    """Stub `requests` module: records calls and returns a canned response.

    Installed onto llm_router.requests so Provider.complete() runs end-to-end
    without any socket. `calls` lets a test assert post was (or was not) hit.
    """

    def __init__(self, response):
        self._response = response
        self.calls = []

    def post(self, url, headers=None, json=None, timeout=None):
        self.calls.append(
            {"url": url, "headers": headers, "json": json, "timeout": timeout}
        )
        return self._response


# ─── available_providers() reflects env ──────────────────────────────────────────

class TestAvailableProviders:

    def test_none_set_is_empty(self, clean_env):
        assert available_providers() == []

    def test_single_key_reflected(self, clean_env):
        clean_env.setenv("GROQ_API_KEY", "gsk_test")
        assert available_providers() == ["groq"]

    def test_returned_in_default_order_not_env_order(self, clean_env):
        # Set them in a deliberately "wrong" order; output must follow DEFAULT_ORDER.
        clean_env.setenv("OPENAI_API_KEY", "sk-openai")
        clean_env.setenv("ANTHROPIC_API_KEY", "sk-ant")
        clean_env.setenv("GROQ_API_KEY", "gsk")
        assert available_providers() == ["anthropic", "groq", "openai"]

    def test_empty_string_key_is_not_available(self, clean_env):
        clean_env.setenv("GROQ_API_KEY", "")
        assert available_providers() == []

    def test_ollama_available_only_when_host_explicitly_set(self, clean_env):
        # No OLLAMA_HOST -> not available (the documented clean-machine state).
        assert is_available("ollama") is False
        clean_env.setenv("OLLAMA_HOST", "http://localhost:11434")
        assert is_available("ollama") is True
        assert available_providers() == ["ollama"]

    def test_unknown_provider_never_available(self, clean_env):
        assert is_available("definitely-not-a-provider") is False

    def test_provider_credential_reads_env_at_call_time(self, clean_env):
        assert provider_credential("anthropic") is None
        clean_env.setenv("ANTHROPIC_API_KEY", "sk-ant-123")
        assert provider_credential("anthropic") == "sk-ant-123"
        # ollama is keyless.
        assert provider_credential("ollama") is None


# ─── resolve_chain() ordering, filtering, prefer ─────────────────────────────────

class TestResolveChain:

    def test_empty_when_nothing_configured(self, clean_env):
        assert resolve_chain() == []
        assert resolve_chain(prefer=["groq", "anthropic"]) == []

    def test_filters_to_available_in_default_order(self, clean_env):
        clean_env.setenv("ANTHROPIC_API_KEY", "a")
        clean_env.setenv("OPENAI_API_KEY", "o")
        # deepseek/groq/ollama not configured -> excluded.
        assert resolve_chain() == ["anthropic", "openai"]

    def test_prefer_moves_available_provider_to_front(self, clean_env):
        clean_env.setenv("ANTHROPIC_API_KEY", "a")
        clean_env.setenv("OPENAI_API_KEY", "o")
        # Prefer openai: it jumps ahead of anthropic, rest fall in DEFAULT_ORDER.
        assert resolve_chain(prefer=["openai"]) == ["openai", "anthropic"]

    def test_prefer_preserves_caller_order_among_preferred(self, clean_env):
        for key in ("ANTHROPIC_API_KEY", "GROQ_API_KEY", "OPENAI_API_KEY"):
            clean_env.setenv(key, "x")
        chain = resolve_chain(prefer=["openai", "groq"])
        assert chain == ["openai", "groq", "anthropic"]

    def test_prefer_unknown_names_ignored(self, clean_env):
        clean_env.setenv("GROQ_API_KEY", "g")
        # "bogus" is not a known provider; it's silently dropped.
        assert resolve_chain(prefer=["bogus", "groq"]) == ["groq"]

    def test_prefer_unavailable_provider_is_filtered_out(self, clean_env):
        clean_env.setenv("GROQ_API_KEY", "g")
        # anthropic preferred but has no key -> filtered; only groq remains.
        assert resolve_chain(prefer=["anthropic", "groq"]) == ["groq"]

    def test_chain_is_deduped(self, clean_env):
        clean_env.setenv("GROQ_API_KEY", "g")
        # Duplicate prefer entries + groq also in DEFAULT_ORDER must appear once.
        assert resolve_chain(prefer=["groq", "groq"]) == ["groq"]

    def test_full_order_matches_default_when_all_available(self, clean_env):
        clean_env.setenv("ANTHROPIC_API_KEY", "a")
        clean_env.setenv("GROQ_API_KEY", "g")
        clean_env.setenv("DEEPSEEK_API_KEY", "d")
        clean_env.setenv("OPENAI_API_KEY", "o")
        clean_env.setenv("OLLAMA_HOST", "http://localhost:11434")
        assert resolve_chain() == DEFAULT_ORDER


# ─── resolve_model() ─────────────────────────────────────────────────────────────

class TestResolveModel:

    def test_explicit_model_wins(self):
        assert resolve_model("groq", "custom-model") == "custom-model"

    def test_falls_back_to_provider_default(self):
        assert resolve_model("groq", None) == PROVIDERS["groq"]["default_model"]

    def test_unknown_provider_no_model_returns_empty(self):
        assert resolve_model("nope", None) == ""


# ─── complete(): no provider configured (NO network) ─────────────────────────────

class TestCompleteNoProvider:

    def test_returns_no_provider_configured(self, clean_env):
        result = complete("hello")
        assert result == {
            "provider": None,
            "model": None,
            "text": "",
            "ok": False,
            "error": "no provider configured",
        }

    def test_no_provider_makes_no_network_call(self, clean_env, monkeypatch):
        # Install a recording stub; assert it is NEVER posted to when no
        # provider is configured. Proves the empty-chain path is short-circuited
        # before any transport use.
        stub = _RecordingRequests(_FakeResponse({}))
        monkeypatch.setattr(llm_router, "requests", stub)
        result = complete("hello", prefer=["groq", "anthropic"])
        assert result["ok"] is False
        assert result["error"] == "no provider configured"
        assert stub.calls == []


# ─── complete(): single-provider success path (stubbed transport) ────────────────

class TestCompleteSuccessPath:

    def test_openai_style_success(self, clean_env, monkeypatch):
        clean_env.setenv("GROQ_API_KEY", "gsk_test_key")
        payload = {"choices": [{"message": {"content": "  hi there  "}}]}
        stub = _RecordingRequests(_FakeResponse(payload, status_code=200))
        monkeypatch.setattr(llm_router, "requests", stub)

        result = complete("ping", prefer=["groq"])

        assert result["ok"] is True
        assert result["provider"] == "groq"
        assert result["model"] == PROVIDERS["groq"]["default_model"]
        assert result["text"] == "hi there"  # extracted + stripped
        assert result["error"] is None

        # Exactly one network call, to the groq endpoint, with Bearer auth.
        assert len(stub.calls) == 1
        call = stub.calls[0]
        assert call["url"] == PROVIDERS["groq"]["endpoint"]
        assert call["headers"]["authorization"] == "Bearer gsk_test_key"
        assert call["json"]["model"] == PROVIDERS["groq"]["default_model"]
        assert call["json"]["messages"] == [{"role": "user", "content": "ping"}]

    def test_anthropic_style_success_and_headers(self, clean_env, monkeypatch):
        clean_env.setenv("ANTHROPIC_API_KEY", "sk-ant-xyz")
        payload = {"content": [{"type": "text", "text": "answer "}]}
        stub = _RecordingRequests(_FakeResponse(payload))
        monkeypatch.setattr(llm_router, "requests", stub)

        result = complete("q", prefer=["anthropic"], model="claude-custom", max_tokens=7)

        assert result["ok"] is True
        assert result["provider"] == "anthropic"
        assert result["model"] == "claude-custom"
        assert result["text"] == "answer"
        call = stub.calls[0]
        assert call["url"] == PROVIDERS["anthropic"]["endpoint"]
        assert call["headers"]["x-api-key"] == "sk-ant-xyz"
        assert call["headers"]["anthropic-version"] == llm_router.ANTHROPIC_VERSION
        assert call["json"]["max_tokens"] == 7

    def test_first_provider_failure_falls_through_to_next(self, clean_env, monkeypatch):
        # Two providers available; first returns HTTP 500, second succeeds.
        clean_env.setenv("ANTHROPIC_API_KEY", "a")
        clean_env.setenv("GROQ_API_KEY", "g")

        good = _FakeResponse({"choices": [{"message": {"content": "ok"}}]}, 200)
        bad = _FakeResponse(None, status_code=500, text="boom")

        class _Sequenced:
            def __init__(self):
                self.calls = []

            def post(self, url, headers=None, json=None, timeout=None):
                self.calls.append(url)
                # anthropic is first in DEFAULT_ORDER -> fails; groq -> succeeds.
                if url == PROVIDERS["anthropic"]["endpoint"]:
                    return bad
                return good

        stub = _Sequenced()
        monkeypatch.setattr(llm_router, "requests", stub)

        result = complete("hi")
        assert result["ok"] is True
        assert result["provider"] == "groq"
        assert result["text"] == "ok"
        assert stub.calls == [
            PROVIDERS["anthropic"]["endpoint"],
            PROVIDERS["groq"]["endpoint"],
        ]

    def test_all_available_fail_returns_last_failed_result(self, clean_env, monkeypatch):
        clean_env.setenv("GROQ_API_KEY", "g")
        bad = _FakeResponse(None, status_code=429, text="rate limited")
        stub = _RecordingRequests(bad)
        monkeypatch.setattr(llm_router, "requests", stub)

        result = complete("hi", prefer=["groq"])
        assert result["ok"] is False
        assert result["provider"] == "groq"
        assert "429" in result["error"]

    def test_requests_missing_degrades_gracefully(self, clean_env, monkeypatch):
        clean_env.setenv("GROQ_API_KEY", "g")
        monkeypatch.setattr(llm_router, "requests", None)
        result = complete("hi", prefer=["groq"])
        assert result["ok"] is False
        assert result["provider"] == "groq"
        assert "requests" in result["error"]


# ─── ollama_host() request URL (always returns; independent of availability) ─────

class TestOllamaHost:

    def test_default_when_unset(self, clean_env):
        assert ollama_host() == llm_router.DEFAULT_OLLAMA_HOST

    def test_env_override_and_trailing_slash_stripped(self, clean_env):
        clean_env.setenv("OLLAMA_HOST", "http://gpu-box:11434/")
        assert ollama_host() == "http://gpu-box:11434"

    def test_provider_endpoint_uses_host_at_call_time(self, clean_env):
        clean_env.setenv("OLLAMA_HOST", "http://gpu-box:11434")
        assert Provider("ollama").endpoint() == "http://gpu-box:11434/api/chat"


# ─── Provider construction guard ─────────────────────────────────────────────────

class TestProviderConstruction:

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError):
            Provider("nope")

    def test_known_provider_constructs_without_network(self, clean_env):
        # No env set, no stub installed: construction must not touch the network.
        p = Provider("openai")
        assert p.name == "openai"
        assert p.style == "openai"
        assert p.endpoint() == PROVIDERS["openai"]["endpoint"]


# ─── CLI: --list-providers / --probe never hit the network ───────────────────────

class TestCLI:

    def test_list_providers_empty(self, clean_env, capsys):
        rc = llm_router.main(["--list-providers"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "No providers configured" in out

    def test_list_providers_json(self, clean_env, capsys):
        clean_env.setenv("GROQ_API_KEY", "g")
        rc = llm_router.main(["--list-providers", "--json"])
        out = capsys.readouterr().out
        assert rc == 0
        import json as _json
        assert _json.loads(out) == {"available": ["groq"]}

    def test_probe_honors_prefer(self, clean_env, capsys):
        clean_env.setenv("ANTHROPIC_API_KEY", "a")
        clean_env.setenv("GROQ_API_KEY", "g")
        rc = llm_router.main(["--probe", "--prefer", "groq,anthropic", "--json"])
        out = capsys.readouterr().out
        assert rc == 0
        import json as _json
        assert _json.loads(out) == {"chain": ["groq", "anthropic"]}

    def test_probe_empty_chain(self, clean_env, capsys):
        rc = llm_router.main(["--probe"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "empty" in out

    def test_prompt_no_provider_exits_1_no_network(self, clean_env, monkeypatch, capsys):
        stub = _RecordingRequests(_FakeResponse({}))
        monkeypatch.setattr(llm_router, "requests", stub)
        rc = llm_router.main(["--prompt", "hello"])
        err = capsys.readouterr().err
        assert rc == 1
        assert "no provider configured" in err
        assert stub.calls == []

    def test_prompt_success_prints_provider_and_text(self, clean_env, monkeypatch, capsys):
        clean_env.setenv("GROQ_API_KEY", "g")
        payload = {"choices": [{"message": {"content": "pong"}}]}
        stub = _RecordingRequests(_FakeResponse(payload))
        monkeypatch.setattr(llm_router, "requests", stub)
        rc = llm_router.main(["--prompt", "ping", "--prefer", "groq"])
        out = capsys.readouterr().out
        assert rc == 0
        assert out.startswith(f"[groq:{PROVIDERS['groq']['default_model']}]")
        assert "pong" in out

    def test_no_mode_and_no_prompt_is_argparse_error(self, clean_env):
        with pytest.raises(SystemExit) as exc:
            llm_router.main([])
        assert exc.value.code == 2
