#!/usr/bin/env python3
"""
llm_router.py — Optional multi-provider LLM router for UBH's first-party tools.

Provides a small Provider abstraction + a router so that UBH's own Python tools
(and a future standalone CLI mode) can send chat-completion prompts to whichever
LLM backend is configured, with an ordered fallback chain across providers.

Supported providers (all config-driven via environment variables):

    anthropic  ANTHROPIC_API_KEY              https://api.anthropic.com/v1/messages
    groq       GROQ_API_KEY                   https://api.groq.com/openai/v1/chat/completions
    deepseek   DEEPSEEK_API_KEY               https://api.deepseek.com/chat/completions
    openai     OPENAI_API_KEY                 https://api.openai.com/v1/chat/completions
    ollama     (no key — local daemon)        $OLLAMA_HOST  (default http://localhost:11434)

A provider is "available" when its credential (or, for ollama, its host) is
present in the environment. complete() walks the resolved chain and returns the
first successful response; it NEVER raises and NEVER makes a network call at
import time.

IMPORTANT — honest scope note:
    This router governs completions issued by UBH's *first-party* Python tools
    and a future standalone CLI. It does NOT, and cannot, reroute the reasoning
    of the Claude Code session you are talking to — that is decided entirely by
    the host (the Claude Code / Agent SDK runtime). Setting GROQ_API_KEY here
    will not make Claude Code "think with Groq"; it only changes which backend
    the helper tools in this repo call when they need an LLM completion.

Usage (CLI):
    python3 tools/llm_router.py --list-providers
    python3 tools/llm_router.py --probe
    python3 tools/llm_router.py --probe --prefer ollama,groq
    python3 tools/llm_router.py --prompt "Summarize CWE-89" --prefer groq --model llama-3.3-70b-versatile

Usage (importable):
    from tools.llm_router import available_providers, resolve_chain, complete
    result = complete("Explain SSRF in one sentence", prefer=["groq", "anthropic"])
    if result["ok"]:
        print(result["provider"], result["model"], result["text"])
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# requests is imported defensively: the module must import cleanly even when the
# dependency is absent (tests import these functions; CI may not install it).
# Real HTTP only happens inside provider .complete() at call time, never here.
try:
    import requests  # noqa: F401
except ImportError:  # pragma: no cover - exercised only when requests missing
    requests = None


# ─── Configuration contract ───────────────────────────────────────────────────
# Default order is intentional: hosted high-quality first (anthropic), then fast
# /cheap hosted (groq, deepseek, openai), then local (ollama) as the last resort.
DEFAULT_ORDER = ["anthropic", "groq", "deepseek", "openai", "ollama"]

# Per-provider config. `key_env` is the env var holding the credential (None for
# ollama, which authenticates by reachability, not by key). `default_model` is
# used when the caller passes model=None. `endpoint` is resolved lazily so env
# overrides (e.g. OLLAMA_HOST) are honored at call time, not import time.
PROVIDERS: dict[str, dict] = {
    "anthropic": {
        "key_env": "ANTHROPIC_API_KEY",
        "default_model": "claude-3-5-haiku-latest",
        "endpoint": "https://api.anthropic.com/v1/messages",
        "style": "anthropic",
    },
    "groq": {
        "key_env": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "style": "openai",
    },
    "deepseek": {
        "key_env": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
        "endpoint": "https://api.deepseek.com/chat/completions",
        "style": "openai",
    },
    "openai": {
        "key_env": "OPENAI_API_KEY",
        "default_model": "gpt-4o-mini",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "style": "openai",
    },
    "ollama": {
        "key_env": None,  # local; no credential
        "default_model": "llama3.1",
        "endpoint": None,  # derived from OLLAMA_HOST at call time
        "style": "ollama",
    },
}

# Anthropic Messages API version pin. Sent as the `anthropic-version` header.
ANTHROPIC_VERSION = "2023-06-01"

# Default local Ollama host when OLLAMA_HOST is unset.
DEFAULT_OLLAMA_HOST = "http://localhost:11434"


# ─── Helpers ───────────────────────────────────────────────────────────────────

def ollama_host() -> str:
    """Return the Ollama base URL to call (OLLAMA_HOST, else the localhost default).

    This is the URL used for the actual request and always returns a value. It is
    distinct from availability: see is_available(), which gates ollama on the
    OLLAMA_HOST env var being explicitly set so that "no provider configured" is
    a reachable state on a clean machine.
    """
    return (os.environ.get("OLLAMA_HOST") or DEFAULT_OLLAMA_HOST).rstrip("/")


def provider_credential(name: str) -> str | None:
    """Return the API key for a provider, or None if it has no key / isn't set."""
    cfg = PROVIDERS.get(name)
    if not cfg:
        return None
    key_env = cfg.get("key_env")
    if not key_env:
        return None
    val = os.environ.get(key_env)
    return val or None


def is_available(name: str) -> bool:
    """A provider is available when its credential (or, for ollama, host) is set.

    No network call is made here — availability is purely a config check so it is
    safe to call in tests and at import-adjacent points. Ollama is keyless and
    local: it counts as available only when OLLAMA_HOST is explicitly present in
    the environment (opting the local daemon in), so that a machine with neither
    keys nor OLLAMA_HOST yields the documented "no provider configured" state.
    """
    cfg = PROVIDERS.get(name)
    if not cfg:
        return False
    if cfg.get("key_env") is None:
        return bool(os.environ.get("OLLAMA_HOST"))
    return provider_credential(name) is not None


def available_providers() -> list[str]:
    """Return provider names with creds/host present, in DEFAULT_ORDER order."""
    return [name for name in DEFAULT_ORDER if is_available(name)]


def resolve_chain(prefer: list[str] | None = None) -> list[str]:
    """Resolve the ordered fallback chain, filtered to available providers.

    Args:
        prefer: Optional caller-supplied priority order. Names here are tried
                first (in the given order), then the remaining DEFAULT_ORDER
                providers fill in behind them. Unknown names are ignored.

    Returns:
        Ordered list of available provider names, deduplicated.
    """
    order: list[str] = []
    if prefer:
        for name in prefer:
            if name in PROVIDERS and name not in order:
                order.append(name)
    for name in DEFAULT_ORDER:
        if name not in order:
            order.append(name)
    return [name for name in order if is_available(name)]


def resolve_model(name: str, model: str | None) -> str:
    """Resolve the model id for a provider (explicit model or its default)."""
    if model:
        return model
    cfg = PROVIDERS.get(name) or {}
    return cfg.get("default_model", "")


# ─── Provider abstraction ──────────────────────────────────────────────────────

class Provider:
    """A single LLM backend. `complete()` performs the only real network call.

    Construction is cheap and side-effect free (no network). Each provider knows
    its request shape via the `style` field of its config: 'anthropic',
    'openai' (the OpenAI-compatible chat schema shared by groq/deepseek/openai),
    or 'ollama' (the local /api/chat endpoint).
    """

    def __init__(self, name: str):
        if name not in PROVIDERS:
            raise ValueError(f"unknown provider: {name}")
        self.name = name
        self.config = PROVIDERS[name]
        self.style = self.config["style"]

    def endpoint(self) -> str:
        """Resolve the request URL at call time (honors OLLAMA_HOST overrides)."""
        if self.name == "ollama":
            return f"{ollama_host()}/api/chat"
        return self.config["endpoint"]

    def credential(self) -> str | None:
        return provider_credential(self.name)

    def complete(
        self,
        prompt: str,
        *,
        model: str | None = None,
        max_tokens: int = 512,
        timeout: int = 30,
    ) -> dict:
        """Call this provider once. Returns the standard result dict; never raises.

        Result dict shape:
            {"provider": str, "model": str, "text": str, "ok": bool, "error": str|None}
        """
        resolved_model = resolve_model(self.name, model)
        result = {
            "provider": self.name,
            "model": resolved_model,
            "text": "",
            "ok": False,
            "error": None,
        }

        if requests is None:
            result["error"] = "requests not installed (pip install requests)"
            return result

        try:
            url, headers, payload = self._build_request(prompt, resolved_model, max_tokens)
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
            if resp.status_code >= 400:
                snippet = (resp.text or "")[:200]
                result["error"] = f"HTTP {resp.status_code}: {snippet}"
                return result
            data = resp.json()
            result["text"] = self._extract_text(data)
            result["ok"] = True
        except Exception as exc:  # network/JSON/shape errors all degrade gracefully
            result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    # -- request construction (pure; no network) --

    def _build_request(self, prompt: str, model: str, max_tokens: int):
        """Return (url, headers, payload) for this provider's API style."""
        url = self.endpoint()
        if self.style == "anthropic":
            headers = {
                "x-api-key": self.credential() or "",
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json",
            }
            payload = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
        elif self.style == "ollama":
            headers = {"content-type": "application/json"}
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"num_predict": max_tokens},
            }
        else:  # openai-compatible (groq, deepseek, openai)
            headers = {
                "authorization": f"Bearer {self.credential() or ''}",
                "content-type": "application/json",
            }
            payload = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
        return url, headers, payload

    # -- response extraction (pure; tolerant of missing fields) --

    def _extract_text(self, data: dict) -> str:
        """Pull the completion text out of a provider response, defensively."""
        if self.style == "anthropic":
            blocks = data.get("content") or []
            parts = [b.get("text", "") for b in blocks if isinstance(b, dict)]
            return "".join(parts).strip()
        if self.style == "ollama":
            return ((data.get("message") or {}).get("content") or "").strip()
        # openai-compatible
        choices = data.get("choices") or []
        if choices:
            msg = choices[0].get("message") or {}
            return (msg.get("content") or "").strip()
        return ""


# ─── Router entrypoint ──────────────────────────────────────────────────────────

def complete(
    prompt: str,
    *,
    prefer: list[str] | None = None,
    model: str | None = None,
    max_tokens: int = 512,
    timeout: int = 30,
) -> dict:
    """Route a completion across the fallback chain; return the first success.

    Tries each provider in resolve_chain(prefer) until one returns ok=True. If
    NO provider is configured, returns {ok: False, error: 'no provider configured'}.
    If providers exist but all fail, returns the LAST provider's failed result
    (so the caller sees a concrete error). Never raises.

    Returns:
        {"provider": str|None, "model": str|None, "text": str,
         "ok": bool, "error": str|None}
    """
    chain = resolve_chain(prefer)
    if not chain:
        return {
            "provider": None,
            "model": None,
            "text": "",
            "ok": False,
            "error": "no provider configured",
        }

    last = None
    for name in chain:
        try:
            provider = Provider(name)
            result = provider.complete(
                prompt, model=model, max_tokens=max_tokens, timeout=timeout
            )
        except Exception as exc:  # construction guard — should not happen
            result = {
                "provider": name,
                "model": resolve_model(name, model),
                "text": "",
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        if result.get("ok"):
            return result
        last = result
    return last


# ─── CLI ─────────────────────────────────────────────────────────────────────────

def _parse_prefer(value: str | None) -> list[str] | None:
    """Parse a comma-separated --prefer value into an ordered provider list."""
    if not value:
        return None
    names = [part.strip() for part in value.split(",") if part.strip()]
    return names or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Multi-provider LLM router for UBH first-party tools. Routes tool "
            "completions only — it does NOT reroute the Claude Code session's "
            "own reasoning (that is the host's job)."
        )
    )
    parser.add_argument(
        "--list-providers",
        action="store_true",
        help="Print providers that are currently available (creds/host present).",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Print the resolved fallback chain (respects --prefer).",
    )
    parser.add_argument(
        "--prompt",
        default="",
        help="Prompt to send through the fallback chain.",
    )
    parser.add_argument(
        "--prefer",
        default="",
        help="Comma-separated priority order, e.g. ollama,groq",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Override the model id for the chosen provider.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=512,
        help="Max tokens for the completion (default 512).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-request timeout in seconds (default 30).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    args = parser.parse_args(argv)

    prefer = _parse_prefer(args.prefer)

    if args.list_providers:
        providers = available_providers()
        if args.json:
            print(json.dumps({"available": providers}, indent=2, sort_keys=True))
        elif providers:
            print("Available providers: " + ", ".join(providers))
        else:
            print("No providers configured (set an API key or run Ollama locally).")
        return 0

    if args.probe:
        chain = resolve_chain(prefer)
        if args.json:
            print(json.dumps({"chain": chain}, indent=2, sort_keys=True))
        elif chain:
            print("Resolved chain: " + " -> ".join(chain))
        else:
            print("Resolved chain: (empty — no provider configured)")
        return 0

    if not args.prompt:
        parser.error("provide --prompt, or use --list-providers / --probe")

    result = complete(
        args.prompt,
        prefer=prefer,
        model=args.model or None,
        max_tokens=args.max_tokens,
        timeout=args.timeout,
    )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if result["ok"]:
            print(f"[{result['provider']}:{result['model']}]\n{result['text']}")
        else:
            print(f"ERROR ({result.get('provider') or 'router'}): {result['error']}",
                  file=sys.stderr)

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
