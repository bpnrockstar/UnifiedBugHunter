---
description: Inspect and probe UBH's optional multi-provider LLM router — list configured providers, preview the fallback chain, and route a one-off completion. Routes first-party tool completions, NOT the Claude Code session itself.
argument-hint: "[--list-providers | --probe | --prompt <text>] [--prefer a,b] [--model X] [--max-tokens N] [--timeout S] [--json]"
allowed-tools: Bash
---

# /llm-config — LLM Router Configuration

Inspect and exercise the optional multi-provider LLM router that UBH's
first-party Python tools (and a future standalone CLI) use when they need a
chat completion. A provider becomes "available" purely from environment
variables — there is no config file to edit.

## Honest scope note — read this first

This router governs completions issued by **UBH's own Python tools** and a
future standalone CLI mode. It does **NOT**, and cannot, reroute the reasoning
of the Claude Code session you are talking to right now — that is decided
entirely by the host (the Claude Code / Agent SDK runtime). Setting
`GROQ_API_KEY` will not make Claude Code "think with Groq"; it only changes
which backend the helper tools in this repo call when they need an LLM
completion. Configuring a provider here is about the repo's tooling, not about
this conversation.

## Run This

Invoke `tools/llm_router.py` directly — do not re-implement the provider
abstraction, the fallback chain, or the API calls. The script does no network
I/O at import time or during `--list-providers`/`--probe`; HTTP only fires when
`--prompt` actually routes a completion.

```bash
python3 tools/llm_router.py $ARGUMENTS
```

If `$ARGUMENTS` is empty, default to a read-only inventory:

```bash
python3 tools/llm_router.py --list-providers
```

## Modes

Exactly one mode flag is expected (argparse errors with exit 2 if none is
given):

```
/llm-config --list-providers              — print available providers (creds present), DEFAULT_ORDER order
/llm-config --probe                       — print the resolved fallback chain
/llm-config --probe --prefer ollama,groq  — preview the chain with a preferred head
/llm-config --prompt "<text>"             — route a real completion through the chain
```

- `--list-providers` — prints providers whose credential (or, for ollama, host)
  is set. Prints "No providers configured" and exits `0` when nothing is set.
- `--probe` — prints the ordered fallback chain (`a -> b -> ...`), honoring
  `--prefer`. Prints "(empty — no provider configured)" when nothing is set.
- `--prompt <text>` — walks the chain and prints `[provider:model]` then the
  completion text on success (exit `0`), or an error to stderr (exit `1`) when
  no provider is configured or every available provider fails. Never raises.
- `--json` — available on all three modes for machine-readable output.

Common options for `--prompt` (and `--prefer` also applies to `--probe`):

- `--prefer a,b` — comma-separated preferred providers, tried first, then the
  rest of `DEFAULT_ORDER`; filtered to available + deduped, unknown names ignored.
- `--model X` — override the provider's default model.
- `--max-tokens N` — completion token budget (default `512`).
- `--timeout S` — per-request timeout in seconds (default `30`).

## Env-var / config contract

Providers are resolved at call time, so exported env overrides take effect
immediately. `DEFAULT_ORDER = anthropic, groq, deepseek, openai, ollama`.

| Provider | Env key | Available when | Default model | Endpoint |
|---|---|---|---|---|
| anthropic | `ANTHROPIC_API_KEY` | key set | `claude-3-5-haiku-latest` | `https://api.anthropic.com/v1/messages` |
| groq | `GROQ_API_KEY` | key set | `llama-3.3-70b-versatile` | `https://api.groq.com/openai/v1/chat/completions` |
| deepseek | `DEEPSEEK_API_KEY` | key set | `deepseek-chat` | `https://api.deepseek.com/chat/completions` |
| openai | `OPENAI_API_KEY` | key set | `gpt-4o-mini` | `https://api.openai.com/v1/chat/completions` |
| ollama | `OLLAMA_HOST` (no key) | `OLLAMA_HOST` explicitly set | `llama3.1` | `$OLLAMA_HOST/api/chat` (default `http://localhost:11434`) |

Notes on the ollama row: a provider is "available" only from config, never from
a live network check. Ollama gates on `OLLAMA_HOST` being **explicitly set** so
that the "no provider configured" state stays reachable — `ollama_host()` still
returns the `http://localhost:11434` default for the actual request URL even
when the variable is unset. If `requests` is not installed, `--prompt` fails
gracefully with an install hint instead of crashing.

## Examples

```bash
# What's configured right now?
python3 tools/llm_router.py --list-providers

# Same, machine-readable
python3 tools/llm_router.py --list-providers --json

# Preview the fallback order without sending anything
python3 tools/llm_router.py --probe

# Preview with a preferred head (local Ollama first, then Groq)
python3 tools/llm_router.py --probe --prefer ollama,groq

# Route a one-off completion through the chain
python3 tools/llm_router.py --prompt "Explain SSRF in one sentence"

# Force a provider/model and a tighter budget
python3 tools/llm_router.py --prompt "Summarize CWE-89" \
  --prefer groq --model llama-3.3-70b-versatile --max-tokens 256 --timeout 20

# JSON result for piping into other tools
python3 tools/llm_router.py --prompt "Classify this finding" --json
```

## Importable API (for UBH tools)

```python
from tools.llm_router import available_providers, resolve_chain, complete

available_providers()                     # -> list[str], DEFAULT_ORDER order
resolve_chain(prefer=["groq"])            # -> ordered, deduped, available-only
result = complete("...", prefer=["groq"]) # -> {"provider","model","text","ok","error"}
if result["ok"]:
    print(result["provider"], result["model"], result["text"])
```

`complete()` returns `{"provider": None, "model": None, "text": "", "ok": False,
"error": "no provider configured"}` when nothing is available, and the last
failed result dict when every available provider fails — it never raises.
