---
description: "Auto-confirm a [POSSIBLE] DOM-XSS by executing one (url, payload) in a headless Chromium (Playwright) and reporting whether it actually fired. Detection: a JS dialog opening, window[marker] being set, or a console marker — any one ⇒ CONFIRMED. Turns hunt-dom / hunt-xss [POSSIBLE] candidates into CONFIRMED (or kills them). Degrades to UNVERIFIED with an install hint (exit 0) when Playwright/Chromium are absent. Usage: /dom-verify <url> <payload> [--marker m] [--json]"
argument-hint: "<url> <payload> [--marker m] [--timeout s] [--json]"
allowed-tools: Bash, Read
---

# /dom-verify — Confirm a DOM-XSS in a Real Browser

DOM-based XSS executes in the victim's browser — the server never sees the
payload, so a grep/source pass can only mark a sink **[POSSIBLE]**. The only proof
that counts is the payload *firing*. `/dom-verify` drives one `(url, payload)` in a
headless Chromium and returns a deterministic verdict, flipping a `hunt-dom` /
`hunt-xss` **[POSSIBLE]** into **CONFIRMED** (or killing it as a false positive).

## Run This

Invoke the backing tool directly — do not re-implement the browser run inline. The
CLI takes the candidate as `--url` and the payload as `--payload`:

```bash
python3 tools/dom_xss_verifier.py --url "$1" --payload "$2" "${@:3}"
```

Full flag surface (maps straight onto the real CLI):

```bash
python3 tools/dom_xss_verifier.py --url <u> --payload <p> [--marker m] [--timeout s] [--json]
```

- `--url` / `--payload` — **required**; the candidate page and the payload to inject.
- `--marker` — window/console marker that signals execution without a visible dialog
  (default `__xss_fired__`). Have the payload set `window[marker]=1` or
  `console.log(marker)`; an `alert`/`confirm`/`prompt` is detected automatically.
- `--timeout` — per-navigation timeout in seconds (default 15).
- `--json` — print the raw result JSON instead of the human-readable verdict.

A missing `--url`/`--payload` exits 2; a completed run (including UNVERIFIED and
NOT-TRIGGERED) exits 0.

## Verdicts

| Verdict | Meaning |
|---|---|
| `CONFIRMED` | The payload executed — a JS dialog opened, `window[marker]` was set, or a console message carried the marker. **This is the DOM-XSS proof.** |
| `NOT-TRIGGERED` | The browser ran and the page loaded, but no execution signal was seen — the candidate is a false positive *under this payload*. |
| `UNVERIFIED` | Could not test — Playwright/Chromium not installed. Carries the install hint. **Not** a judgment on the bug. |
| `ERROR` | The browser launched but the run failed (navigation error, timeout, crash). Not a confirmation either way. |

The result also carries `detail` and `signals` (`dialog` / `window-marker` /
`console-marker`). Use the verdict as the browser-execution proof the `hunt-xss`
Gate 0 and `hunt-dom` validation discipline require for DOM-based XSS.

## How it fits the hunt

`/dom-verify` is the **confirmer**, not the hunter — the same engine/triager split as
`/sast` ↔ `/code-audit`:

- **`hunt-dom` / `hunt-xss` (the model) — find the candidate.** They locate the
  source→sink (`location.hash`→`innerHTML`, `document.write`, `eval`,
  `dangerouslySetInnerHTML`, …) and mark it **[POSSIBLE]**.
- **`/dom-verify` (this command) — confirm one payload.** It does not crawl or invent
  payloads; you bring the `(url, payload)`, it returns the deterministic browser
  verdict so a finding can be promoted to CONFIRMED without hand-waving.

## Graceful degradation (no engine installed is a supported state)

If Playwright (or its Chromium) is not installed, `verify_dom_xss()` returns verdict
`UNVERIFIED` with the hint below and the CLI still exits 0 — mirroring `/sast`,
`secrets_hunter.sh`, and `/sca`. `UNVERIFIED` is deliberately distinct from
`NOT-TRIGGERED`: absence of a verifier is not a verdict on the bug, so install before
you claim or retract a DOM-XSS:

```bash
pip install playwright && playwright install chromium
```

All Playwright imports live inside the tool's functions (never at module import), so
the tool imports — and its test suite runs — with Playwright absent. Playwright stays
optional; the network is never required to test the tool.

## Usage

```
/dom-verify https://target.com/p '<img src=x onerror=window.__xss_fired__=1>'
/dom-verify https://target.com/p '"><svg onload=alert(1)>'           # dialog auto-detected
/dom-verify 'https://target.com/p#already=injected' '<svg onload=alert(1)>'   # URL used verbatim
/dom-verify https://target.com/p "console.log('myMARK7')" --marker myMARK7 --json
```

When the URL has no fragment and doesn't already contain the payload, the payload is
appended after `#` (the canonical `location.hash` DOM-XSS trigger). If the URL already
carries a fragment or contains the payload, it is navigated verbatim — so you can wire
the payload into `?q=`, the path, or a fragment yourself.
