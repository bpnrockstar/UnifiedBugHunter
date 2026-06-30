#!/usr/bin/env python3
"""
dom_xss_verifier.py — auto-confirm a "[POSSIBLE]" DOM-XSS in a real headless browser.

DOM-based XSS is the one bug class a curl/grep pipeline can never actually prove:
the payload never reaches the server, so the only evidence that counts is the script
*executing in a browser*. The `hunt-dom` / `hunt-xss` skills surface candidate sinks
(location.hash → innerHTML, document.write, eval, dangerouslySetInnerHTML, ...) and
tag them "[POSSIBLE]". This module is the closing step: it drives a headless Chromium
(via Playwright), navigates the candidate URL with the payload, and reports whether the
payload actually FIRED — turning a "[POSSIBLE]" into a "CONFIRMED" (or killing it).

WHY THIS IS THE TRIAGER, NOT THE HUNTER (mirrors tools/sast_runner.py):
  The skills/model produce CANDIDATES; this tool produces a deterministic VERDICT for a
  single (url, payload) pair by observing real execution. It does not invent payloads or
  crawl — it confirms one. Keeping confirmation in a real browser is what lets the model
  promote a finding to CONFIRMED without hand-waving "it looked reflected".

GRACEFUL DEGRADATION (mirrors tools/sast_runner.py + tools/secrets_hunter.sh + sca_audit.py):
  Playwright (and a downloaded Chromium) absent is a NORMAL, supported state — not an
  error. When the engine is missing, verify_dom_xss() returns verdict "UNVERIFIED" with a
  clear install hint and NEVER crashes; the CLI still exits 0. EVERY playwright import is
  done INSIDE the function (never at module import), so importing this module — and the
  whole test suite — works with playwright not installed. Tests never launch a real
  browser or touch the network: they drive is_available() via monkeypatch and the verdict
  logic via a stubbed/mocked browser engine. Playwright stays OPTIONAL.

Importable surface (all logic lives in top-level functions; tests import them):
    is_available() -> bool
    verify_dom_xss(url, payload, *, marker='__xss_fired__', timeout=15) -> dict

verify_dom_xss() result schema:
    verdict   str   "CONFIRMED" | "NOT-TRIGGERED" | "UNVERIFIED" | "ERROR"
    detail    str   human-readable explanation of the verdict
    url       str   the URL that was driven (echoed back)
    payload   str   the payload that was injected (echoed back)
    marker    str   the window/console marker that was watched for
    signals   list  which detectors fired, e.g. ["dialog"], ["window-marker"],
                    ["console-marker"] (present on CONFIRMED; [] otherwise)
  Verdict meanings:
    CONFIRMED      — the payload executed: a JS dialog opened, OR window[marker] was set,
                     OR a console message carried the marker. This IS the DOM-XSS proof.
    NOT-TRIGGERED  — the browser ran fine and the page loaded, but NO execution signal was
                     observed. The candidate is (under this payload) a false positive.
    UNVERIFIED     — could not test: Playwright/Chromium not installed (carries the install
                     hint). Distinct from NOT-TRIGGERED — absence of a verifier is not a
                     verdict on the bug.
    ERROR          — the browser launched but the run itself failed (navigation error,
                     timeout, crash). Not a confirmation either way.

CLI:
    python3 tools/dom_xss_verifier.py --url <u> --payload <p> [--marker m] [--json]
  Prints a human-readable verdict (or the raw JSON with --json). ALWAYS exits 0 when the
  run completes — including UNVERIFIED (no engine) and NOT-TRIGGERED — mirroring the other
  UBH engines; non-zero only on usage errors (missing --url/--payload).

INJECTION STRATEGY:
  The payload is appended to the URL fragment (after '#') when the URL has no fragment of
  its own — this is the canonical DOM-XSS trigger (location.hash is the most common
  source). If the caller already encoded the payload into the URL (it contains the
  payload, or already has a fragment), the URL is navigated as-is. A small bootstrap
  script defines window[marker] hooks so payloads of the form
  `...;window.__xss_fired__=1` or `...;console.log('__xss_fired__')` are detected even
  when no visible dialog is raised.

Python 3, stdlib only at import time. Playwright is an OPTIONAL runtime dependency,
imported defensively inside the functions — never at module top level.
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import json
import sys

# Verdict constants — the only four states verify_dom_xss() can return.
CONFIRMED = "CONFIRMED"
NOT_TRIGGERED = "NOT-TRIGGERED"
UNVERIFIED = "UNVERIFIED"
ERROR = "ERROR"

# Default marker a payload can set (window[marker]=1) or log (console.log(marker)) to
# signal execution without raising a visible dialog. Overridable per call.
DEFAULT_MARKER = "__xss_fired__"

# Shown whenever the engine is missing so the user knows exactly how to enable real
# verification. Kept as a module constant so tests can assert on it.
INSTALL_HINT = "playwright not installed: pip install playwright && playwright install chromium"


def is_available() -> bool:
    """Report whether DOM-XSS verification can actually run on this host.

    True only when BOTH are satisfied:
      1. the ``playwright`` Python package is importable, and
      2. a Chromium browser has been downloaded for it (``playwright install chromium``).

    Pure capability probe — it never launches a browser or makes a network request. The
    import is done HERE (inside the function), never at module import, so importing this
    module always works even with playwright absent. Any failure (ImportError, or a
    Playwright that cannot locate a Chromium executable) is swallowed and reported as
    False — absence is a supported state, not an error.

    Returns:
        bool: True if playwright + chromium are present; False otherwise.
    """
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401  (defensive: inside fn)
    except Exception:  # noqa: BLE001 - ImportError or any partial-install breakage
        return False

    # The package imports, but Chromium may not have been downloaded. Resolve the browser
    # executable path WITHOUT launching it; a missing/empty path means it's not installed.
    try:
        with sync_playwright() as pw:
            exe = getattr(pw.chromium, "executable_path", None)
        if not exe:
            return False
        try:
            import os
            return os.path.exists(exe)
        except Exception:  # noqa: BLE001
            # We have a path string but couldn't stat it; treat the engine as present
            # (launch will surface any real problem as an ERROR verdict, not a crash).
            return True
    except Exception:  # noqa: BLE001 - driver missing, browsers not installed, etc.
        return False


def _bootstrap_script(marker: str) -> str:
    """JS init-script injected before navigation so window/console markers are catchable.

    Defines an idempotent ``window[marker]`` slot and wraps ``alert``/``confirm``/``prompt``
    so a payload that calls them also flips the marker — this is a backup signal for the
    primary dialog handler (some headless configs auto-dismiss dialogs before the Python
    handler sees them). The script is intentionally tiny and side-effect-free beyond the
    marker so it cannot itself create a false positive.
    """
    safe_marker = json.dumps(marker)  # safely embed the marker as a JS string literal
    return (
        "(function(){"
        "try{"
        f"var __m={safe_marker};"
        "if(window[__m]===undefined){window[__m]=0;}"
        "var __orig={alert:window.alert,confirm:window.confirm,prompt:window.prompt};"
        "function __wrap(fn){return function(){try{window[__m]=1;}catch(e){}"
        "try{return fn&&fn.apply(this,arguments);}catch(e){}};}"
        "window.alert=__wrap(__orig.alert);"
        "window.confirm=__wrap(__orig.confirm);"
        "window.prompt=__wrap(__orig.prompt);"
        "}catch(e){}"
        "})();"
    )


def _build_target_url(url: str, payload: str) -> str:
    """Decide the actual URL to navigate, appending the payload to the fragment if needed.

    DOM-XSS most commonly fires from ``location.hash``/``location.search``. If the caller
    already wove the payload into the URL (the URL contains the payload string) or the URL
    already carries a fragment, it is used verbatim — the caller is assumed to know the
    injection point. Otherwise the payload is appended after ``#`` so a fragment-reading
    sink receives it. Pure string logic; no network.
    """
    if not payload:
        return url
    if payload in url:
        return url
    if "#" in url:
        # Caller already chose a fragment; respect it rather than clobbering.
        return url
    return f"{url}#{payload}"


def _run_in_browser(url: str, payload: str, marker: str, timeout: int) -> dict:
    """Drive headless Chromium for ONE (url, payload) and return a verdict dict.

    All Playwright imports/usage live here (inside the function) so the module imports
    without the engine present. Detection is three-pronged — ANY one confirms execution:
      * dialog  — a JS dialog (alert/confirm/prompt/beforeunload) opened.
      * window-marker  — ``window[marker]`` evaluated truthy after load.
      * console-marker — a console message text contained the marker.

    A run that loads cleanly with no signal is NOT-TRIGGERED; a navigation/timeout/crash
    is ERROR. This function assumes is_available() is True; callers gate on it.
    """
    # Imported defensively, inside the function — never at module top level.
    from playwright.sync_api import sync_playwright, Error as PlaywrightError

    signals: list[str] = []
    target = _build_target_url(url, payload)
    timeout_ms = max(1, int(timeout)) * 1000

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                context = browser.new_context()
                # Inject the marker bootstrap BEFORE any page script runs.
                context.add_init_script(_bootstrap_script(marker))
                page = context.new_page()

                # Dialog handler: any opened dialog == execution. Accept + record, then
                # dismiss so navigation isn't blocked.
                def _on_dialog(dialog):
                    if "dialog" not in signals:
                        signals.append("dialog")
                    try:
                        dialog.accept()
                    except Exception:  # noqa: BLE001 - already handled/closed
                        pass

                page.on("dialog", _on_dialog)

                # Console handler: a console message carrying the marker == execution.
                def _on_console(msg):
                    try:
                        text = msg.text
                    except Exception:  # noqa: BLE001
                        text = ""
                    if marker and marker in (text or "") and "console-marker" not in signals:
                        signals.append("console-marker")

                page.on("console", _on_console)

                page.goto(target, timeout=timeout_ms, wait_until="load")
                # Give onerror/onload/microtask payloads a beat to run.
                try:
                    page.wait_for_timeout(500)
                except Exception:  # noqa: BLE001
                    pass

                # Primary marker check: did the payload set window[marker]?
                try:
                    fired = page.evaluate(
                        "(m) => { try { return !!window[m]; } catch (e) { return false; } }",
                        marker,
                    )
                    if fired and "window-marker" not in signals:
                        signals.append("window-marker")
                except Exception:  # noqa: BLE001 - page navigated away / context gone
                    pass
            finally:
                try:
                    browser.close()
                except Exception:  # noqa: BLE001
                    pass
    except PlaywrightError as exc:
        return {
            "verdict": ERROR,
            "detail": f"browser run failed: {exc}",
            "url": url,
            "payload": payload,
            "marker": marker,
            "signals": [],
        }
    except Exception as exc:  # noqa: BLE001 - any unexpected engine failure -> ERROR, never crash
        return {
            "verdict": ERROR,
            "detail": f"unexpected error during browser run: {exc}",
            "url": url,
            "payload": payload,
            "marker": marker,
            "signals": [],
        }

    if signals:
        return {
            "verdict": CONFIRMED,
            "detail": (
                "payload executed in headless Chromium — confirmed via "
                + ", ".join(signals)
            ),
            "url": url,
            "payload": payload,
            "marker": marker,
            "signals": signals,
        }

    return {
        "verdict": NOT_TRIGGERED,
        "detail": (
            "page loaded but no execution signal observed (no dialog, "
            f"window[{marker!r}] not set, no console marker) — payload did not fire"
        ),
        "url": url,
        "payload": payload,
        "marker": marker,
        "signals": [],
    }


def verify_dom_xss(
    url: str,
    payload: str,
    *,
    marker: str = DEFAULT_MARKER,
    timeout: int = 15,
) -> dict:
    """Confirm whether a DOM-XSS payload actually executes against ``url`` in a browser.

    Launches headless Chromium (via Playwright), navigates ``url`` with ``payload``
    injected (into the fragment when the caller hasn't already placed it), and watches for
    real execution through three detectors — a JS dialog opening, ``window[marker]`` being
    set, or a console message carrying ``marker``. ANY of them == CONFIRMED.

    GRACEFUL DEGRADATION: if Playwright/Chromium are not installed, returns verdict
    "UNVERIFIED" with the install hint and does NOT crash. "UNVERIFIED" is deliberately
    distinct from "NOT-TRIGGERED": the latter means the browser ran and saw nothing; the
    former means we could not run at all.

    Args:
        url: the candidate page URL (e.g. the "[POSSIBLE]" DOM-XSS location).
        payload: the XSS payload to inject (e.g.
            ``<img src=x onerror=window.__xss_fired__=1>`` or
            ``"><svg onload=alert(1)>``). To use the window-marker detector, have the
            payload set ``window[marker]`` or ``console.log(marker)``; dialog-based
            payloads (alert/confirm/prompt) are detected automatically.
        marker: the window/console marker watched for (default ``__xss_fired__``).
        timeout: per-navigation timeout in SECONDS (default 15).

    Returns:
        dict with keys: verdict, detail, url, payload, marker, signals (see module
        docstring for the full schema). Never raises for an absent engine or a failed
        navigation — those become UNVERIFIED / ERROR verdicts respectively.
    """
    if not url or not isinstance(url, str):
        return {
            "verdict": ERROR,
            "detail": "no url provided",
            "url": url or "",
            "payload": payload or "",
            "marker": marker,
            "signals": [],
        }
    if payload is None or not isinstance(payload, str) or payload == "":
        return {
            "verdict": ERROR,
            "detail": "no payload provided",
            "url": url,
            "payload": payload or "",
            "marker": marker,
            "signals": [],
        }

    if not is_available():
        # Engine absent — supported state. Report clearly, do not crash.
        return {
            "verdict": UNVERIFIED,
            "detail": INSTALL_HINT,
            "url": url,
            "payload": payload,
            "marker": marker,
            "signals": [],
        }

    return _run_in_browser(url, payload, marker, timeout)


# ─── Human-readable rendering ───────────────────────────────────────────────────

# Per-verdict glyph for the human summary (kept ASCII-safe).
_VERDICT_GLYPH = {
    CONFIRMED: "[+]",
    NOT_TRIGGERED: "[-]",
    UNVERIFIED: "[?]",
    ERROR: "[!]",
}


def _render_result(result: dict) -> str:
    """Render a verify_dom_xss() result as a short human-readable block."""
    verdict = result.get("verdict", ERROR)
    glyph = _VERDICT_GLYPH.get(verdict, "[?]")
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("  DOM-XSS verification (headless Chromium)")
    lines.append(f"  URL    : {result.get('url', '')}")
    lines.append(f"  Payload: {result.get('payload', '')}")
    lines.append(f"  Marker : {result.get('marker', '')}")
    lines.append("=" * 60)
    lines.append(f"{glyph} Verdict: {verdict}")
    lines.append(f"    {result.get('detail', '')}")
    signals = result.get("signals") or []
    if signals:
        lines.append(f"    Signals: {', '.join(signals)}")
    if verdict == UNVERIFIED:
        lines.append("    (no engine — this is NOT a judgment on the bug; install to verify)")
    return "\n".join(lines)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Auto-confirm a [POSSIBLE] DOM-XSS by executing one (url, payload) in a "
            "headless Chromium and reporting whether it fired. Degrades to UNVERIFIED "
            "(with an install hint, exit 0) when Playwright/Chromium are not installed."
        )
    )
    parser.add_argument("--url", required=True, help="Candidate page URL to verify.")
    parser.add_argument("--payload", required=True, help="XSS payload to inject.")
    parser.add_argument(
        "--marker",
        default=DEFAULT_MARKER,
        help=(
            "window/console marker that signals execution without a dialog "
            f"(default: {DEFAULT_MARKER}). Have the payload set window[marker] or "
            "console.log(marker)."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Per-navigation timeout in seconds (default: 15).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the raw result JSON instead of the human-readable verdict.",
    )
    args = parser.parse_args(argv)

    result = verify_dom_xss(
        args.url,
        args.payload,
        marker=args.marker,
        timeout=args.timeout,
    )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_render_result(result))

    # Run completed: exit 0 even for UNVERIFIED (no engine) and NOT-TRIGGERED, mirroring
    # the other UBH engines. Usage errors (missing --url/--payload) already exit 2 via
    # argparse before we reach here.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
