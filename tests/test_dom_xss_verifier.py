"""Tests for tools/dom_xss_verifier.py — DOM-XSS confirmation, fully offline.

Playwright and Chromium are NEVER required. The module imports cleanly without
playwright (all playwright imports live inside the functions), and the verdict logic
is exercised two ways without any real browser or network:

  * is_available() is monkeypatched to force the engine-present / engine-absent paths.
  * The headless-browser run is driven against a FAKE playwright module injected into
    sys.modules — a tiny stub that records the dialog/console/init handlers and lets a
    test decide which execution signal "fires". This proves the dialog / window-marker /
    console-marker detectors and the NOT-TRIGGERED / ERROR branches without launching
    Chromium.

stdlib + pytest only.

Covers:
  * module imports with playwright absent (no top-level import of it)
  * is_available()        — False on ImportError; gated correctly
  * verify_dom_xss()      — UNVERIFIED (no engine, carries install hint, never crashes),
                            ERROR on empty url/payload, and (via the fake engine)
                            CONFIRMED on each detector, NOT-TRIGGERED, and ERROR on a
                            navigation failure
  * _build_target_url()   — payload appended to fragment / respected when already present
  * CLI main()            — exits 0 for UNVERIFIED + completed runs, JSON output shape
"""

import builtins
import importlib
import json
import os
import sys

import pytest

# Make tools/ importable (mirrors tests/conftest.py; kept self-contained so this module
# imports cleanly even if run in isolation).
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_ROOT = os.path.join(REPO_ROOT, "tools")
for _path in (REPO_ROOT, TOOLS_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import dom_xss_verifier as dom


RESULT_FIELDS = {"verdict", "detail", "url", "payload", "marker", "signals"}


# --- module import / no top-level playwright -------------------------------------

def test_module_imports_without_playwright():
    # The module must import even when playwright is entirely absent — it is in
    # sys.modules here only if installed; the import above already succeeded, which is
    # the proof. Re-importing must not blow up either.
    importlib.reload(dom)
    assert hasattr(dom, "verify_dom_xss")
    assert hasattr(dom, "is_available")


def test_no_top_level_playwright_import():
    # Static guard: 'playwright' must not be imported at module top level (only inside
    # functions). Read the source and assert no bare top-level import line.
    src_path = os.path.join(TOOLS_ROOT, "dom_xss_verifier.py")
    with open(src_path, encoding="utf-8") as fh:
        src = fh.read()
    for line in src.splitlines():
        stripped = line.strip()
        # Top-level (column 0) import lines have no leading indentation.
        if line and not line[0].isspace():
            assert not stripped.startswith("import playwright")
            assert not stripped.startswith("from playwright")


# --- is_available() --------------------------------------------------------------

def test_is_available_false_when_playwright_missing(monkeypatch):
    # Force the defensive import inside is_available() to raise ImportError.
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "playwright" or name.startswith("playwright."):
            raise ImportError("No module named 'playwright'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert dom.is_available() is False


# --- verify_dom_xss(): engine-absent + input guards ------------------------------

def test_verify_unverified_when_engine_absent(monkeypatch):
    monkeypatch.setattr(dom, "is_available", lambda: False)
    result = dom.verify_dom_xss("https://example.com/p", "<svg onload=alert(1)>")
    assert result["verdict"] == dom.UNVERIFIED
    assert result["detail"] == dom.INSTALL_HINT
    assert "pip install playwright" in result["detail"]
    assert result["signals"] == []
    assert set(result.keys()) == RESULT_FIELDS
    # url/payload/marker echoed back.
    assert result["url"] == "https://example.com/p"
    assert result["payload"] == "<svg onload=alert(1)>"
    assert result["marker"] == dom.DEFAULT_MARKER


def test_verify_never_raises_when_engine_absent(monkeypatch):
    monkeypatch.setattr(dom, "is_available", lambda: False)
    # Even with odd inputs, no exception — graceful degradation.
    result = dom.verify_dom_xss("https://x.com", "payload", marker="m", timeout=1)
    assert result["verdict"] == dom.UNVERIFIED


def test_verify_error_on_empty_url(monkeypatch):
    # Guards run before the engine check, so this holds regardless of availability.
    monkeypatch.setattr(dom, "is_available", lambda: True)
    result = dom.verify_dom_xss("", "<svg>")
    assert result["verdict"] == dom.ERROR
    assert "url" in result["detail"]
    assert set(result.keys()) == RESULT_FIELDS


def test_verify_error_on_empty_payload(monkeypatch):
    monkeypatch.setattr(dom, "is_available", lambda: True)
    result = dom.verify_dom_xss("https://x.com", "")
    assert result["verdict"] == dom.ERROR
    assert "payload" in result["detail"]


def test_verify_error_on_none_payload(monkeypatch):
    monkeypatch.setattr(dom, "is_available", lambda: True)
    result = dom.verify_dom_xss("https://x.com", None)  # type: ignore[arg-type]
    assert result["verdict"] == dom.ERROR


# --- _build_target_url() ---------------------------------------------------------

def test_build_target_url_appends_payload_to_fragment():
    assert dom._build_target_url("https://x.com/p", "<svg onload=alert(1)>") == (
        "https://x.com/p#<svg onload=alert(1)>"
    )


def test_build_target_url_respects_existing_fragment():
    # Caller already chose a fragment — do not clobber it.
    assert dom._build_target_url("https://x.com/p#foo", "bar") == "https://x.com/p#foo"


def test_build_target_url_payload_already_in_url():
    # Caller wove the payload into the URL — use verbatim.
    url = "https://x.com/p?q=<svg>"
    assert dom._build_target_url(url, "<svg>") == url


def test_build_target_url_empty_payload_returns_url():
    assert dom._build_target_url("https://x.com/p", "") == "https://x.com/p"


# --- Fake playwright engine (drives _run_in_browser without a real browser) ------

class _FakeDialog:
    def __init__(self):
        self.accepted = False

    def accept(self):
        self.accepted = True


class _FakeConsoleMsg:
    def __init__(self, text):
        self.text = text


class _FakePage:
    """A stub Page whose .goto() emits whichever execution signal the test selects."""

    def __init__(self, fire="none", marker=dom.DEFAULT_MARKER, goto_raises=None):
        self._fire = fire            # 'dialog' | 'window' | 'console' | 'none'
        self._marker = marker
        self._goto_raises = goto_raises
        self._handlers = {}

    def on(self, event, handler):
        self._handlers[event] = handler

    def add_init_script(self, script):  # context-level in real API; harmless here
        pass

    def goto(self, url, timeout=None, wait_until=None):
        if self._goto_raises is not None:
            raise self._goto_raises
        # Simulate the page executing the payload by invoking the registered handlers.
        if self._fire == "dialog" and "dialog" in self._handlers:
            self._handlers["dialog"](_FakeDialog())
        elif self._fire == "console" and "console" in self._handlers:
            self._handlers["console"](_FakeConsoleMsg(f"prefix {self._marker} suffix"))

    def wait_for_timeout(self, ms):
        pass

    def evaluate(self, expr, marker=None):
        # Returns truthy only when this test selected the window-marker signal.
        return self._fire == "window"


class _FakeContext:
    def __init__(self, page):
        self._page = page

    def add_init_script(self, script):
        pass

    def new_page(self):
        return self._page


class _FakeBrowser:
    def __init__(self, page):
        self._page = page
        self.closed = False

    def new_context(self):
        return _FakeContext(self._page)

    def close(self):
        self.closed = True


class _FakeChromium:
    def __init__(self, page, launch_raises=None):
        self._page = page
        self._launch_raises = launch_raises
        self.executable_path = "/fake/chromium"

    def launch(self, headless=True):
        if self._launch_raises is not None:
            raise self._launch_raises
        return _FakeBrowser(self._page)


class _FakePlaywrightCtx:
    def __init__(self, page, launch_raises=None):
        self.chromium = _FakeChromium(page, launch_raises=launch_raises)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakePlaywrightError(Exception):
    """Stand-in for playwright.sync_api.Error."""


def _install_fake_playwright(monkeypatch, page, launch_raises=None):
    """Inject a fake `playwright.sync_api` module so _run_in_browser drives the stub.

    No real playwright is required. is_available() is forced True so verify_dom_xss()
    proceeds into _run_in_browser, where `from playwright.sync_api import ...` resolves
    to this fake.
    """
    import types

    sync_api = types.ModuleType("playwright.sync_api")

    def sync_playwright():
        return _FakePlaywrightCtx(page, launch_raises=launch_raises)

    sync_api.sync_playwright = sync_playwright
    sync_api.Error = _FakePlaywrightError

    pkg = types.ModuleType("playwright")
    pkg.sync_api = sync_api

    monkeypatch.setitem(sys.modules, "playwright", pkg)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(dom, "is_available", lambda: True)


# --- verify_dom_xss(): CONFIRMED via each detector -------------------------------

def test_verify_confirmed_via_dialog(monkeypatch):
    page = _FakePage(fire="dialog")
    _install_fake_playwright(monkeypatch, page)
    result = dom.verify_dom_xss("https://x.com/p", "<svg onload=alert(1)>")
    assert result["verdict"] == dom.CONFIRMED
    assert "dialog" in result["signals"]
    assert set(result.keys()) == RESULT_FIELDS


def test_verify_confirmed_via_window_marker(monkeypatch):
    page = _FakePage(fire="window")
    _install_fake_playwright(monkeypatch, page)
    result = dom.verify_dom_xss(
        "https://x.com/p", "<img src=x onerror=window.__xss_fired__=1>"
    )
    assert result["verdict"] == dom.CONFIRMED
    assert "window-marker" in result["signals"]


def test_verify_confirmed_via_console_marker(monkeypatch):
    page = _FakePage(fire="console", marker="ZZmark99")
    _install_fake_playwright(monkeypatch, page)
    result = dom.verify_dom_xss(
        "https://x.com/p", "<img src=x onerror=console.log('ZZmark99')>", marker="ZZmark99"
    )
    assert result["verdict"] == dom.CONFIRMED
    assert "console-marker" in result["signals"]


def test_verify_not_triggered_when_no_signal(monkeypatch):
    page = _FakePage(fire="none")
    _install_fake_playwright(monkeypatch, page)
    result = dom.verify_dom_xss("https://x.com/p", "<b>not xss</b>")
    assert result["verdict"] == dom.NOT_TRIGGERED
    assert result["signals"] == []
    # Distinct from UNVERIFIED — the browser ran and saw nothing.
    assert result["verdict"] != dom.UNVERIFIED


def test_verify_error_on_navigation_failure(monkeypatch):
    # goto() raising the playwright Error subclass -> ERROR verdict, no crash.
    page = _FakePage(fire="none", goto_raises=_FakePlaywrightError("net::ERR_NAME_NOT_RESOLVED"))
    _install_fake_playwright(monkeypatch, page)
    result = dom.verify_dom_xss("https://nonexistent.invalid/p", "<svg onload=alert(1)>")
    assert result["verdict"] == dom.ERROR
    assert "failed" in result["detail"].lower()
    assert result["signals"] == []


def test_verify_error_on_unexpected_launch_failure(monkeypatch):
    # A non-playwright exception during launch is caught too — never crashes the caller.
    page = _FakePage(fire="none")
    _install_fake_playwright(monkeypatch, page, launch_raises=RuntimeError("boom"))
    result = dom.verify_dom_xss("https://x.com/p", "<svg onload=alert(1)>")
    assert result["verdict"] == dom.ERROR


# --- CLI main() ------------------------------------------------------------------

def test_cli_unverified_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(dom, "is_available", lambda: False)
    rc = dom.main(["--url", "https://x.com/p", "--payload", "<svg onload=alert(1)>"])
    assert rc == 0  # completed run (no engine) still exits 0
    out = capsys.readouterr().out
    assert "UNVERIFIED" in out
    assert dom.INSTALL_HINT in out


def test_cli_json_output_shape(monkeypatch, capsys):
    monkeypatch.setattr(dom, "is_available", lambda: False)
    rc = dom.main(["--url", "https://x.com/p", "--payload", "x", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert set(data.keys()) == RESULT_FIELDS
    assert data["verdict"] == dom.UNVERIFIED


def test_cli_confirmed_exits_zero(monkeypatch, capsys):
    page = _FakePage(fire="dialog")
    _install_fake_playwright(monkeypatch, page)
    rc = dom.main(["--url", "https://x.com/p", "--payload", "<svg onload=alert(1)>"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CONFIRMED" in out


def test_cli_missing_payload_exits_two(monkeypatch):
    # argparse enforces required args -> SystemExit(2) before any run.
    with pytest.raises(SystemExit) as exc:
        dom.main(["--url", "https://x.com/p"])
    assert exc.value.code == 2


def test_cli_custom_marker_passed_through(monkeypatch, capsys):
    page = _FakePage(fire="console", marker="myMARK7")
    _install_fake_playwright(monkeypatch, page)
    rc = dom.main(
        ["--url", "https://x.com/p", "--payload", "console.log('myMARK7')",
         "--marker", "myMARK7", "--json"]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["marker"] == "myMARK7"
    assert data["verdict"] == dom.CONFIRMED
