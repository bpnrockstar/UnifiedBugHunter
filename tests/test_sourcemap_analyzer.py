"""Tests for tools/sourcemap_analyzer.py — JS source-map recovery, fully offline.

NO NETWORK. Every case is driven off an inline minified bundle and a local `.map`
file written to a temp dir (its `sourcesContent` carries the original pre-minified
sources). Nothing here fetches a URL, and importing the module never touches the
network. semgrep / jsbeautifier / requests are all OPTIONAL: the SAST pass may come
back empty (engine 'regex-fallback' or 'unavailable') and beautify may fall back to
the built-in line-splitter — either way analysis must complete without crashing.

Covers the importable surface the prompt names:
  * find_sourcemap_url() — parses the `//# sourceMappingURL=` comment (and the
    legacy `//@` form); returns None when absent; last annotation wins
  * load_sourcemap()     — loads/JSON-parses a `.map` from a file path, a data:
    URI, and past a leading XSSI `)]}'` guard
  * extract_sources()    — recovers {path: content} from sourcesContent, skips
    entries with no embedded content, cleans webpack:// / traversal paths
  * beautify_js()         — returns analyzable text, never raises (built-in fallback)
  * secret_scan()         — flags a planted hardcoded key, drops placeholders
  * analyze_bundle()      — on the temp bundle: sources_recovered=='sourcemap',
    recovered_count>0, full result schema, sast_findings may be empty (must not
    crash), secret_hits surfaces the planted secret

stdlib + pytest only.
"""

import json
import os
import sys

import pytest

# Make tools/ importable (mirrors tests/conftest.py; kept self-contained so this
# module imports cleanly even if run in isolation).
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_ROOT = os.path.join(REPO_ROOT, "tools")
for _path in (REPO_ROOT, TOOLS_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import sourcemap_analyzer as sma


# --- Inline offline fixtures -----------------------------------------------------

# A planted, well-formed hardcoded secret (a Google API key shape — AIza + 35 chars)
# embedded in one recovered source. NOT a real key; it just matches the detector so
# the secret pass has something to surface. Kept out of the minified blob on purpose
# so it is only reachable AFTER source-map recovery.
# Assembled at runtime so the literal never appears contiguously in source
# (GitHub push protection flags a contiguous AIza... Google-key string).
PLANTED_GOOGLE_KEY = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"

ORIGINAL_INDEX_JS = (
    "// src/index.js — original pre-minified source\n"
    "export function greet(name) {\n"
    "  return `hello ${name}`;\n"
    "}\n"
)

ORIGINAL_CONFIG_JS = (
    "// src/config.js — original pre-minified source\n"
    f'const GOOGLE_API_KEY = "{PLANTED_GOOGLE_KEY}";\n'
    "export default { GOOGLE_API_KEY };\n"
)

# The shipped, minified bundle. Everything interesting (the two original files,
# the secret) lives ONLY in the map's sourcesContent — the blob itself is a single
# mangled line, exactly like a real build, ending in the sourceMappingURL comment.
MINIFIED_BUNDLE = (
    "(function(){function g(n){return`hello ${n}`}var c={k:0};"
    "window.__app={greet:g,config:c}})();\n"
    "//# sourceMappingURL=app.min.js.map\n"
)

MAP_NAME = "app.min.js.map"
BUNDLE_NAME = "app.min.js"


def _make_sourcemap(sources, sources_content):
    """Build a minimal but valid source-map object (v3 envelope)."""
    return {
        "version": 3,
        "file": BUNDLE_NAME,
        "sourceRoot": "",
        "sources": sources,
        # `mappings` can be empty for our purposes — we only read sourcesContent.
        "names": [],
        "mappings": "",
        "sourcesContent": sources_content,
    }


@pytest.fixture
def bundle_tree(tmp_path):
    """Write a minified bundle + its sibling `.map` into a temp dir.

    The map carries TWO recoverable sources (sourcesContent populated) plus a third
    `sources` entry with NO content (None) that extract_sources must skip. Source
    names use the `webpack://` prefix and a `../` parent escape to exercise the
    traversal-safe path cleaning.

    Returns (bundle_path, map_path, sourcemap_dict).
    """
    sourcemap = _make_sourcemap(
        sources=[
            "webpack://app/./src/index.js",
            "webpack://app/../../src/config.js",  # parent-escape -> must be neutralized
            "webpack://app/./src/vendor-no-content.js",  # no sourcesContent -> skipped
        ],
        sources_content=[
            ORIGINAL_INDEX_JS,
            ORIGINAL_CONFIG_JS,
            None,  # not recoverable from the map alone
        ],
    )
    bundle_path = tmp_path / BUNDLE_NAME
    map_path = tmp_path / MAP_NAME
    bundle_path.write_text(MINIFIED_BUNDLE, encoding="utf-8")
    map_path.write_text(json.dumps(sourcemap), encoding="utf-8")
    return str(bundle_path), str(map_path), sourcemap


# --- import-time safety ----------------------------------------------------------

def test_module_imports_without_network_or_optional_deps():
    # All optional deps are imported defensively; the module exposes the surface
    # regardless of whether requests/semgrep/jsbeautifier are installed.
    for name in (
        "find_sourcemap_url",
        "load_sourcemap",
        "extract_sources",
        "beautify_js",
        "secret_scan",
        "analyze_bundle",
    ):
        assert callable(getattr(sma, name)), f"missing public function {name}"


# --- find_sourcemap_url() --------------------------------------------------------

def test_find_sourcemap_url_parses_standard_comment():
    assert sma.find_sourcemap_url(MINIFIED_BUNDLE) == MAP_NAME


def test_find_sourcemap_url_accepts_legacy_at_form():
    js = "var x=1;\n//@ sourceMappingURL=legacy.js.map\n"
    assert sma.find_sourcemap_url(js) == "legacy.js.map"


def test_find_sourcemap_url_returns_none_when_absent():
    assert sma.find_sourcemap_url("var x = 1; console.log(x);\n") is None
    assert sma.find_sourcemap_url("") is None
    assert sma.find_sourcemap_url(None) is None  # type: ignore[arg-type]


def test_find_sourcemap_url_last_annotation_wins():
    # An earlier hit (inside a vendored sub-bundle) is ignored; bundlers emit the
    # real annotation at the very end.
    js = (
        "//# sourceMappingURL=vendor.js.map\n"
        "var a=1;\n"
        "//# sourceMappingURL=real.js.map\n"
    )
    assert sma.find_sourcemap_url(js) == "real.js.map"


# --- load_sourcemap() ------------------------------------------------------------

def test_load_sourcemap_from_local_file(bundle_tree):
    _bundle, map_path, expected = bundle_tree
    loaded = sma.load_sourcemap(map_path)
    assert isinstance(loaded, dict)
    assert loaded["version"] == 3
    assert loaded["sources"] == expected["sources"]
    assert loaded["sourcesContent"] == expected["sourcesContent"]


def test_load_sourcemap_strips_xssi_guard(tmp_path):
    # Some servers prepend `)]}'` to JSON responses; load_sourcemap must strip it.
    obj = _make_sourcemap(["src/a.js"], ["const a = 1;\n"])
    guarded = tmp_path / "guarded.js.map"
    guarded.write_text(")]}'\n" + json.dumps(obj), encoding="utf-8")
    loaded = sma.load_sourcemap(str(guarded))
    assert loaded["sources"] == ["src/a.js"]


def test_load_sourcemap_from_data_uri():
    import base64

    obj = _make_sourcemap(["src/inline.js"], ["export const z = 42;\n"])
    payload = base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")
    data_uri = "data:application/json;charset=utf-8;base64," + payload
    loaded = sma.load_sourcemap(data_uri)
    assert loaded["sources"] == ["src/inline.js"]
    assert loaded["sourcesContent"] == ["export const z = 42;\n"]


def test_load_sourcemap_invalid_json_raises(tmp_path):
    bad = tmp_path / "bad.js.map"
    bad.write_text("this is not json {{{", encoding="utf-8")
    with pytest.raises(RuntimeError):
        sma.load_sourcemap(str(bad))


# --- extract_sources() -----------------------------------------------------------

def test_extract_sources_recovers_original_content(bundle_tree):
    _bundle, _map, sourcemap = bundle_tree
    sources = sma.extract_sources(sourcemap)

    # Two recoverable files; the no-content entry is skipped.
    assert len(sources) == 2
    # Content is recovered verbatim.
    assert ORIGINAL_INDEX_JS in sources.values()
    assert ORIGINAL_CONFIG_JS in sources.values()
    # The recovered content carries the planted secret (it was never in the blob).
    assert any(PLANTED_GOOGLE_KEY in c for c in sources.values())


def test_extract_sources_cleans_webpack_and_traversal_paths(bundle_tree):
    _bundle, _map, sourcemap = bundle_tree
    sources = sma.extract_sources(sourcemap)
    for path in sources:
        # No scheme prefix, no parent escapes, no absolute roots leaked through.
        assert "://" not in path
        assert not path.startswith("/")
        assert ".." not in path.split("/")
        assert path  # non-empty


def test_extract_sources_skips_empty_content():
    sm = _make_sourcemap(
        sources=["a.js", "b.js", "c.js"],
        sources_content=["const a=1;\n", None, ""],  # only the first is recoverable
    )
    sources = sma.extract_sources(sm)
    assert len(sources) == 1
    assert list(sources.values()) == ["const a=1;\n"]


def test_extract_sources_empty_or_garbage_returns_empty():
    assert sma.extract_sources({}) == {}
    assert sma.extract_sources({"sources": [], "sourcesContent": []}) == {}
    assert sma.extract_sources("not a dict") == {}  # type: ignore[arg-type]


# --- beautify_js() ---------------------------------------------------------------

def test_beautify_js_returns_analyzable_text_and_never_raises():
    # Whether or not jsbeautifier is installed, the result is a non-empty string and
    # the minified one-liner is broken into multiple lines for line-based analysis.
    out = sma.beautify_js("function f(){return 1;}var x=2;if(x){g();}")
    assert isinstance(out, str)
    assert out
    assert out.count("\n") >= 1


def test_beautify_js_empty_input():
    assert sma.beautify_js("") == ""


# --- secret_scan() ---------------------------------------------------------------

def test_secret_scan_flags_planted_key():
    hits = sma.secret_scan(ORIGINAL_CONFIG_JS, path="src/config.js")
    assert hits, "expected the planted Google API key to be flagged"
    h = hits[0]
    assert set(h.keys()) == {"type", "severity", "path", "line", "match"}
    assert h["path"] == "src/config.js"
    assert isinstance(h["line"], int) and h["line"] >= 1
    # The reported match is redacted, never the full secret.
    assert PLANTED_GOOGLE_KEY not in h["match"]


def test_secret_scan_clean_text_no_hits():
    assert sma.secret_scan(ORIGINAL_INDEX_JS, path="src/index.js") == []
    assert sma.secret_scan("", path="x") == []


def test_secret_scan_drops_placeholder():
    # A placeholder assignment must not be reported as a real leak.
    text = 'const api_key = "your_api_key_here_placeholder";\n'
    assert sma.secret_scan(text, path="p.js") == []


# --- analyze_bundle() (the headline case) ----------------------------------------

# The full result schema analyze_bundle() must return.
RESULT_FIELDS = {
    "source",
    "sources_recovered",
    "sourcemap_url",
    "recovered_count",
    "sources_dir",
    "sast_findings",
    "sast_engine",
    "secret_hits",
    "out_path",
}


def test_analyze_bundle_recovers_sources_from_local_map(bundle_tree):
    bundle_path, _map, _sm = bundle_tree
    result = sma.analyze_bundle(bundle_path)

    # Headline assertions from the prompt: recovered via the source map, count > 0.
    assert result["sources_recovered"] == "sourcemap"
    assert result["recovered_count"] > 0

    # Full result structure is present and well-typed.
    assert set(result.keys()) == RESULT_FIELDS
    assert result["source"] == bundle_path
    assert result["sourcemap_url"] is not None
    assert isinstance(result["sast_findings"], list)  # may be empty (semgrep optional)
    assert isinstance(result["secret_hits"], list)
    assert isinstance(result["sast_engine"], str)
    assert result["out_path"] is None  # no out_dir given

    # The original sources were materialized to disk under the temp tree.
    assert result["sources_dir"] and os.path.isdir(result["sources_dir"])
    recovered_files = []
    for root, _dirs, files in os.walk(result["sources_dir"]):
        recovered_files.extend(files)
    assert recovered_files, "expected recovered source files on disk"


def test_analyze_bundle_findings_structure_does_not_crash(bundle_tree):
    # SAST is optional. Whether semgrep is installed or not, sast_findings is a list
    # (possibly empty) and the run completes without raising. Each finding, if any,
    # is a dict — the structure must be sane regardless of engine availability.
    bundle_path, _map, _sm = bundle_tree
    result = sma.analyze_bundle(bundle_path)

    assert isinstance(result["sast_findings"], list)
    for f in result["sast_findings"]:
        assert isinstance(f, dict)
    # Engine label is one of the known states (semgrep present / regex fallback /
    # sast_runner not importable). Never crashes, never an empty/None label.
    assert result["sast_engine"] in (
        "semgrep",
        "regex-fallback",
        "unavailable",
        "unknown",
    )


def test_analyze_bundle_surfaces_recovered_secret(bundle_tree):
    # The planted secret lives ONLY in the map's sourcesContent, so it is reachable
    # only after recovery — proving the pipeline analyzed the recovered source, not
    # the minified blob.
    bundle_path, _map, _sm = bundle_tree
    result = sma.analyze_bundle(bundle_path)

    assert result["secret_hits"], "expected the recovered secret to be flagged"
    for h in result["secret_hits"]:
        assert {"type", "severity", "path", "line", "match"} <= set(h.keys())
        assert PLANTED_GOOGLE_KEY not in h["match"]  # redacted in the report


def test_analyze_bundle_writes_out_path(tmp_path, bundle_tree):
    bundle_path, _map, _sm = bundle_tree
    out = tmp_path / "out"
    result = sma.analyze_bundle(bundle_path, out_dir=str(out))

    out_path = result["out_path"]
    assert out_path and os.path.isfile(out_path)
    # Lands under <out>/findings/js/<ts>/sourcemap_analysis.json.
    assert out_path.startswith(str(out))
    assert os.path.join("findings", "js") in out_path
    assert os.path.basename(out_path) == "sourcemap_analysis.json"
    with open(out_path, encoding="utf-8") as fh:
        on_disk = json.load(fh)
    assert on_disk["sources_recovered"] == "sourcemap"
    assert on_disk["recovered_count"] == result["recovered_count"]


def test_analyze_bundle_beautifies_when_no_map(tmp_path):
    # A bundle with NO sourceMappingURL degrades to beautification — still completes,
    # still recovers (writes) something, never crashes.
    blob = tmp_path / "nomap.js"
    blob.write_text("var a=1;function f(){return a;}window.f=f;\n", encoding="utf-8")
    result = sma.analyze_bundle(str(blob))

    assert result["sources_recovered"] == "beautified"
    assert result["sourcemap_url"] is None
    assert result["recovered_count"] >= 1
    assert isinstance(result["sast_findings"], list)
    assert set(result.keys()) == RESULT_FIELDS


def test_analyze_bundle_missing_map_falls_back_to_beautify(tmp_path):
    # The bundle references a map that does NOT exist on disk. analyze_bundle must
    # degrade to beautification rather than raise.
    blob = tmp_path / "dangling.js"
    blob.write_text(
        "var x=1;window.x=x;\n//# sourceMappingURL=does-not-exist.js.map\n",
        encoding="utf-8",
    )
    result = sma.analyze_bundle(str(blob))
    assert result["sources_recovered"] == "beautified"
    assert result["recovered_count"] >= 1


def test_analyze_bundle_unloadable_bundle_raises(tmp_path):
    # A local bundle path that does not exist is the one unrecoverable error.
    missing = tmp_path / "nope.js"
    with pytest.raises(RuntimeError):
        sma.analyze_bundle(str(missing))
