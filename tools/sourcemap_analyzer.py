#!/usr/bin/env python3
"""
sourcemap_analyzer.py — make LIVE JavaScript analysis real.

Until now "JS analysis" in UBH was curl + grep: download a bundle, regex it for
`api_key`, eyeball the result. That misses almost everything, because shipped JS
is minified into one unreadable line — the interesting code (API routes, auth
logic, hardcoded secrets) is mangled past the point a grep can see it. But most
build pipelines ALSO ship a source map: a `//# sourceMappingURL=...` comment
pointing at a `.map` file whose `sourcesContent` array carries the ORIGINAL,
pre-minified source. Recovering that turns "grep a blob" into "read the actual
TypeScript/ES6 the developers wrote" — and then we can run the real SAST engine
over it.

This module is that recovery step:
  1. find the `//# sourceMappingURL=` comment in a bundle,
  2. fetch/load the referenced `.map` (URL or file),
  3. extract `sourcesContent` into a temp source tree (original sources),
  4. when there is NO map, beautify the minified bundle so it is at least
     line-split and analyzable,
  5. run tools/sast_runner.run_sast() over the reconstructed tree AND a built-in
     secret-regex pass, and return one structured result.

GRACEFUL DEGRADATION (mirrors tools/sast_runner.py + tools/secrets_hunter.sh):
  Every external dependency is OPTIONAL and degrades to a clear, labeled fallback
  — never a crash, never a non-zero exit on a completed analysis:
    * `requests` absent           -> urllib.request (stdlib) is used instead.
    * no source map on the bundle -> beautify the minified source (a real
      beautifier if installed, else a tiny built-in line-splitter) and analyze
      that, labeled sources_recovered='beautified'.
    * semgrep absent              -> run_sast() itself degrades to its regex
      fallback (engine_used='regex-fallback'); we just consume its result.
  No network access happens at import time. `requests` is imported defensively so
  importing this module never requires it (and never touches the network). Tests
  drive the whole surface off fixtures / temp dirs / local servers / mocks and
  NEVER require semgrep, a beautifier, or the network.

Importable surface (all logic lives in top-level functions; tests import them):
    find_sourcemap_url(js_text) -> str | None
    load_sourcemap(path_or_url) -> dict
    extract_sources(sourcemap) -> dict{path: content}
    beautify_js(js_text) -> str
    secret_scan(text, path='') -> list[dict]
    analyze_bundle(js_path_or_url, out_dir=None) -> dict

analyze_bundle() result schema:
    {
      "source": str,                # the bundle we analyzed (url or file)
      "sources_recovered": str,     # 'sourcemap' | 'beautified' | 'raw'
      "sourcemap_url": str | None,  # resolved .map location, when one was found
      "recovered_count": int,       # number of original source files recovered
      "sources_dir": str | None,    # temp tree the sources were written to
      "sast_findings": list[dict],  # tools/sast_runner findings over the tree
      "sast_engine": str,           # run_sast()'s engine_used (semgrep|regex-fallback)
      "secret_hits": list[dict],    # secret-regex pass over the recovered text
      "out_path": str | None,       # set when out_dir was given
    }

CLI:
    python3 tools/sourcemap_analyzer.py --bundle <url|file> [--out <dir>] [--json]
  Prints a human-readable summary (or raw JSON with --json). Always exits 0 when
  the analysis completes — including every fallback path; non-zero only on usage
  / unexpected errors (e.g. the bundle could not be loaded at all).

Python 3, stdlib + optional `requests`. No third-party import is required to
import this module or to run its tests.
"""
from __future__ import annotations  # PEP 604 union syntax on Python 3.9 (system /usr/bin/python3)

import argparse
import importlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

# ─── Optional / sibling imports (defensive — never required to import this) ─────

# `requests` is OPTIONAL and imported defensively. It is NOT imported at module
# import time in a way that could touch the network, and its absence is fine — we
# fall back to urllib.request (stdlib). Importing this module never requires it.
try:  # pragma: no cover - presence depends on the host
    import requests as _requests
except Exception:  # noqa: BLE001 - any import failure means "use the stdlib path"
    _requests = None

# run_sast() from the sibling SAST engine. Imported the same defensive way the
# dashboard imports redact.py: if it cannot be loaded the secret pass still runs
# and sast_findings simply comes back empty (engine 'unavailable'), rather than
# the whole analysis crashing.
_run_sast = None  # type: ignore[assignment]
try:  # pragma: no cover - exercised indirectly
    _TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
    if _TOOLS_DIR not in sys.path:
        sys.path.insert(0, _TOOLS_DIR)
    _sast_mod = importlib.import_module("sast_runner")
    _candidate = getattr(_sast_mod, "run_sast", None)
    if callable(_candidate):
        _run_sast = _candidate
except Exception:  # noqa: BLE001 - never let a missing engine break analysis
    _run_sast = None


# Network timeout (seconds) for any fetch. Kept short — recon fetches should fail
# fast rather than hang the whole pass on one slow host.
_FETCH_TIMEOUT = 15

# Default UA: some CDNs 403 the stdlib urllib default. A browser-ish UA is friendlier.
_USER_AGENT = "Mozilla/5.0 (compatible; UnifiedBugHunter/1.0; sourcemap_analyzer)"

# Directories never written into / never analyzed when materializing sources.
_SKIP_SOURCE_DIRS = ("node_modules", "webpack", ".git", "__pycache__")


# ─── sourceMappingURL discovery ─────────────────────────────────────────────────

# Matches the source-map annotation in JS or CSS, on its own line or trailing.
# Both the `//# sourceMappingURL=` (current) and legacy `//@ sourceMappingURL=`
# forms are accepted, as well as the `/*# ... */` block-comment CSS variant.
_SOURCEMAP_RE = re.compile(
    r"""(?:^|[\s;])               # start-of-line, whitespace, or a trailing `;`
        (?://[#@]|/\*[#@])\s*
        sourceMappingURL\s*=\s*
        (?P<url>[^\s'"*]+)
    """,
    re.VERBOSE | re.MULTILINE,
)


def find_sourcemap_url(js_text: str) -> str | None:
    """Extract the `sourceMappingURL` annotation from a JS/CSS bundle.

    Scans for the `//# sourceMappingURL=<url>` comment (also accepts the legacy
    `//@` and the `/*# ... */` CSS block form). The LAST occurrence wins — bundlers
    emit the real annotation at the very end of the file, and an earlier hit is
    usually inside a vendored sub-bundle or a string literal.

    Args:
        js_text: the full text of a JavaScript (or CSS) bundle.

    Returns:
        The raw map reference exactly as written (a relative path, absolute path,
        or a `data:` URI), or None when no annotation is present.
    """
    if not js_text or not isinstance(js_text, str):
        return None
    matches = list(_SOURCEMAP_RE.finditer(js_text))
    if not matches:
        return None
    return matches[-1].group("url").strip()


# ─── Fetching (requests when present, urllib otherwise) ─────────────────────────

def _is_url(path_or_url: str) -> bool:
    """True when the argument looks like an http(s) URL (vs a local file path)."""
    try:
        scheme = urlparse(path_or_url).scheme.lower()
    except Exception:  # noqa: BLE001
        return False
    return scheme in ("http", "https")


def _fetch_text(url: str) -> str:
    """Fetch a URL's body as text, using `requests` if available else urllib.

    No network happens unless this is actually called (never at import). Raises on
    a failed fetch so the caller can decide how to degrade.

    Raises:
        RuntimeError: the URL could not be fetched / decoded.
    """
    if _requests is not None:
        try:
            resp = _requests.get(
                url, timeout=_FETCH_TIMEOUT, headers={"User-Agent": _USER_AGENT}
            )
            resp.raise_for_status()
            return resp.text
        except Exception as exc:  # noqa: BLE001 - normalize to RuntimeError
            raise RuntimeError(f"failed to fetch {url}: {exc}") from exc

    # stdlib fallback — no third-party dependency required.
    try:
        req = Request(url, headers={"User-Agent": _USER_AGENT})
        with urlopen(req, timeout=_FETCH_TIMEOUT) as resp:  # noqa: S310 - scheme is validated by caller
            raw = resp.read()
        charset = "utf-8"
        ctype = resp.headers.get_content_charset() if hasattr(resp, "headers") else None
        if ctype:
            charset = ctype
        return raw.decode(charset, errors="replace")
    except Exception as exc:  # noqa: BLE001 - normalize to RuntimeError
        raise RuntimeError(f"failed to fetch {url}: {exc}") from exc


def _load_text(path_or_url: str) -> str:
    """Load text from a local file or an http(s) URL."""
    if _is_url(path_or_url):
        return _fetch_text(path_or_url)
    with open(path_or_url, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _resolve_map_ref(bundle_ref: str, map_ref: str) -> str:
    """Resolve a sourceMappingURL relative to the bundle it came from.

    A bundle at `https://x/static/main.js` with `sourceMappingURL=main.js.map`
    resolves to `https://x/static/main.js.map`; a file bundle resolves against its
    directory. Absolute URLs / `data:` URIs / absolute paths pass through.
    """
    if map_ref.startswith("data:") or _is_url(map_ref) or os.path.isabs(map_ref):
        return map_ref
    if _is_url(bundle_ref):
        return urljoin(bundle_ref, map_ref)
    base_dir = os.path.dirname(os.path.abspath(bundle_ref))
    return os.path.join(base_dir, map_ref)


def _decode_data_uri(data_uri: str) -> str:
    """Decode a `data:application/json;base64,...` (or plain) source-map URI."""
    header, _, payload = data_uri.partition(",")
    if ";base64" in header.lower():
        import base64

        return base64.b64decode(payload).decode("utf-8", errors="replace")
    from urllib.parse import unquote

    return unquote(payload)


# ─── Source map loading + extraction ────────────────────────────────────────────

def load_sourcemap(path_or_url: str) -> dict:
    """Load and JSON-parse a source map from a file path, URL, or data: URI.

    Args:
        path_or_url: a `.map` file path, an http(s) URL, or an inline
            `data:application/json;base64,...` source-map URI.

    Returns:
        The parsed source-map object (a dict). Source maps may begin with the XSSI
        guard `)]}'` — it is stripped before parsing.

    Raises:
        RuntimeError: the map could not be loaded or parsed as a JSON object.
    """
    if path_or_url.startswith("data:"):
        text = _decode_data_uri(path_or_url)
    else:
        try:
            text = _load_text(path_or_url)
        except (OSError, RuntimeError) as exc:
            raise RuntimeError(f"could not load source map {path_or_url}: {exc}") from exc

    # Strip a leading XSSI / anti-hijack prefix some servers prepend to JSON.
    stripped = text.lstrip()
    if stripped.startswith(")]}'"):
        stripped = stripped.split("\n", 1)[-1] if "\n" in stripped else ""

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"source map is not valid JSON ({path_or_url}): {exc}") from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"source map is not a JSON object ({path_or_url})")
    return data


def _clean_source_path(raw: str, index: int) -> str:
    """Turn a source-map `sources[i]` entry into a safe relative tree path.

    Strips `webpack://`, scheme prefixes, leading `../` / `./`, and any absolute /
    drive root, so materializing the tree can never escape the temp dir
    (path-traversal-safe). Falls back to `source_<i>.js` when nothing usable
    remains.
    """
    path = (raw or "").strip()
    # Drop a webpack:// (or other scheme) prefix, keeping the path component.
    path = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", path)
    # Webpack also emits namespaced entries like "webpack://app/./src/x.js".
    path = re.sub(r"^[^/]*/", "", path) if path.startswith("webpack") else path
    # Normalize separators and strip query/hash noise.
    path = path.replace("\\", "/").split("?", 1)[0].split("#", 1)[0]
    # Remove any leading relative / absolute markers and parent escapes.
    parts = [p for p in path.split("/") if p not in ("", ".", "..")]
    cleaned = "/".join(parts)
    if not cleaned:
        cleaned = f"source_{index}.js"
    return cleaned


def extract_sources(sourcemap: dict) -> dict:
    """Pull the original pre-minified sources out of a parsed source map.

    Pairs each `sources[i]` name with its `sourcesContent[i]` body (the original
    file text bundlers embed). Entries with no embedded content (None / empty) are
    skipped — those would have to be re-fetched separately and are not recoverable
    from the map alone.

    Args:
        sourcemap: a parsed source-map object (from load_sourcemap()).

    Returns:
        dict mapping a cleaned, traversal-safe relative path -> source text. Empty
        when the map carries no `sourcesContent`.
    """
    if not isinstance(sourcemap, dict):
        return {}
    sources = sourcemap.get("sources") or []
    contents = sourcemap.get("sourcesContent") or []

    recovered: dict[str, str] = {}
    for i, name in enumerate(sources):
        content = contents[i] if i < len(contents) else None
        if not content or not isinstance(content, str):
            continue  # no embedded source for this entry — not recoverable here
        path = _clean_source_path(str(name), i)
        # Avoid clobbering on a duplicate cleaned path (rare; disambiguate by index).
        if path in recovered:
            root, ext = os.path.splitext(path)
            path = f"{root}.{i}{ext}"
        recovered[path] = content
    return recovered


# ─── Beautification (no map available) ──────────────────────────────────────────

def _builtin_beautify(js_text: str) -> str:
    """Tiny dependency-free line-splitter for minified JS.

    Not a real beautifier — it just inserts newlines after `;` `{` `}` so a one-line
    minified blob becomes line-oriented enough for line-based SAST/regex passes to
    see distinct statements. String/regex literals are NOT parsed, so this is
    deliberately conservative; it is the absolute fallback when no real beautifier
    is installed.
    """
    out = re.sub(r"([;{}])", r"\1\n", js_text)
    # Collapse runs of blank lines the naive split can produce.
    out = re.sub(r"\n\s*\n+", "\n", out)
    return out


def beautify_js(js_text: str) -> str:
    """Beautify a minified JS bundle, degrading to a built-in splitter.

    Prefers the `jsbeautifier` package when it is installed (a real beautifier);
    otherwise falls back to a small built-in line-splitter so the result is at
    least analyzable line-by-line. Either way returns a string and never raises —
    absence of the optional beautifier is a supported state.

    Args:
        js_text: minified JavaScript source.

    Returns:
        Beautified (or at least line-split) JavaScript.
    """
    if not js_text:
        return ""
    try:  # optional dependency — real beautifier when present
        import jsbeautifier  # type: ignore

        return jsbeautifier.beautify(js_text)
    except Exception:  # noqa: BLE001 - not installed / failed -> built-in fallback
        return _builtin_beautify(js_text)


# ─── Secret regex pass ──────────────────────────────────────────────────────────

# High-signal secret patterns. Mirrors the intent of secrets_hunter.sh's regex
# fallback and sast_runner's secret rule, but tuned for recovered JS source: known
# token shapes (AWS/Google/Slack/GitHub/JWT/private keys) first, then a generic
# assignment catch-all. Each entry: (name, severity, compiled regex).
_SECRET_PATTERNS: list[tuple[str, str, "re.Pattern[str]"]] = [
    ("aws-access-key-id", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", "high", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("slack-token", "high", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b")),
    ("github-token", "high", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("stripe-key", "high", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    (
        "private-key-block",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    (
        "jwt",
        "medium",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ),
    (
        "generic-assigned-secret",
        "medium",
        re.compile(
            r"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|secret[_-]?key|aws_secret_access_key|"
            r"private[_-]?key|passwd|password)"
            r"\s*[:=]\s*[\"'][A-Za-z0-9/\+=_\-\.]{12,}[\"']"
        ),
    ),
]

# Substrings that mark an assignment as a placeholder, not a real leak — skipped to
# cut obvious false positives on the generic catch-all.
_SECRET_PLACEHOLDERS = (
    "your_", "example", "changeme", "placeholder", "xxxx", "<", "process.env",
    "redacted", "dummy", "sample", "todo",
)


def _redact_secret(value: str) -> str:
    """Mask the middle of a matched secret for safe logging/reporting."""
    value = value.strip().strip("'\"")
    if len(value) <= 8:
        return value[:2] + "***"
    return f"{value[:4]}...{value[-2:]}"


def secret_scan(text: str, path: str = "") -> list[dict]:
    """Scan recovered source text for hardcoded secrets, line by line.

    Args:
        text: source text to scan.
        path: logical path of the source (recorded on each hit for context).

    Returns:
        list of hit dicts: {type, severity, path, line, match (redacted)}.
        Matches whose value looks like a placeholder are dropped.
    """
    if not text:
        return []
    hits: list[dict] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, severity, pattern in _SECRET_PATTERNS:
            m = pattern.search(line)
            if not m:
                continue
            matched = m.group(0)
            if any(ph in matched.lower() for ph in _SECRET_PLACEHOLDERS):
                continue
            hits.append(
                {
                    "type": name,
                    "severity": severity,
                    "path": path,
                    "line": lineno,
                    "match": _redact_secret(matched),
                }
            )
    return hits


# ─── Materialization + orchestration ────────────────────────────────────────────

def _write_sources(sources: dict, dest_root: str) -> int:
    """Write recovered {path: content} into dest_root, traversal-safe.

    Returns the count of files actually written. Paths that would escape dest_root
    (defense in depth on top of _clean_source_path) or land in a skip dir are
    dropped.
    """
    written = 0
    real_root = os.path.realpath(dest_root)
    for rel, content in sources.items():
        if any(part in _SKIP_SOURCE_DIRS for part in rel.split("/")):
            continue
        target = os.path.realpath(os.path.join(dest_root, rel))
        # Containment check: target must stay inside dest_root.
        if target != real_root and not target.startswith(real_root + os.sep):
            continue
        os.makedirs(os.path.dirname(target) or dest_root, exist_ok=True)
        try:
            with open(target, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(content)
            written += 1
        except OSError:
            continue
    return written


def analyze_bundle(js_path_or_url: str, out_dir: str | None = None) -> dict:
    """Recover original sources from a JS bundle and run real analysis over them.

    Pipeline (each step degrades gracefully — see the module docstring):
      1. load the bundle text (URL via requests/urllib, or a local file),
      2. find its `sourceMappingURL`; if present, load the `.map` and extract
         `sourcesContent` into a temp source tree (sources_recovered='sourcemap'),
      3. if there is no usable map, beautify the minified bundle and analyze that
         (sources_recovered='beautified'),
      4. run tools/sast_runner.run_sast() over the recovered tree, and
      5. run secret_scan() over the recovered text.

    Args:
        js_path_or_url: the bundle to analyze — an http(s) URL or a local file.
        out_dir: when set, the full result JSON is written to
            <out_dir>/findings/js/<timestamp>/sourcemap_analysis.json.

    Returns:
        The result dict described in the module docstring. Raises only when the
        bundle itself cannot be loaded at all (the one unrecoverable error).

    Raises:
        RuntimeError: the bundle could not be loaded (no text to analyze).
    """
    try:
        js_text = _load_text(js_path_or_url)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"could not load bundle {js_path_or_url}: {exc}") from exc

    result: dict = {
        "source": js_path_or_url,
        "sources_recovered": "raw",
        "sourcemap_url": None,
        "recovered_count": 0,
        "sources_dir": None,
        "sast_findings": [],
        "sast_engine": "unavailable",
        "secret_hits": [],
        "out_path": None,
    }

    # Temp tree the recovered/beautified sources are materialized into. Kept on
    # disk (NOT auto-deleted) so the caller / downstream tools can inspect it; the
    # path is returned in the result.
    work_dir = tempfile.mkdtemp(prefix="ubh_jsmap_")
    sources_dir = os.path.join(work_dir, "sources")
    os.makedirs(sources_dir, exist_ok=True)
    result["sources_dir"] = sources_dir

    recovered_text_parts: list[str] = []

    # --- Step 2/3: recover sources (sourcemap preferred, beautify fallback) ------
    map_ref = find_sourcemap_url(js_text)
    sources: dict[str, str] = {}
    if map_ref:
        resolved = _resolve_map_ref(js_path_or_url, map_ref)
        result["sourcemap_url"] = resolved
        try:
            sourcemap = load_sourcemap(resolved)
            sources = extract_sources(sourcemap)
        except RuntimeError as exc:
            # Map was referenced but unreachable/unparseable — degrade to beautify.
            print(f"WARNING: source map unusable ({exc}); beautifying instead", file=sys.stderr)
            sources = {}

    if sources:
        result["sources_recovered"] = "sourcemap"
        result["recovered_count"] = _write_sources(sources, sources_dir)
        recovered_text_parts.extend(sources.values())
    else:
        # No usable map -> beautify the minified bundle so it is analyzable.
        beautified = beautify_js(js_text)
        result["sources_recovered"] = "beautified"
        bundle_name = os.path.basename(urlparse(js_path_or_url).path) or "bundle.js"
        if not bundle_name.endswith(".js"):
            bundle_name += ".js"
        result["recovered_count"] = _write_sources({bundle_name: beautified}, sources_dir)
        recovered_text_parts.append(beautified)

    # --- Step 4: SAST over the recovered tree (run_sast degrades on its own) -----
    if _run_sast is not None:
        try:
            sast_result = _run_sast(sources_dir)
            result["sast_findings"] = sast_result.get("findings", [])
            result["sast_engine"] = sast_result.get("summary", {}).get(
                "engine_used", "unknown"
            )
        except Exception as exc:  # noqa: BLE001 - analysis must survive a SAST error
            print(f"WARNING: SAST pass failed: {exc}", file=sys.stderr)
            result["sast_engine"] = "unavailable"
    # else: sast_runner could not be imported — sast_findings stays [], engine 'unavailable'.

    # --- Step 5: secret regex pass over all recovered text -----------------------
    secret_hits: list[dict] = []
    if result["sources_recovered"] == "sourcemap":
        for rel, content in sources.items():
            secret_hits.extend(secret_scan(content, path=rel))
    else:
        for chunk in recovered_text_parts:
            secret_hits.extend(secret_scan(chunk, path=result["source"]))
    result["secret_hits"] = secret_hits

    # --- Optional persistence ----------------------------------------------------
    if out_dir:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        dest_dir = os.path.join(out_dir, "findings", "js", ts)
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, "sourcemap_analysis.json")
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, sort_keys=True)
            fh.write("\n")
        result["out_path"] = dest

    return result


# ─── Human-readable rendering ───────────────────────────────────────────────────

def _render_summary(result: dict) -> str:
    """Render an analyze_bundle() result as a short human-readable block."""
    lines: list[str] = []
    lines.append("=" * 64)
    lines.append("  JS bundle analysis")
    lines.append(f"  Bundle: {result['source']}")
    recovered = result["sources_recovered"]
    lines.append(f"  Recovery: {recovered}  ({result['recovered_count']} file(s))")
    if recovered == "sourcemap":
        lines.append(f"  Source map: {result.get('sourcemap_url')}")
        lines.append("  [+] Original pre-minified sources recovered from sourcesContent.")
    elif recovered == "beautified":
        lines.append("  [!] No usable source map — minified bundle beautified for analysis.")
        try:
            import jsbeautifier  # noqa: F401
        except Exception:  # noqa: BLE001
            lines.append("      (built-in line-splitter used; install jsbeautifier for real beautification)")
    lines.append(f"  Sources dir: {result.get('sources_dir')}")
    lines.append(f"  SAST engine: {result.get('sast_engine')}")
    lines.append("=" * 64)

    sast = result.get("sast_findings") or []
    lines.append(f"SAST findings: {len(sast)}")
    for f in sast[:25]:
        loc = f"{f.get('path','')}:{f.get('line',0)}" if f.get("line") else f.get("path", "")
        lines.append(
            f"  [{f.get('severity','info'):<8}] {f.get('vuln_class','other'):<16} {loc}  ({f.get('rule_id','')})"
        )
    if len(sast) > 25:
        lines.append(f"  ... and {len(sast) - 25} more")

    secrets = result.get("secret_hits") or []
    lines.append("")
    lines.append(f"Secret hits: {len(secrets)}")
    for s in secrets[:25]:
        loc = f"{s.get('path','')}:{s.get('line',0)}"
        lines.append(f"  [{s.get('severity','medium'):<8}] {s.get('type',''):<24} {loc}  {s.get('match','')}")
    if len(secrets) > 25:
        lines.append(f"  ... and {len(secrets) - 25} more")

    if result.get("sast_engine") == "regex-fallback":
        lines.append("\n[!] No SAST engine installed — sast_runner used its regex fallback.")
        lines.append("    Install semgrep for real coverage: pip install semgrep")
    if result.get("sast_engine") == "unavailable":
        lines.append("\n[!] sast_runner could not be loaded — only the secret pass ran.")

    lines.append(
        "\nNote: this is analyzer output. The LLM layer triages, dedupes, and "
        "confirms exploitability (e.g. is a 'secret' live? is a sink reachable?)."
    )
    return "\n".join(lines)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Recover original sources from a JS bundle (via its source map, or by "
            "beautifying when none exists) and run real SAST + a secret pass over "
            "them. Every external dependency is optional and degrades gracefully."
        )
    )
    parser.add_argument(
        "--bundle",
        required=True,
        help="JS bundle to analyze — an http(s) URL or a local file path.",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output root; writes <out>/findings/js/<ts>/sourcemap_analysis.json.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full result as JSON instead of a human-readable summary.",
    )
    args = parser.parse_args(argv)

    # A local-file bundle that does not exist is a usage error (exit 2), matching
    # sast_runner's --path handling. URLs are validated by the fetch itself.
    if not _is_url(args.bundle) and not os.path.exists(args.bundle):
        print(f"ERROR: bundle path does not exist: {args.bundle}", file=sys.stderr)
        return 2

    try:
        result = analyze_bundle(args.bundle, out_dir=args.out)
    except RuntimeError as exc:
        # The one unrecoverable case: the bundle itself could not be loaded.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_render_summary(result))
        if result.get("out_path"):
            print(f"\nWrote full result -> {result['out_path']}")

    # Analysis completed: exit 0 even on every fallback path and even with findings.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
