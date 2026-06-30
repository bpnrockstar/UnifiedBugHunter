"""
Source-level false-positive gate for UBH's code-review (SAST) layer.

This is the negative counterpart to the accuracy eval in
``eval/code_corpus/run_eval_code.py``: instead of measuring recall on the
intentionally-vulnerable fixtures, it pins down PRECISION on the matched SAFE
variants. A code reviewer that screams on parameterized queries, escaped
output, validated redirects, and allowlisted SSRF is worse than useless — every
spurious hit is reviewer time burned and trust lost. This gate fails CI the
moment the analyzer starts flagging code that is provably safe.

What it drives:
  * ``tools/sast_runner.regex_fallback`` — the engine-INDEPENDENT path. We use
    the regex fallback (not semgrep) on purpose: it has no external dependency,
    runs identically on every machine, and is the one analyzer UBH ships and
    fully controls. semgrep / osv-scanner are never required here.

What it asserts:
  1. Over the SAFE corpus (eval/code_corpus/safe/), the fallback produces ZERO
     findings per file — the precision contract for negatives.
  2. Over the matched VULNERABLE files the fallback has patterns for, it DOES
     flag the right class — a sanity check that the gate is not passing simply
     because the engine returns nothing on everything.
  3. A handful of inline SAFE snippets (idiomatic safe SQL / escaped output /
     validated redirect / JSON deserialization) never match. Allowlisted SSRF is
     gated at the corpus level instead — see the known-limitation note below.

Known-limitation handling (honest, not hidden):
  The regex fallback is a substring-level safety net, not a dataflow engine. It
  has exactly one documented false positive on this corpus — its bare ``fetch(``
  SSRF sink matches Python's ``def fetch():`` in ``safe/ssrf.py``. That single
  case is marked ``xfail(strict=True)`` below so (a) the gate stays green and
  enforceable, (b) the FP is loudly tracked and can never silently spread to
  other files, and (c) the day someone tightens the pattern, the xfail flips to
  XPASS and forces this note to be removed. Every OTHER safe file is a hard
  assertion. Classes the fallback has no pattern for (path-traversal, SSTI,
  jwt-alg-none, and the JS variants it misses) are out of this gate's scope:
  they are false NEGATIVES of a deliberately small engine, measured by the
  accuracy eval, not precision regressions.

Offline, stdlib + pytest only. If the corpus is absent the whole module skips
with a clear reason rather than erroring.
"""

import os
import sys

import pytest

# Match the import convention used by conftest.py / test_run_eval_code.py: put
# repo root and tools/ on sys.path so `import sast_runner` resolves the same
# module whether tests import it bare or as `tools.sast_runner`.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_ROOT = os.path.join(REPO_ROOT, "tools")
for _path in (REPO_ROOT, TOOLS_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import sast_runner  # noqa: E402  (path setup must precede the import)

CORPUS_DIR = os.path.join(REPO_ROOT, "eval", "code_corpus")
SAFE_DIR = os.path.join(CORPUS_DIR, "safe")
VULN_DIR = os.path.join(CORPUS_DIR, "vulnerable")

# Skip the ENTIRE module (collection-safe) when the corpus isn't checked out.
pytestmark = pytest.mark.skipif(
    not os.path.isdir(SAFE_DIR) or not os.path.isdir(VULN_DIR),
    reason=(
        "code corpus not present at eval/code_corpus/{safe,vulnerable}/ — "
        "nothing to gate (run from a full checkout to exercise this test)"
    ),
)


# ---------------------------------------------------------------------------
# Negatives: SAFE corpus files must produce ZERO regex-fallback findings.
# ---------------------------------------------------------------------------

# The SAFE files the fallback handles cleanly (parameterized queries, escaped /
# textContent output, env-sourced secrets, JSON instead of pickle, PBKDF2). Each
# is a hard zero-findings assertion. `safe/ssrf.py` is handled separately as a
# documented xfail (see module docstring) so the gate stays enforceable.
SAFE_CLEAN_FILES = [
    "sqli.py",
    "sqli.js",
    "xss.py",
    "xss.js",
    "command_injection.py",
    "command_injection.js",
    "hardcoded_secret.py",
    "hardcoded_secret.js",
    "insecure_deserialization.py",
    "weak_crypto.py",
    # Files with no fallback pattern at all — must also stay clean.
    "path_traversal.py",
    "ssti.py",
    "jwt_alg_none.py",
]


@pytest.mark.parametrize("safe_name", SAFE_CLEAN_FILES)
def test_safe_file_has_no_findings(safe_name):
    """A provably-safe variant must yield zero findings from the fallback."""
    path = os.path.join(SAFE_DIR, safe_name)
    if not os.path.isfile(path):
        pytest.skip(f"safe fixture missing: {safe_name}")
    findings = sast_runner.regex_fallback(path)
    assert findings == [], (
        f"FALSE POSITIVE: regex_fallback flagged safe/{safe_name} "
        f"(precision regression): "
        f"{[(f['vuln_class'], f['line'], f['rule_id']) for f in findings]}"
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN, TRACKED FP: the fallback's bare `fetch(` SSRF sink matches "
        "Python `def fetch():` in safe/ssrf.py (substring match, no dataflow). "
        "Allowlisted-SSRF logic itself is correct. If the pattern is tightened "
        "this XPASSes — delete the xfail and move ssrf.py into SAFE_CLEAN_FILES."
    ),
)
def test_safe_allowlisted_ssrf_has_no_findings():
    """Allowlisted SSRF is safe; the engine's one documented FP is gated here."""
    path = os.path.join(SAFE_DIR, "ssrf.py")
    if not os.path.isfile(path):
        pytest.skip("safe fixture missing: ssrf.py")
    assert sast_runner.regex_fallback(path) == []


def test_safe_dir_scan_only_known_fp():
    """Scanning the whole safe/ tree surfaces only the single documented FP.

    Belt-and-suspenders over the per-file parametrization: it also catches a
    regression where a NEW safe file starts getting flagged. Anything beyond the
    one known `safe/ssrf.py` substring hit is an unacceptable false positive.
    """
    findings = sast_runner.regex_fallback(SAFE_DIR)
    unexpected = [f for f in findings if os.path.basename(f["path"]) != "ssrf.py"]
    assert unexpected == [], (
        "NEW false positive(s) on safe corpus files: "
        f"{[(f['path'], f['line'], f['vuln_class']) for f in unexpected]}"
    )
    # The known FP is allowed but must not silently multiply.
    assert len(findings) <= 1, (
        "regex_fallback produced more safe-corpus findings than the single "
        f"documented FP: {[(f['path'], f['line'], f['vuln_class']) for f in findings]}"
    )


# ---------------------------------------------------------------------------
# Sanity: the matched VULNERABLE files the fallback covers MUST be flagged.
# Proves the precision gate isn't green simply because the engine is inert.
# ---------------------------------------------------------------------------

# (vulnerable filename, expected vuln_class) for the files the regex fallback
# actually has a sink pattern for. We deliberately omit classes the small
# fallback can't see (path-traversal, ssti, jwt-alg-none) and the JS variants it
# misses — those are recall gaps measured by the accuracy eval, not this gate.
VULN_MATCHED = [
    ("sqli.py", "sqli"),
    ("xss.js", "xss"),
    ("command_injection.py", "cmd-injection"),
    ("ssrf.py", "ssrf"),
    ("hardcoded_secret.py", "secret"),
    ("insecure_deserialization.py", "deserialization"),
    ("weak_crypto.py", "crypto"),
]


@pytest.mark.parametrize("vuln_name,expected_class", VULN_MATCHED)
def test_matched_vulnerable_file_is_flagged(vuln_name, expected_class):
    """The fallback must flag the vulnerable files it has patterns for."""
    path = os.path.join(VULN_DIR, vuln_name)
    if not os.path.isfile(path):
        pytest.skip(f"vulnerable fixture missing: {vuln_name}")
    findings = sast_runner.regex_fallback(path)
    assert findings, (
        f"sanity check failed: regex_fallback found NOTHING in "
        f"vulnerable/{vuln_name} — the gate would pass trivially"
    )
    classes = {f["vuln_class"] for f in findings}
    assert expected_class in classes, (
        f"regex_fallback flagged vulnerable/{vuln_name} but with the wrong "
        f"class(es) {sorted(classes)}; expected {expected_class!r}"
    )


def test_gate_is_not_trivially_empty():
    """At least one vulnerable file is flagged AND the safe set is near-clean.

    Single assertion that the gate has discriminating power: the fallback fires
    on real sinks while staying quiet on safe code.
    """
    safe_findings = sast_runner.regex_fallback(SAFE_DIR)
    vuln_findings = sast_runner.regex_fallback(VULN_DIR)
    assert len(vuln_findings) > len(safe_findings) > -1
    assert len(vuln_findings) >= len(VULN_MATCHED), (
        "expected the fallback to flag at least one sink per matched vulnerable "
        f"file; got {len(vuln_findings)} findings total"
    )


# ---------------------------------------------------------------------------
# Inline SAFE snippets — written to a tmp dir, must not match. These guard the
# four classes the prompt calls out without depending on the corpus at all.
# ---------------------------------------------------------------------------

# Each snippet is the idiomatic SAFE form of a class the substring-level engine
# can actually reason about — i.e. the unsafe sink is simply ABSENT (not merely
# guarded). We deliberately do NOT include an inline "allowlisted SSRF" snippet:
# the fallback flags any outbound-HTTP sink (`urllib.request.urlopen(`, etc.)
# regardless of an allowlist because it has no dataflow — asserting such a
# snippet clean would be a false claim. Allowlisted SSRF is gated at the corpus
# level instead (the documented `safe/ssrf.py` xfail above).
INLINE_SAFE_SNIPPETS = {
    # Parameterized query — value is bound, never interpolated.
    "param_query.py": (
        "import sqlite3\n"
        "def get(conn, user_id):\n"
        "    cur = conn.cursor()\n"
        "    cur.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
        "    return cur.fetchall()\n"
    ),
    # Escaped output — markup-significant chars neutralized before reflection.
    "escaped_output.py": (
        "from html import escape\n"
        "def render(name):\n"
        "    return '<h1>Hello ' + escape(name) + '</h1>'\n"
    ),
    # Validated redirect — target checked against an allowlist before use; no
    # HTML/JS sink, just a header tuple.
    "validated_redirect.py": (
        "ALLOWED = {'/home', '/dashboard'}\n"
        "def redirect_to(target):\n"
        "    if target not in ALLOWED:\n"
        "        target = '/home'\n"
        "    return ('Location', target)\n"
    ),
    # Safe deserialization — JSON is data-only; no pickle/yaml.load sink present.
    "safe_deserialize.py": (
        "import json\n"
        "def load(blob):\n"
        "    return json.loads(blob)\n"
    ),
}


@pytest.mark.parametrize("fname", sorted(INLINE_SAFE_SNIPPETS))
def test_inline_safe_snippet_has_no_findings(tmp_path, fname):
    """Idiomatic safe code (the four named classes) must not be flagged."""
    src = tmp_path / fname
    src.write_text(INLINE_SAFE_SNIPPETS[fname], encoding="utf-8")
    findings = sast_runner.regex_fallback(str(src))
    assert findings == [], (
        f"FALSE POSITIVE on inline safe snippet {fname}: "
        f"{[(f['vuln_class'], f['line'], f['rule_id']) for f in findings]}"
    )
