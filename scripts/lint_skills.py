#!/usr/bin/env python3
"""
lint_skills.py — quality + safety gate for unified-bug-hunter skills.

Enforces the rules documented in CONTRIBUTING.md and the repo's hard rule that
NO real client/engagement identifiers ever land in the public tree.

Checks per skills/<name>/SKILL.md:
  STRUCTURE (errors)
    - frontmatter block present (between the first two `---` lines)
    - frontmatter parses as valid YAML with NO duplicate top-level keys
    - `name` present, matches ^[a-z0-9-]+$, and equals the directory name
    - `description` present and <= 1024 chars
    - body (everything after frontmatter) <= 500 lines
    - LEAKED-KEY: the line(s) right after the closing `---` must not repeat a
      frontmatter key, and there must be no stray second `---` fence there
      (catches the duplicate-`description` leak bug class)
    - FENCE-BALANCE: code-fence lines (>=3 backticks) must be even (no unclosed
      fence). 4-backtick wrappers stay balanced, so house-style wrapping is fine.
  STRUCTURE (warnings)
    - file should end with a terminal newline
  SAFETY (errors)
    - client-identifier denylist: hashes every 1- and 2-word shingle of the file
      and compares against scripts/.identifier-denylist.sha256 (+ optional
      .identifier-denylist.local). Plaintext names never live in the repo.
    - real-secret scan: AWS keys, private-key blocks, JWTs, Slack/Google tokens.
      Documentation patterns (regexes, AWS EXAMPLE tokens) are allowlisted so the
      secret-catalog skills don't trip it.

Also lints commands/**/*.md and agents/**/*.md (structural checks only — these
files don't need a name<->dir match): frontmatter parses as YAML with no dup
keys, `description` present + single line, no leaked keys, fences balanced,
terminal newline. Files without a frontmatter block (e.g. README.md) are skipped.

Exit code 0 = clean, 1 = at least one error. Warnings never fail the build.
Stdlib only — no pip install needed in CI.

Usage:
    python3 scripts/lint_skills.py                 # lint all skills + commands + agents
    python3 scripts/lint_skills.py skills/hunt-xss  # lint specific skill dirs
"""
import hashlib
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO, "skills")
COMMANDS_DIR = os.path.join(REPO, "commands")
AGENTS_DIR = os.path.join(REPO, "agents")
SCRIPTS_DIR = os.path.join(REPO, "scripts")

NAME_RE = re.compile(r"^[a-z0-9-]+$")
MAX_DESC = 1024
MAX_BODY_LINES = 500

# A code fence is a line that is only optional leading whitespace followed by
# three or more backticks (the rest of the line is the optional info string).
# 4-backtick wrappers used to nest 3-backtick blocks are still counted one line
# per fence, so a correctly-wrapped file stays even.
FENCE_RE = re.compile(r"^\s*`{3,}")
# A `key: value` (or bare `key:`) line at zero indent — used to detect a
# frontmatter key that leaked into the body just past the closing fence.
TOP_KEY_RE = re.compile(r"^([A-Za-z0-9_-]+):(?:\s.*)?$")

# --- real-secret patterns (kept tight to avoid flagging documented regexes) ---
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("GitHub PAT", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
]
# Tokens that are public documentation/examples, not real secrets.
# `\.\.\.` covers placeholder blocks like "-----BEGIN PRIVATE KEY-----..." in docs.
SECRET_ALLOW = re.compile(
    r"AKIAIOSFODNN7EXAMPLE|EXAMPLE|wJalrXUtnFEMI|\[0-9A-Z\]|\{1[06]\}|<[^>]+>|\.\.\."
)

# Intentional kitchen-sink router/aggregator skills whose descriptions deliberately
# exceed the per-skill limit (they route to everything). Over-length is a warning,
# not an error, for these. Do NOT add new skills here — write focused descriptions.
DESC_LIMIT_GRANDFATHERED = {"bug-bounty", "bb-local-toolkit", "osint-methodology"}

WORD_RE = re.compile(r"[a-z0-9]+")


def load_denylist():
    """Return a set of sha256 hex digests of banned identifiers."""
    hashes = set()
    sha_file = os.path.join(SCRIPTS_DIR, ".identifier-denylist.sha256")
    if os.path.exists(sha_file):
        with open(sha_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    hashes.add(line.lower())
    # Optional gitignored plaintext override for maintainer convenience.
    local = os.path.join(SCRIPTS_DIR, ".identifier-denylist.local")
    if os.path.exists(local):
        with open(local, encoding="utf-8") as fh:
            for line in fh:
                name = " ".join(line.strip().lower().split())
                if name and not name.startswith("#"):
                    hashes.add(hashlib.sha256(name.encode()).hexdigest())
    return hashes


def shingles(text):
    """Yield normalized 1- and 2-word shingles from text."""
    words = WORD_RE.findall(text.lower())
    for i, w in enumerate(words):
        yield w
        if i + 1 < len(words):
            yield w + " " + words[i + 1]


def split_frontmatter(raw):
    """Return (frontmatter_dict, body_lines, error_or_None).

    body_lines is the list of raw lines AFTER the closing `---` so callers can
    inspect what immediately follows the fence (leaked-key detection)."""
    if not raw.startswith("---"):
        return {}, raw.split("\n"), "no frontmatter block (file must start with '---')"
    parts = raw.split("\n")
    # find closing --- after line 0
    close = None
    for i in range(1, len(parts)):
        if parts[i].strip() == "---":
            close = i
            break
    if close is None:
        return {}, parts, "frontmatter opened with '---' but never closed"
    fm = {}
    for line in parts[1:close]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # Only capture TOP-LEVEL keys (no leading indent). Nested mapping values
        # (e.g. an agent's `tools:` block) are intentionally ignored here.
        if line[:1].isspace():
            continue
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m:
            fm[m.group(1)] = m.group(2).strip()
    body_lines = parts[close + 1:]
    return fm, body_lines, None


def frontmatter_yaml_errors(label, raw):
    """Validate the frontmatter BLOCK as YAML and reject DUPLICATE top-level keys.

    Stdlib-only: we scan the lines between the first two `---` fences. A YAML
    block-mapping cannot legally define the same key twice; strict loaders
    (and Claude/Codex) reject it. Lines that are indented (nested values) or
    blank/comment are ignored, so an agent's `tools:` sub-mapping is fine."""
    errs = []
    if not raw.startswith("---"):
        return errs
    parts = raw.split("\n")
    close = None
    for i in range(1, len(parts)):
        if parts[i].strip() == "---":
            close = i
            break
    if close is None:
        return errs  # unterminated fence reported elsewhere
    seen = set()
    for line in parts[1:close]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1].isspace():  # nested mapping / list item / continuation
            continue
        m = re.match(r"^([A-Za-z0-9_-]+):", line)
        if not m:
            continue
        key = m.group(1)
        if key in seen:
            errs.append(f"{label}: DUPLICATE frontmatter key `{key}` — "
                        f"a YAML mapping cannot define the same key twice")
        seen.add(key)
    return errs


def leaked_key_errors(label, fm, body_lines):
    """Catch a frontmatter key that leaked into the body just past the closing
    `---` (the find-* duplicate-`description` bug), and any stray second `---`
    fence sitting where the body should start.

    We inspect the first ~2 non-blank body lines. A `key: value` line at zero
    indent whose key matches a real frontmatter key (e.g. `description:`) is a
    leak. A bare `---` there means a second/duplicate fence was emitted."""
    errs = []
    checked = 0
    for line in body_lines:
        if not line.strip():
            continue
        checked += 1
        if line.strip() == "---":
            errs.append(f"{label}: stray '---' fence immediately after frontmatter "
                        f"(duplicate/leaked second frontmatter block)")
            break
        m = TOP_KEY_RE.match(line)
        if m and fm and m.group(1) in fm:
            errs.append(f"{label}: frontmatter key `{m.group(1)}` leaked into the body "
                        f"(first body line repeats a frontmatter key — duplicate-key leak)")
            break
        if checked >= 2:
            break
    return errs


def fence_balance_errors(label, raw):
    """A truncated or unclosed code fence leaves an ODD number of fence lines.
    Count every line that is optional whitespace + >=3 backticks; require even.
    House-style 4-backtick wrappers nest balanced 3-backtick blocks, so a
    correctly-wrapped file still totals even and passes."""
    n = sum(1 for line in raw.split("\n") if FENCE_RE.match(line))
    if n % 2 != 0:
        return [f"{label}: ODD number of code-fence lines ({n}) — "
                f"an unclosed/truncated ``` fence"]
    return []


def terminal_newline_warnings(label, raw):
    """Warn (never error) when a file doesn't end with a trailing newline."""
    if raw and not raw.endswith("\n"):
        return [f"{label}: file does not end with a newline"]
    return []


def yaml_safety_errors(name, raw):
    """Catch frontmatter a STRICT YAML parser (e.g. Codex) rejects but our lenient
    regex parser accepts — chiefly an unquoted value containing ': ' (colon-space),
    which YAML reads as a nested mapping. This is the hunt-ntlm-info bug class."""
    errs = []
    if not raw.startswith("---"):
        return errs
    lines = raw.split("\n")
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            break
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", lines[i])
        if not m or not m.group(2):
            continue
        val = m.group(2)
        quoted = len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'"
        if not quoted and ": " in val:
            errs.append(f"{name}: frontmatter `{m.group(1)}` is unquoted and contains ': ' — "
                        f"wrap the value in double quotes (strict YAML parsers like Codex reject it)")
    return errs


def lint_skill(skill_dir, denylist):
    errors, warnings = [], []
    name = os.path.basename(skill_dir.rstrip("/"))
    path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.isfile(path):
        return [f"{name}: missing SKILL.md"], []
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()

    fm, body_lines, fm_err = split_frontmatter(raw)
    if fm_err:
        errors.append(f"{name}: {fm_err}")
    errors += yaml_safety_errors(name, raw)
    errors += frontmatter_yaml_errors(name, raw)
    errors += leaked_key_errors(name, fm, body_lines)
    errors += fence_balance_errors(name, raw)
    warnings += terminal_newline_warnings(name, raw)
    # name
    fn = fm.get("name", "")
    if not fn:
        errors.append(f"{name}: frontmatter missing `name`")
    else:
        if not NAME_RE.match(fn):
            errors.append(f"{name}: `name` '{fn}' must match ^[a-z0-9-]+$")
        if fn != name:
            errors.append(f"{name}: `name` '{fn}' != directory '{name}'")
    # description
    desc = fm.get("description", "")
    if not desc:
        errors.append(f"{name}: frontmatter missing `description`")
    elif len(desc) > MAX_DESC:
        msg = (f"{name}: description {len(desc)} chars > {MAX_DESC} limit "
               f"(Codex rejects >1024; install.sh --agents auto-truncates the Codex copy)")
        (warnings if name in DESC_LIMIT_GRANDFATHERED else errors).append(msg)
    elif len(desc) < 40:
        warnings.append(f"{name}: description very short ({len(desc)} chars) — weak trigger surface")
    # body length
    n_body = len(body_lines)
    if n_body > MAX_BODY_LINES:
        warnings.append(f"{name}: body {n_body} lines > {MAX_BODY_LINES} guideline (use references/ subfolder)")

    # client-identifier denylist
    if denylist:
        hit = set()
        for sh in shingles(raw):
            if hashlib.sha256(sh.encode()).hexdigest() in denylist:
                hit.add(sh)
        if hit:
            errors.append(
                f"{name}: CLIENT-IDENTIFIER MATCH — {len(hit)} banned shingle(s). "
                f"Remove client/engagement identifiers before committing."
            )

    # real-secret scan
    for lineno, line in enumerate(raw.splitlines(), 1):
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(line):
                snippet = m.group(0)
                window = line[max(0, m.start() - 8): m.end() + 8]
                if SECRET_ALLOW.search(window) or SECRET_ALLOW.search(snippet):
                    continue
                errors.append(f"{name}:{lineno}: possible {label} leaked — '{snippet[:24]}...'")
    return errors, warnings


def lint_doc(path, denylist, kind):
    """Structural lint for a command/agent markdown file (kind = 'command'|'agent').

    These don't need a name<->dir match, so we apply only the structural and
    safety checks: frontmatter parses as YAML with no duplicate keys, a
    single-line `description` is present, no leaked keys past the fence, fences
    are balanced, terminal newline, plus the denylist + real-secret scan.

    Files that don't start with a frontmatter block (e.g. README.md) are skipped
    silently — they aren't command/agent definitions."""
    errors, warnings = [], []
    rel = os.path.relpath(path, REPO)
    label = f"{kind}:{os.path.basename(path)}"
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()

    # README and other prose files have no frontmatter — not a definition. Skip.
    if not raw.startswith("---"):
        return None

    fm, body_lines, fm_err = split_frontmatter(raw)
    if fm_err:
        errors.append(f"{label}: {fm_err}")
    # NOTE: yaml_safety_errors (the unquoted-`: `-colon check) is intentionally
    # NOT applied to commands/agents. Slash-command descriptions use prose like
    # "Usage: /recon target.com" as house style; Claude Code loads them fine.
    # We still require valid mapping structure (no duplicate keys) below.
    errors += frontmatter_yaml_errors(label, raw)
    errors += leaked_key_errors(label, fm, body_lines)
    errors += fence_balance_errors(label, raw)
    warnings += terminal_newline_warnings(label, raw)

    # description present + single line
    desc = fm.get("description", "")
    if not desc:
        errors.append(f"{label}: frontmatter missing `description`")
    else:
        if len(desc) > MAX_DESC:
            errors.append(f"{label}: description {len(desc)} chars > {MAX_DESC} limit")
        # split_frontmatter only keeps the first physical line of a value, so a
        # multi-line YAML scalar would leak its continuation into the body and
        # be caught by leaked_key/structure checks; flag a raw embedded newline.
        if "\n" in desc:
            errors.append(f"{label}: `description` must be a single line")

    # client-identifier denylist
    if denylist:
        hit = set()
        for sh in shingles(raw):
            if hashlib.sha256(sh.encode()).hexdigest() in denylist:
                hit.add(sh)
        if hit:
            errors.append(f"{label}: CLIENT-IDENTIFIER MATCH — {len(hit)} banned shingle(s). "
                          f"Remove client/engagement identifiers before committing.")

    # real-secret scan
    for lineno, line in enumerate(raw.splitlines(), 1):
        for slabel, pat in SECRET_PATTERNS:
            for m in pat.finditer(line):
                snippet = m.group(0)
                window = line[max(0, m.start() - 8): m.end() + 8]
                if SECRET_ALLOW.search(window) or SECRET_ALLOW.search(snippet):
                    continue
                errors.append(f"{rel}:{lineno}: possible {slabel} leaked — '{snippet[:24]}...'")
    return errors, warnings


def iter_markdown(root):
    """Yield every *.md path under root (recursively), sorted for stable output."""
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if f.endswith(".md"):
                out.append(os.path.join(dirpath, f))
    return sorted(out)


def main(argv):
    denylist = load_denylist()
    all_errors, all_warnings = [], []
    n_skills = n_docs = 0

    if argv:
        # Explicit targets: treat each as a skill directory (back-compat).
        targets = [a if os.path.isabs(a) else os.path.join(REPO, a) for a in argv]
        for t in targets:
            e, w = lint_skill(t, denylist)
            all_errors += e
            all_warnings += w
            n_skills += 1
    else:
        # Skills: one SKILL.md per top-level directory.
        skill_dirs = [os.path.join(SKILLS_DIR, d) for d in sorted(os.listdir(SKILLS_DIR))
                      if os.path.isdir(os.path.join(SKILLS_DIR, d))]
        for t in skill_dirs:
            e, w = lint_skill(t, denylist)
            all_errors += e
            all_warnings += w
            n_skills += 1
        # Commands + agents: every *.md that is a definition (has frontmatter).
        for root, kind in ((COMMANDS_DIR, "command"), (AGENTS_DIR, "agent")):
            if not os.path.isdir(root):
                continue
            for path in iter_markdown(root):
                res = lint_doc(path, denylist, kind)
                if res is None:
                    continue  # not a definition (e.g. README.md)
                e, w = res
                all_errors += e
                all_warnings += w
                n_docs += 1

    for w in all_warnings:
        print(f"::warning:: {w}" if os.environ.get("GITHUB_ACTIONS") else f"WARN  {w}")
    for e in all_errors:
        print(f"::error:: {e}" if os.environ.get("GITHUB_ACTIONS") else f"ERROR {e}")

    print(f"\nLinted {n_skills} skill(s) + {n_docs} command/agent doc(s): "
          f"{len(all_errors)} error(s), {len(all_warnings)} warning(s).")
    if not denylist:
        print("NOTE: no client-identifier denylist loaded (scripts/.identifier-denylist.sha256 missing).")
    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
