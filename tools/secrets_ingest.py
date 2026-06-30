#!/usr/bin/env python3
"""
secrets_ingest.py — Bridge secrets_hunter.sh output into the findings DB.

`tools/secrets_hunter.sh` runs trufflehog / gitleaks / a regex fallback and
drops loose files (trufflehog.jsonl, gitleaks.json, regex_hits.txt) in a
scan-output dir. Today nothing reads those back, so leaked credentials never
reach the dashboard, dedup, or retest pipeline. This module parses that output
and normalizes every hit into `database.add_finding(...)` so secrets become
first-class findings like everything else.

Normalization (per hit):
  title       = "Leaked secret: <detector>"
  severity    = "high" if the scanner verified the credential live, else "medium"
  bug_class   = "secret"
  endpoint    = the file path or URL the secret was found in
  description  = human-readable context (detector, location, verified flag)
  poc         = the (already-redacted-where-possible) matched string; the DB's
                `_scrub` hook redacts it again defensively, so RAW secrets are
                never persisted — we lean on database redaction by design.
  source      = "secrets-hunter"

Dedup: identical (detector, file, line) hits are collapsed to one finding both
within a single ingest run and (best-effort) against findings already in the DB.

Importable API:
  parse_trufflehog(path) -> list[dict]
  parse_gitleaks(path)   -> list[dict]
  ingest(results_dir, target) -> int        # number of findings written

CLI:
  python3 tools/secrets_ingest.py --results-dir <dir> --target <t> [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# ─── Repo path bootstrap so `dashboard.database` imports cleanly ───────────────
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# ─── Defensive DB import ───────────────────────────────────────────────────────
# The database layer is the canonical home for findings + redaction. Import is
# best-effort: if it can't be loaded (missing deps, partial checkout) we degrade
# to parse-only mode rather than blowing up, so the parsers stay usable.
database = None  # type: ignore[assignment]
try:  # pragma: no cover - exercised indirectly
    from dashboard import database as _database  # type: ignore

    database = _database
except Exception:  # noqa: BLE001 - never let a DB import failure break parsing
    try:
        import importlib.util as _ilu

        _db_path = Path(_REPO) / "dashboard" / "database.py"
        if _db_path.is_file():
            _spec = _ilu.spec_from_file_location("_ubh_database", str(_db_path))
            if _spec and _spec.loader:
                _mod = _ilu.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                database = _mod
    except Exception:  # noqa: BLE001
        database = None


# Output filenames written by secrets_hunter.sh.
TRUFFLEHOG_FILE = "trufflehog.jsonl"
GITLEAKS_FILE = "gitleaks.json"
REGEX_FILE = "regex_hits.txt"


# ─── Helpers ───────────────────────────────────────────────────────────────────
def _redacted(value):
    """Best-effort redaction of a candidate secret string.

    The DB's add_finding scrubs free-text fields again, so this is belt-and-
    suspenders: even if we end up in parse-only mode the parser output never
    surfaces a raw credential. Falls back to identity if no redactor is wired.
    """
    if not isinstance(value, str) or not value:
        return value
    if database is not None:
        scrub = getattr(database, "_scrub", None)
        if callable(scrub):
            try:
                return scrub(value)
            except Exception:  # noqa: BLE001
                return value
    return value


def _norm(detector, file, line, verified, match, url=None):
    """Build one normalized finding dict from raw scanner fields."""
    detector = (detector or "secret").strip() or "secret"
    file = (file or url or "").strip()
    try:
        line = int(line) if line not in (None, "") else None
    except (TypeError, ValueError):
        line = None
    endpoint = url or file or None
    loc = endpoint or "<unknown location>"
    if line is not None:
        loc = f"{loc}:{line}"
    verified = bool(verified)
    description = (
        f"Leaked credential detected by '{detector}' at {loc}. "
        f"Live-verified: {'yes' if verified else 'no'}."
    )
    return {
        "detector": detector,
        "file": file or None,
        "line": line,
        "verified": verified,
        # redact at parse time too; never carry a raw secret around.
        "match": _redacted(match),
        "endpoint": endpoint,
        "description": description,
    }


def _dedup_key(hit):
    """Identity used for dedup: (detector, file, line)."""
    return (hit.get("detector"), hit.get("file"), hit.get("line"))


# ─── Parsers ───────────────────────────────────────────────────────────────────
def parse_trufflehog(path):
    """Parse trufflehog v3 `--json` output (one JSON object per line, JSONL).

    Relevant fields per object:
      DetectorName       e.g. "AWS", "Slack"
      Verified           bool — true if validated against the issuer API
      Raw / Redacted     the matched secret (we prefer the redacted form)
      SourceMetadata.Data.{Filesystem,Git,Github,...}.{file,link,...}
                         where the secret lives (file path or URL) + line

    Returns a list of normalized hit dicts. Malformed lines are skipped.
    """
    hits = []
    p = Path(path)
    if not p.is_file():
        return hits
    try:
        text = p.read_text(errors="replace")
    except OSError:
        return hits

    for raw_line in text.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            obj = json.loads(raw_line)
        except (TypeError, ValueError):
            continue  # not JSON — skip, stay resilient
        if not isinstance(obj, dict):
            continue

        detector = obj.get("DetectorName") or obj.get("DetectorType") or "trufflehog"
        verified = obj.get("Verified", False)
        # Prefer the scanner-redacted form, fall back to Raw (which _norm redacts).
        match = obj.get("Redacted") or obj.get("Raw") or obj.get("RawV2") or ""

        file, line, url = _trufflehog_location(obj)
        hits.append(_norm(detector, file, line, verified, match, url=url))
    return hits


def _trufflehog_location(obj):
    """Extract (file, line, url) from a trufflehog SourceMetadata block.

    The shape varies by source (Filesystem / Git / Github / Gitlab / ...), so we
    walk whatever sub-object is present and read common key names.
    """
    file = None
    line = None
    url = None
    meta = obj.get("SourceMetadata")
    if isinstance(meta, dict):
        data = meta.get("Data")
        if isinstance(data, dict):
            for _src_name, src in data.items():
                if not isinstance(src, dict):
                    continue
                file = file or src.get("file") or src.get("File") or src.get("path")
                url = url or src.get("link") or src.get("Link") or src.get("uri")
                if line is None:
                    line = src.get("line") or src.get("Line")
                # Some Git sources nest commit info but still expose `file`.
    # Top-level fallbacks occasionally seen in older formats.
    file = file or obj.get("file") or obj.get("File")
    url = url or obj.get("link")
    return file, line, url


def parse_gitleaks(path):
    """Parse gitleaks `--report-format json` output (a JSON array of findings).

    Relevant fields per finding:
      RuleID / Description   the detector / rule that fired
      File                   path the secret was found in
      StartLine / Line       line number
      Secret / Match         the matched text (gitleaks may already --redact it)
      (gitleaks has no live-verify, so `verified` is always False here)

    Returns a list of normalized hit dicts. Malformed input yields [].
    """
    hits = []
    p = Path(path)
    if not p.is_file():
        return hits
    try:
        raw = p.read_text(errors="replace").strip()
    except OSError:
        return hits
    if not raw:
        return hits
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return hits
    if isinstance(data, dict):
        # Some wrappers nest the array; otherwise treat a lone object as one hit.
        data = data.get("findings") or data.get("leaks") or [data]
    if not isinstance(data, list):
        return hits

    for obj in data:
        if not isinstance(obj, dict):
            continue
        detector = (
            obj.get("RuleID")
            or obj.get("Rule")
            or obj.get("Description")
            or "gitleaks"
        )
        file = obj.get("File") or obj.get("file") or obj.get("path")
        line = obj.get("StartLine", obj.get("Line", obj.get("line")))
        match = obj.get("Secret") or obj.get("Match") or obj.get("match") or ""
        # gitleaks does not validate keys against the issuer → never "verified".
        hits.append(_norm(detector, file, line, False, match))
    return hits


def _resolve_target_id(target):
    """Resolve a target string to a DB target_id, creating the target if needed.

    Mirrors the add_target + get_targets pattern other importers use. The
    `target` is normalized to a bare domain/host the same way (strip scheme +
    path). Returns an int id, or None if the DB is unavailable.
    """
    if database is None or not target:
        return None
    domain = (
        str(target)
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .strip()
    )
    if not domain:
        domain = str(target)
    try:
        database.add_target(domain)
        for t in database.get_targets():
            if t.get("domain") == domain:
                return t.get("id")
        targets = database.get_targets()
        return targets[0]["id"] if targets else None
    except Exception:  # noqa: BLE001
        return None


def _existing_db_keys(target_id):
    """Best-effort set of (detector, file, line) already in the DB for dedup.

    The dedup key is stashed in the structured `poc_spec` column under
    "secret_key" at ingest time. We read it back from there because poc_spec is
    intentionally NOT scrubbed by the DB, whereas the title/endpoint/poc free-
    text fields ARE redacted (e.g. the detector "Slack" in the title becomes
    "[REDACTED:...]"), which would otherwise corrupt the reconstructed key.
    Failures return an empty set so a read hiccup never blocks ingestion.
    """
    keys = set()
    if database is None or target_id is None:
        return keys
    try:
        rows, _total = database.get_findings(
            target_id=target_id, bug_class="secret", limit=100000
        )
    except Exception:  # noqa: BLE001
        return keys
    for row in rows or []:
        raw = row.get("poc_spec")
        if not raw:
            continue
        try:
            spec = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if not isinstance(spec, dict):
            continue
        k = spec.get("secret_key")
        if isinstance(k, list):
            detector, file, line = (k + [None, None, None])[:3]
            keys.add((detector, file, line))
    return keys


# ─── Ingest ────────────────────────────────────────────────────────────────────
def ingest(results_dir, target):
    """Parse a secrets_hunter.sh output dir and write findings to the DB.

    Reads trufflehog.jsonl + gitleaks.json from `results_dir`, normalizes every
    hit, dedups on (detector, file, line) within the batch AND against findings
    already stored for the target, then calls add_finding(...) for each new hit.

    Returns the number of findings actually written (int).
    """
    results_dir = Path(results_dir)
    hits = []
    hits.extend(parse_trufflehog(results_dir / TRUFFLEHOG_FILE))
    hits.extend(parse_gitleaks(results_dir / GITLEAKS_FILE))

    if database is None:
        # Parse-only mode: nothing to write to.
        return 0

    target_id = _resolve_target_id(target)
    if target_id is None:
        return 0

    seen = _existing_db_keys(target_id)
    written = 0
    for hit in hits:
        key = _dedup_key(hit)
        if key in seen:
            continue  # duplicate (this batch or already in DB)
        seen.add(key)
        severity = "high" if hit.get("verified") else "medium"
        try:
            database.add_finding(
                target_id,
                title=f"Leaked secret: {hit.get('detector') or 'secret'}",
                severity=severity,
                bug_class="secret",
                endpoint=hit.get("endpoint"),
                description=hit.get("description"),
                poc=hit.get("match"),  # _scrub redacts again; no raw secret stored
                source="secrets-hunter",
                # Stash the dedup identity in the (unscrubbed) structured column
                # so re-runs can recognise an already-ingested hit even though
                # the title/endpoint free-text gets redacted on write.
                poc_spec={"secret_key": list(key)},
            )
            written += 1
        except Exception:  # noqa: BLE001 - one bad row shouldn't sink the batch
            continue
    return written


# ─── CLI ───────────────────────────────────────────────────────────────────────
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Ingest secrets_hunter.sh output into the findings DB."
    )
    parser.add_argument(
        "--results-dir",
        required=True,
        help="Scan-output dir produced by secrets_hunter.sh "
        "(contains trufflehog.jsonl / gitleaks.json).",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target the secrets belong to (domain or URL; created if new).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON result summary instead of a human line.",
    )
    args = parser.parse_args(argv)

    count = ingest(args.results_dir, args.target)

    if args.json:
        print(
            json.dumps(
                {
                    "results_dir": str(args.results_dir),
                    "target": args.target,
                    "findings_ingested": count,
                    "db_available": database is not None,
                }
            )
        )
    else:
        if database is None:
            print(
                f"[!] database unavailable — parsed only, 0 findings written "
                f"from {args.results_dir}"
            )
        else:
            print(f"[+] Ingested {count} secret finding(s) for {args.target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
