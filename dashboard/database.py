"""
database.py — SQLite database for Unified Bug Hunter.

Stores targets, findings, recon data, reports, knowledge base, and monitoring logs.
All results are saved in a searchable format for future reference.
"""
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

DB_DIR = Path(__file__).resolve().parent / "data"
DB_PATH = DB_DIR / "bughunter.db"


# ─── Defensive redaction hook ────────────────────────────────────────────────
# Scrub PII / secrets from inbound text fields before they are persisted. The
# redactor lives in tools/redact.py. Import is best-effort: if the module is
# missing or fails to load, _redact_text falls back to an identity function so
# the database layer keeps working unchanged.
_redact_text = None  # type: ignore[assignment]
try:  # pragma: no cover - exercised indirectly
    import importlib.util as _ilu

    _redact_path = Path(__file__).resolve().parent.parent / "tools" / "redact.py"
    if _redact_path.is_file():
        _spec = _ilu.spec_from_file_location("_ubh_redact", str(_redact_path))
        if _spec and _spec.loader:
            _mod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            _candidate = getattr(_mod, "redact_text", None)
            if callable(_candidate):
                _redact_text = _candidate
except Exception:  # noqa: BLE001 - never let redaction break the DB
    _redact_text = None


def _scrub(value):
    """Redact a single text field. Non-str / None / failures pass through."""
    if _redact_text is None or not isinstance(value, str) or not value:
        return value
    try:
        return _redact_text(value)
    except Exception:  # noqa: BLE001 - redaction must never break a write
        return value


def get_db():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL UNIQUE,
        program TEXT,
        platform TEXT,
        scope_notes TEXT,
        status TEXT DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER REFERENCES targets(id),
        title TEXT NOT NULL,
        severity TEXT CHECK(severity IN ('critical','high','medium','low','info')),
        bug_class TEXT,
        endpoint TEXT,
        description TEXT,
        poc TEXT,
        impact TEXT,
        remediation TEXT,
        cvss_score REAL,
        cvss_vector TEXT,
        confidence INTEGER DEFAULT 100,
        status TEXT DEFAULT 'open' CHECK(status IN ('open','verified','false_positive','fixed','accepted')),
        source TEXT DEFAULT 'manual',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS recon_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER REFERENCES targets(id),
        type TEXT CHECK(type IN ('subdomain','url','endpoint','js_file','parameter','port','technology','screenshot')),
        value TEXT NOT NULL,
        source TEXT,
        metadata TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER REFERENCES targets(id),
        title TEXT NOT NULL,
        format TEXT DEFAULT 'markdown',
        content TEXT,
        summary TEXT,
        finding_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS knowledge_base (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        bug_class TEXT,
        severity TEXT,
        source TEXT,
        url TEXT,
        content TEXT,
        payloads TEXT,
        techniques TEXT,
        tags TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS monitoring_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER REFERENCES targets(id),
        check_type TEXT CHECK(check_type IN ('subdomain','js_change','port','certificate','tech_change')),
        status TEXT CHECK(status IN ('changed','unchanged','new','error')),
        detail TEXT,
        checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER REFERENCES targets(id),
        scan_type TEXT,
        tool TEXT,
        duration_seconds INTEGER,
        finding_count INTEGER,
        status TEXT DEFAULT 'completed',
        log TEXT,
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_findings_class ON findings(bug_class);
    CREATE INDEX IF NOT EXISTS idx_recon_target ON recon_data(target_id);
    CREATE INDEX IF NOT EXISTS idx_recon_type ON recon_data(type);
    CREATE INDEX IF NOT EXISTS idx_kb_class ON knowledge_base(bug_class);
    CREATE INDEX IF NOT EXISTS idx_kb_tags ON knowledge_base(tags);
    """)

    # Additive, idempotent migration: store a replayable retest.py PoC-spec
    # (JSON) alongside the existing free-text 'poc' evidence column. SQLite has
    # no "ADD COLUMN IF NOT EXISTS", so re-runs raise OperationalError (column
    # already exists) which we swallow.
    try:
        conn.execute("ALTER TABLE findings ADD COLUMN poc_spec TEXT")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()


def add_target(domain, program=None, platform=None, scope_notes=None):
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO targets (domain, program, platform, scope_notes) VALUES (?, ?, ?, ?)",
        (domain, program, platform, scope_notes),
    )
    conn.commit()
    conn.close()


def get_targets(status=None):
    conn = get_db()
    if status:
        rows = conn.execute("SELECT * FROM targets WHERE status = ? ORDER BY updated_at DESC", (status,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM targets ORDER BY updated_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_target(target_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def add_finding(target_id, title, severity, bug_class, endpoint=None, description=None, poc=None, impact=None, remediation=None, cvss_score=None, cvss_vector=None, source="manual", poc_spec=None):
    # Scrub PII / secrets from free-text + evidence fields before storage.
    title = _scrub(title)
    endpoint = _scrub(endpoint)
    description = _scrub(description)
    poc = _scrub(poc)
    impact = _scrub(impact)
    remediation = _scrub(remediation)
    # poc_spec is a structured retest.py PoC-spec dict; persist as JSON. It is
    # machine-replayable config (not free-text), so it is not run through _scrub.
    poc_spec_json = json.dumps(poc_spec) if poc_spec is not None else None
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO findings (target_id, title, severity, bug_class, endpoint, description, poc, impact, remediation, cvss_score, cvss_vector, source, poc_spec) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (target_id, title, severity, bug_class, endpoint, description, poc, impact, remediation, cvss_score, cvss_vector, source, poc_spec_json),
    )
    finding_id = cur.lastrowid
    conn.commit()
    conn.close()
    return finding_id


def get_findings(target_id=None, severity=None, bug_class=None, status=None, search=None, limit=100, offset=0):
    conn = get_db()
    # Build the WHERE clause + params ONCE so the row query and the COUNT(*)
    # query stay in lockstep. Previously `total` was hard-zeroed whenever any
    # filter was active (and the search-only count used a mismatched 3-column
    # WHERE), so the reported total was wrong under every filter — fixed here by
    # counting with the exact same predicate as the rows.
    where = " WHERE 1=1"
    where_params = []
    if target_id:
        where += " AND f.target_id = ?"
        where_params.append(target_id)
    if severity:
        where += " AND f.severity = ?"
        where_params.append(severity)
    if bug_class:
        where += " AND f.bug_class = ?"
        where_params.append(bug_class)
    if status:
        where += " AND f.status = ?"
        where_params.append(status)
    if search:
        where += " AND (f.title LIKE ? OR f.description LIKE ? OR f.endpoint LIKE ? OR f.poc LIKE ?)"
        where_params.extend([f"%{search}%"] * 4)

    query = (
        "SELECT f.*, t.domain FROM findings f JOIN targets t ON f.target_id = t.id"
        + where
        + " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.created_at DESC LIMIT ? OFFSET ?"
    )
    rows = conn.execute(query, where_params + [limit, offset]).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) FROM findings f JOIN targets t ON f.target_id = t.id" + where,
        where_params,
    ).fetchone()[0]
    conn.close()
    return [dict(r) for r in rows], total


def get_finding(finding_id):
    conn = get_db()
    row = conn.execute("SELECT f.*, t.domain FROM findings f JOIN targets t ON f.target_id = t.id WHERE f.id = ?", (finding_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# Allowed finding.status values — mirrors the CHECK(status IN (...)) enum on the
# findings table. Kept in sync here so set_finding_status can validate before
# issuing the UPDATE (a bad value would otherwise hit a sqlite IntegrityError).
FINDING_STATUSES = ("open", "verified", "false_positive", "fixed", "accepted")


def set_finding_status(finding_id, status):
    """Update a finding's status (the missing UPDATE for retest verdicts).

    Validates `status` against the findings.status CHECK enum and bumps
    updated_at when that column exists. Returns True if a row was updated,
    False if no finding matched the id.
    """
    if status not in FINDING_STATUSES:
        raise ValueError(
            f"invalid finding status {status!r}; expected one of {FINDING_STATUSES}"
        )
    conn = get_db()
    try:
        has_updated_at = any(
            col["name"] == "updated_at"
            for col in conn.execute("PRAGMA table_info(findings)").fetchall()
        )
        if has_updated_at:
            cur = conn.execute(
                "UPDATE findings SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status, finding_id),
            )
        else:
            cur = conn.execute(
                "UPDATE findings SET status = ? WHERE id = ?",
                (status, finding_id),
            )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_retest_specs(target_id=None, status=None, ids=None):
    """Return stored PoC-specs ready to feed retest.py's load_findings() shape.

    Selects findings that carry a non-null poc_spec, applies optional
    target_id / status / ids filters, JSON-decodes each poc_spec, injects the
    DB row id as spec['id'], and maps the DB status onto spec['previous_status']
    ('fixed' -> 'FIXED', anything else -> 'STILL-VULN'). Rows whose poc_spec is
    malformed JSON (or not a JSON object) are skipped so one bad row can't break
    a retest batch.
    """
    query = "SELECT id, target_id, status, poc_spec FROM findings WHERE poc_spec IS NOT NULL"
    params = []
    if target_id is not None:
        query += " AND target_id = ?"
        params.append(target_id)
    if status is not None:
        query += " AND status = ?"
        params.append(status)
    if ids:
        placeholders = ",".join("?" for _ in ids)
        query += f" AND id IN ({placeholders})"
        params.extend(ids)
    query += " ORDER BY id"

    conn = get_db()
    try:
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()

    specs = []
    for row in rows:
        raw = row["poc_spec"]
        try:
            spec = json.loads(raw)
        except (TypeError, ValueError):
            continue  # malformed JSON — skip, stay resilient
        if not isinstance(spec, dict):
            continue  # not a PoC-spec object — skip
        spec["id"] = row["id"]
        spec["previous_status"] = "FIXED" if row["status"] == "fixed" else "STILL-VULN"
        specs.append(spec)
    return specs


def add_recon_data(target_id, rtype, value, source=None, metadata=None):
    # Scrub PII / secrets from the recon value before storage / dedup lookup.
    value = _scrub(value)
    metadata_json = _scrub(json.dumps(metadata)) if metadata else None
    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM recon_data WHERE target_id = ? AND type = ? AND value = ?",
        (target_id, rtype, value),
    ).fetchone()
    if existing:
        conn.execute("UPDATE recon_data SET last_seen = CURRENT_TIMESTAMP, source = COALESCE(?, source) WHERE id = ?", (source, existing["id"]))
    else:
        conn.execute(
            "INSERT INTO recon_data (target_id, type, value, source, metadata) VALUES (?, ?, ?, ?, ?)",
            (target_id, rtype, value, source, metadata_json),
        )
    conn.commit()
    conn.close()


def get_recon_data(target_id=None, rtype=None, search=None, limit=100):
    conn = get_db()
    query = "SELECT r.*, t.domain FROM recon_data r JOIN targets t ON r.target_id = t.id WHERE 1=1"
    params = []
    if target_id:
        query += " AND r.target_id = ?"
        params.append(target_id)
    if rtype:
        query += " AND r.type = ?"
        params.append(rtype)
    if search:
        query += " AND (r.value LIKE ? OR r.metadata LIKE ?)"
        params.extend([f"%{search}%"] * 2)
    query += " ORDER BY r.last_seen DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_report(target_id, title, content, summary=None, finding_count=0):
    # Scrub PII / secrets from report text before storage.
    title = _scrub(title)
    content = _scrub(content)
    summary = _scrub(summary)
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO reports (target_id, title, content, summary, finding_count) VALUES (?, ?, ?, ?, ?)",
        (target_id, title, content, summary, finding_count),
    )
    report_id = cur.lastrowid
    conn.commit()
    conn.close()
    return report_id


def get_reports(target_id=None, limit=50):
    conn = get_db()
    if target_id:
        rows = conn.execute("SELECT r.*, t.domain FROM reports r JOIN targets t ON r.target_id = t.id WHERE r.target_id = ? ORDER BY r.created_at DESC LIMIT ?", (target_id, limit)).fetchall()
    else:
        rows = conn.execute("SELECT r.*, t.domain FROM reports r JOIN targets t ON r.target_id = t.id ORDER BY r.created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_to_knowledge_base(title, bug_class, severity=None, source=None, url=None, content=None, payloads=None, techniques=None, tags=None):
    conn = get_db()
    conn.execute(
        "INSERT INTO knowledge_base (title, bug_class, severity, source, url, content, payloads, techniques, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (title, bug_class, severity, source, url, content, json.dumps(payloads) if payloads else None, json.dumps(techniques) if techniques else None, tags),
    )
    conn.commit()
    conn.close()


def search_knowledge_base(search=None, bug_class=None, limit=50):
    conn = get_db()
    query = "SELECT * FROM knowledge_base WHERE 1=1"
    params = []
    if search:
        query += " AND (title LIKE ? OR content LIKE ? OR tags LIKE ? OR payloads LIKE ?)"
        params.extend([f"%{search}%"] * 4)
    if bug_class:
        query += " AND bug_class = ?"
        params.append(bug_class)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def log_monitoring(target_id, check_type, status, detail=None):
    conn = get_db()
    conn.execute(
        "INSERT INTO monitoring_log (target_id, check_type, status, detail) VALUES (?, ?, ?, ?)",
        (target_id, check_type, status, detail),
    )
    conn.commit()
    conn.close()


def get_monitoring_log(target_id=None, limit=50):
    conn = get_db()
    if target_id:
        rows = conn.execute("SELECT m.*, t.domain FROM monitoring_log m JOIN targets t ON m.target_id = t.id WHERE m.target_id = ? ORDER BY m.checked_at DESC LIMIT ?", (target_id, limit)).fetchall()
    else:
        rows = conn.execute("SELECT m.*, t.domain FROM monitoring_log m JOIN targets t ON m.target_id = t.id ORDER BY m.checked_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    conn = get_db()
    stats = {}
    stats["targets"] = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    stats["findings"] = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    stats["open_findings"] = conn.execute("SELECT COUNT(*) FROM findings WHERE status = 'open'").fetchone()[0]
    stats["critical"] = conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'critical'").fetchone()[0]
    stats["high"] = conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'high'").fetchone()[0]
    stats["medium"] = conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'medium'").fetchone()[0]
    stats["low"] = conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'low'").fetchone()[0]
    stats["recon_entries"] = conn.execute("SELECT COUNT(*) FROM recon_data").fetchone()[0]
    stats["reports"] = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    stats["kb_entries"] = conn.execute("SELECT COUNT(*) FROM knowledge_base").fetchone()[0]
    stats["monitoring_checks"] = conn.execute("SELECT COUNT(*) FROM monitoring_log").fetchone()[0]
    stats["subdomains"] = conn.execute("SELECT COUNT(*) FROM recon_data WHERE type = 'subdomain'").fetchone()[0]
    stats["urls"] = conn.execute("SELECT COUNT(*) FROM recon_data WHERE type = 'url'").fetchone()[0]

    # Findings per class
    class_rows = conn.execute("SELECT bug_class, COUNT(*) as cnt FROM findings GROUP BY bug_class ORDER BY cnt DESC LIMIT 10").fetchall()
    stats["top_classes"] = [dict(r) for r in class_rows]

    # Findings over time (last 30 days)
    time_rows = conn.execute("""
        SELECT DATE(created_at) as day, COUNT(*) as cnt
        FROM findings
        WHERE created_at >= DATE('now', '-30 days')
        GROUP BY DATE(created_at)
        ORDER BY day
    """).fetchall()
    stats["findings_over_time"] = [dict(r) for r in time_rows]

    conn.close()
    return stats
