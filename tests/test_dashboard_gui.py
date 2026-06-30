"""
test_dashboard_gui.py — end-to-end GUI route tests for dashboard/app.py.

Exercises the Flask dashboard through Flask's built-in test_client against a
real (but throwaway) SQLite database seeded with one target, one finding, and
one report. No network / semgrep / playwright / external binaries are touched —
every route under test is pure read/render or a deterministic transform.

Design notes:
  * The DB layer (dashboard/database.py) keeps DB_DIR / DB_PATH as MODULE
    GLOBALS that get_db() reads at call time. We repoint both at a per-test temp
    file via monkeypatch, then init_db() + seed. Because every query goes through
    get_db(), repointing the globals is sufficient — no app config knob needed.
  * Auth + DB path are resolved inside create_app() / at query time, so each
    test builds its own app AFTER the environment is arranged (temp DB patched,
    auth env set/cleared). We therefore call create_app() lazily per test rather
    than importing the module-level `app` singleton.
  * Skips (with a reason) if Flask isn't importable, per the harness contract.

Run: /tmp/ubh-venv/bin/python -m pytest tests/test_dashboard_gui.py -v
"""
import base64
import importlib.util
import os
import sys
import types

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _load_dashboard_package():
    """Import the dashboard PACKAGE and its app/database submodules robustly.

    Import-path hazard: conftest.py prepends both repo-root AND tools/ to
    sys.path, and tools/ contains a REGULAR module tools/dashboard.py. A regular
    module shadows a same-named namespace package during the path scan, so a bare
    `from dashboard import app` can bind `dashboard` to tools/dashboard.py and
    fail. We mustn't strip tools/ from sys.path globally — sibling tests import
    modules straight out of tools/. So instead we load dashboard/ + its submodules
    by explicit file path and register them in sys.modules, leaving sys.path (and
    therefore every other test's imports) untouched.

    Returns (app_module, database_module).
    """
    pkg_dir = os.path.join(REPO_ROOT, "dashboard")

    # Register the dashboard package as a namespace package pointing at dashboard/
    # — but only if a correct one isn't already loaded. If conftest's import order
    # cached the wrong module (the tools/ file), replace it.
    existing = sys.modules.get("dashboard")
    correct = existing is not None and pkg_dir in list(getattr(existing, "__path__", []))
    if not correct:
        pkg = types.ModuleType("dashboard")
        pkg.__path__ = [pkg_dir]  # makes it a package so submodule imports resolve
        sys.modules["dashboard"] = pkg

    def _load_submodule(name):
        full = f"dashboard.{name}"
        spec = importlib.util.spec_from_file_location(full, os.path.join(pkg_dir, f"{name}.py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[full] = module  # register BEFORE exec so intra-pkg imports find it
        spec.loader.exec_module(module)
        return module

    # database first: app.py does `from dashboard.database import ...` at import time.
    database_module = _load_submodule("database")
    app_module = _load_submodule("app")
    return app_module, database_module

# Flask is an optional dep (declared in requirements.txt, not always in the base
# interpreter). Skip the whole module — with a reason — if it can't be imported,
# rather than erroring at collection time.
flask = pytest.importorskip("flask", reason="Flask not installed; GUI tests skipped")

# Loaded after the Flask skip-guard so a Flask-less environment skips cleanly
# rather than erroring inside app.py's `from flask import ...`.
dashboard_app, db = _load_dashboard_package()


# ─── Seed values (referenced by assertions below) ────────────────────────────

TARGET_DOMAIN = "example.com"
FINDING_TITLE = "Reflected XSS in search box"
FINDING_BUG_CLASS = "xss"
FINDING_ENDPOINT = "/search?q=FUZZ"
REPORT_TITLE = "Q3 Security Report"
REPORT_CONTENT = "# Findings\n\nA reflected XSS was confirmed on the search endpoint."


@pytest.fixture
def seeded_db(tmp_path, monkeypatch):
    """Point the DB layer at a fresh temp file, init schema, seed minimal data.

    Yields a dict of the seeded primary keys so tests can build URLs and assert
    on identity. The DB layer caches nothing across calls, so repointing the two
    path globals is enough to fully isolate this test's data.
    """
    db_file = tmp_path / "bughunter.db"
    monkeypatch.setattr(db, "DB_DIR", tmp_path)
    monkeypatch.setattr(db, "DB_PATH", db_file)

    db.init_db()

    db.add_target(TARGET_DOMAIN, program="Example BBP", platform="hackerone")
    targets = db.get_targets()
    assert targets, "target seed failed"
    target_id = targets[0]["id"]

    finding_id = db.add_finding(
        target_id,
        FINDING_TITLE,
        "high",
        FINDING_BUG_CLASS,
        endpoint=FINDING_ENDPOINT,
        description="User input reflected without encoding.",
        poc="GET /search?q=<script>alert(1)</script>",
        impact="Session theft.",
        cvss_score=6.1,
    )

    report_id = db.add_report(
        target_id,
        REPORT_TITLE,
        REPORT_CONTENT,
        summary="One high-severity XSS.",
        finding_count=1,
    )

    return {"target_id": target_id, "finding_id": finding_id, "report_id": report_id}


def _make_client(config=None):
    """Build a fresh app via the factory and return a test client.

    Built lazily (per call) so env-driven config — Basic auth — is read at the
    right moment in each test.
    """
    application = dashboard_app.create_app(config)
    application.config["TESTING"] = True
    return application.test_client()


@pytest.fixture
def client(seeded_db):
    """Default test client: no auth env, temp DB already seeded."""
    return _make_client()


# ─── /findings (HTML) ─────────────────────────────────────────────────────────

def test_findings_page_ok_and_shows_finding(client):
    resp = client.get("/findings")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert FINDING_TITLE in body


# ─── /findings.csv ─────────────────────────────────────────────────────────────

def test_findings_csv_content_type_and_finding(client):
    resp = client.get("/findings.csv")
    assert resp.status_code == 200
    # mimetype is text/csv (charset may be appended in the full Content-Type).
    assert resp.mimetype == "text/csv"
    assert "text/csv" in resp.headers.get("Content-Type", "")
    # Streamed as a downloadable attachment.
    assert "attachment" in resp.headers.get("Content-Disposition", "")
    assert "findings.csv" in resp.headers.get("Content-Disposition", "")

    body = resp.get_data(as_text=True)
    # Header row from EXPORT_COLUMNS + the seeded finding's data.
    assert "title" in body
    assert FINDING_TITLE in body
    assert FINDING_BUG_CLASS in body


# ─── /findings.md ──────────────────────────────────────────────────────────────

def test_findings_md_is_markdown_table(client):
    resp = client.get("/findings.md")
    assert resp.status_code == 200
    assert resp.mimetype == "text/markdown"

    body = resp.get_data(as_text=True)
    # A GitHub-flavored markdown table: header row + a separator row of dashes.
    assert "| title |" in body or "title |" in body
    assert "---" in body
    # Header and separator are pipe-delimited rows.
    lines = [ln for ln in body.splitlines() if ln.strip()]
    assert lines[0].startswith("|") and lines[0].endswith("|")
    assert set(lines[1].replace("|", "").replace(" ", "")) <= {"-"}
    # The seeded finding appears as a data row.
    assert FINDING_TITLE in body


# ─── /reports/<id> ─────────────────────────────────────────────────────────────

def test_report_detail_renders_content(client, seeded_db):
    rid = seeded_db["report_id"]
    resp = client.get(f"/reports/{rid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert REPORT_TITLE in body
    # Content is rendered (markdown shown verbatim in a <pre> by default format).
    assert "reflected XSS was confirmed" in body


def test_report_detail_404_when_missing(client):
    resp = client.get("/reports/999999")
    assert resp.status_code == 404


# ─── /charts ────────────────────────────────────────────────────────────────────

def test_charts_page_ok(client):
    resp = client.get("/charts")
    assert resp.status_code == 200


# ─── /api/trends ─────────────────────────────────────────────────────────────────

def test_api_trends_json_shape(client):
    resp = client.get("/api/trends")
    assert resp.status_code == 200
    assert resp.mimetype == "application/json"
    data = resp.get_json()
    assert isinstance(data, dict)
    # Exactly the two documented series.
    assert "findings_over_time" in data
    assert "top_classes" in data
    assert isinstance(data["findings_over_time"], list)
    assert isinstance(data["top_classes"], list)
    # The seeded finding's class shows up in the top-classes aggregation.
    assert any(row.get("bug_class") == FINDING_BUG_CLASS for row in data["top_classes"])


# ─── finding_detail page: retest button + status select ──────────────────────────

def test_finding_detail_has_retest_and_status_controls(client, seeded_db):
    fid = seeded_db["finding_id"]
    resp = client.get(f"/findings/{fid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert FINDING_TITLE in body
    # The retest form posts to /findings/<id>/retest and carries a Retest button.
    assert f"/findings/{fid}/retest" in body
    assert "Retest" in body
    # The editable status control: a <select name="status"> with the enum values.
    assert 'name="status"' in body
    assert 'id="status-select"' in body
    for status_value in ("open", "verified", "false_positive", "fixed", "accepted"):
        assert f'value="{status_value}"' in body


# ─── CSRF protection on state-changing POSTs ─────────────────────────────────────

def test_finding_detail_embeds_csrf_token(client, seeded_db):
    """The status + retest forms must render a CSRF hidden field."""
    body = client.get(f"/findings/{seeded_db['finding_id']}").get_data(as_text=True)
    assert 'name="csrf_token"' in body


def test_post_without_csrf_token_is_rejected(client, seeded_db):
    """A state-changing POST with no CSRF token is rejected with 400."""
    resp = client.post(
        f"/findings/{seeded_db['finding_id']}/status", data={"status": "fixed"}
    )
    assert resp.status_code == 400


def test_post_with_valid_csrf_token_is_accepted(client, seeded_db):
    """A POST carrying the session's CSRF token passes the guard (not 400)."""
    with client.session_transaction() as s:
        s["_csrf_token"] = "tok-valid"
    resp = client.post(
        f"/findings/{seeded_db['finding_id']}/status",
        data={"status": "fixed", "csrf_token": "tok-valid"},
    )
    assert resp.status_code != 400
    assert resp.status_code in (200, 302, 303)


def test_post_with_wrong_csrf_token_is_rejected(client, seeded_db):
    """A mismatched CSRF token is rejected with 400 (constant-time compare)."""
    with client.session_transaction() as s:
        s["_csrf_token"] = "the-right-token"
    resp = client.post(
        f"/findings/{seeded_db['finding_id']}/status",
        data={"status": "fixed", "csrf_token": "a-wrong-token"},
    )
    assert resp.status_code == 400


# ─── Basic auth: opt-in via env; open by default ────────────────────────────────

def test_default_no_auth_is_open(client):
    """No DASHBOARD_AUTH_* env -> dashboard is open (localhost default)."""
    resp = client.get("/findings")
    assert resp.status_code == 200


def test_auth_env_challenges_unauthenticated(seeded_db, monkeypatch):
    """With both auth env vars set, an unauthenticated request is challenged."""
    monkeypatch.setenv("DASHBOARD_AUTH_USER", "admin")
    monkeypatch.setenv("DASHBOARD_AUTH_PASS", "s3cret")
    # create_app() reads os.environ at build time, so build AFTER setting env.
    client = _make_client()

    resp = client.get("/findings")
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers
    assert "Basic" in resp.headers["WWW-Authenticate"]


def test_auth_env_allows_correct_credentials(seeded_db, monkeypatch):
    """Sanity check the other side of the gate: valid creds pass through."""
    monkeypatch.setenv("DASHBOARD_AUTH_USER", "admin")
    monkeypatch.setenv("DASHBOARD_AUTH_PASS", "s3cret")
    client = _make_client()

    token = base64.b64encode(b"admin:s3cret").decode("ascii")
    resp = client.get("/findings", headers={"Authorization": f"Basic {token}"})
    assert resp.status_code == 200
    assert FINDING_TITLE in resp.get_data(as_text=True)
