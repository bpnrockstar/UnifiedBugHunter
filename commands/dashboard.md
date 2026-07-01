---
description: Launch the Unified Bug Hunter web GUI — a Flask dashboard for browsing targets, findings, recon data, reports, the knowledge base, and monitoring status from the shared SQLite database.
allowed-tools: Bash
---

# /dashboard

Start the local web dashboard (`dashboard/app.py`). It serves a Flask app backed
by the project's SQLite database so you can view targets, findings, recon data,
reports, and the knowledge base in a browser. Invoke the app directly — do NOT
re-implement the server.

## Usage

```
/dashboard
/dashboard --port 5050
```

## Run This

Launch the Flask dashboard:

```bash
python3 dashboard/app.py
```

Then open the dashboard in a browser:

```
http://127.0.0.1:5000
```

The server runs in the foreground until interrupted (Ctrl-C). It binds to
`127.0.0.1:5000` (localhost only) by default. All views read from the shared
SQLite database, so any findings/recon already imported by other commands show
up automatically.

### Using a different port

Port is configurable — CLI flag > env var > default (5000):

```bash
python3 dashboard/app.py --port 5050
# or
DASHBOARD_PORT=5050 python3 dashboard/app.py
# host is overridable too: --host / DASHBOARD_HOST
```

If the chosen port is already bound, the app now **fails loudly with a clear
error** instead of silently doing nothing — it never leaves you pointed at a
port with nothing listening.

> **macOS: seeing a bare `403 Forbidden` at `127.0.0.1:5000`?** That's almost
> always **not** this app — macOS's Control Center **AirPlay Receiver** listens
> on port 5000 by default and returns exactly that 403 to any plain HTTP
> request. Either disable it (System Settings → General → AirDrop & Handoff →
> AirPlay Receiver) or just launch on another port as above. The startup check
> now detects this exact collision and tells you so directly.

> Note: `tools/dashboard.py` is a separate live **TUI** used by `/recon` and
> `/hunt` to render in-terminal phase progress — it is not the web GUI. For the
> browser dashboard use `dashboard/app.py` as above.
