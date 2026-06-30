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
`127.0.0.1:5000` (localhost only). All views read from the shared SQLite
database, so any findings/recon already imported by other commands show up
automatically.

> Note: `tools/dashboard.py` is a separate live **TUI** used by `/recon` and
> `/hunt` to render in-terminal phase progress — it is not the web GUI. For the
> browser dashboard use `dashboard/app.py` as above.
