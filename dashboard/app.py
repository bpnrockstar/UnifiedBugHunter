"""
Unified Bug Hunter — Web Dashboard

Flask web app for viewing targets, findings, recon data, reports,
knowledge base, and monitoring status. All data is stored in a
searchable SQLite database.

Usage:
    python3 dashboard/app.py
    # Then open http://127.0.0.1:5000
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, jsonify, redirect, render_template, request, url_for

from dashboard.database import (
    add_finding,
    add_report,
    add_target,
    add_to_knowledge_base,
    get_finding,
    get_findings,
    get_monitoring_log,
    get_recon_data,
    get_reports,
    get_stats,
    get_target,
    get_targets,
    init_db,
    search_knowledge_base,
)

app = Flask(__name__)
app.config["TITLE"] = "Unified Bug Hunter"


@app.route("/")
def index():
    stats = get_stats()
    return render_template("index.html", stats=stats)


@app.route("/targets")
def targets():
    all_targets = get_targets()
    return render_template("targets.html", targets=all_targets)


@app.route("/targets/<int:target_id>")
def target_detail(target_id):
    target = get_target(target_id)
    if not target:
        return "Target not found", 404
    findings, _ = get_findings(target_id=target_id, limit=500)
    recon = get_recon_data(target_id=target_id, limit=500)
    reports = get_reports(target_id=target_id)
    return render_template("target_detail.html", target=target, findings=findings, recon=recon, reports=reports)


@app.route("/targets/add", methods=["POST"])
def add_target_route():
    domain = request.form.get("domain")
    program = request.form.get("program")
    platform = request.form.get("platform")
    if domain:
        add_target(domain, program, platform)
    return redirect(url_for("targets"))


@app.route("/findings")
def findings():
    severity = request.args.get("severity")
    bug_class = request.args.get("class")
    status = request.args.get("status")
    search = request.args.get("q")
    findings_list, total = get_findings(severity=severity, bug_class=bug_class, status=status, search=search, limit=200)
    return render_template("findings.html", findings=findings_list, total=total, severity=severity, bug_class=bug_class, status=status, search=search)


@app.route("/findings/<int:finding_id>")
def finding_detail(finding_id):
    finding = get_finding(finding_id)
    if not finding:
        return "Finding not found", 404
    return render_template("finding_detail.html", finding=finding)


@app.route("/recon")
def recon():
    rtype = request.args.get("type")
    search = request.args.get("q")
    data = get_recon_data(rtype=rtype, search=search, limit=500)
    return render_template("recon.html", recon_data=data, rtype=rtype, search=search)


@app.route("/reports")
def reports():
    all_reports = get_reports()
    return render_template("reports.html", reports=all_reports)


@app.route("/knowledge-base")
def knowledge_base():
    search = request.args.get("q")
    bug_class = request.args.get("class")
    entries = search_knowledge_base(search=search, bug_class=bug_class)
    return render_template("knowledge_base.html", entries=entries, search=search, bug_class=bug_class)


@app.route("/knowledge-base/add", methods=["POST"])
def add_kb_entry():
    title = request.form.get("title")
    bug_class = request.form.get("bug_class")
    source = request.form.get("source")
    content = request.form.get("content")
    if title:
        add_to_knowledge_base(title, bug_class, source=source, content=content)
    return redirect(url_for("knowledge_base"))


@app.route("/monitoring")
def monitoring():
    logs = get_monitoring_log(limit=200)
    return render_template("monitoring.html", logs=logs)


@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@app.route("/api/findings")
def api_findings():
    findings_list, total = get_findings(
        severity=request.args.get("severity"),
        bug_class=request.args.get("class"),
        search=request.args.get("q"),
        limit=int(request.args.get("limit", 100)),
    )
    return jsonify({"findings": findings_list, "total": total})


@app.route("/api/findings/<int:finding_id>")
def api_finding(finding_id):
    finding = get_finding(finding_id)
    return jsonify(finding) if finding else ("Not found", 404)


@app.route("/api/knowledge-base")
def api_kb():
    entries = search_knowledge_base(search=request.args.get("q"), bug_class=request.args.get("class"))
    return jsonify(entries)


@app.route("/api/recon")
def api_recon():
    data = get_recon_data(rtype=request.args.get("type"), search=request.args.get("q"))
    return jsonify(data)


if __name__ == "__main__":
    init_db()
    print(f"Dashboard: http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)
