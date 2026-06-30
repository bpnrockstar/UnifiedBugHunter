# Unified Bug Hunter

**A scope-safe, memory-backed bug-bounty and red-team operator for Claude Code.**

89 skills · 40 commands · 30 agents · 6 MCP servers · 372 tests

> **Warning**: For authorized security testing only. Always read and respect program scope.

UnifiedBugHunter turns a Claude Code session into a disciplined offensive operator. It *orchestrates* real tooling — subfinder, httpx, nuclei, dalfox, sqlmap, TREVORspray, Foundry, and ~50 others — and wraps it in distilled methodology, false-positive judgment, and deterministic scope safety. It does **not** replace those tools; it decides what to run, when, and where, then proves and reports findings the way an experienced hunter would. A deterministic scope checker, an append-only audit trail, and cross-target pattern learning keep every run safe and cumulatively smarter.

---

## Why it's different

- **Methodology distilled from real disclosed reports and current CVEs** — not generic checklists. Each `hunt-*` skill carries a `report_count` + `sources` and anchors to concrete advisories (Rocket.Chat CVE-2021-22911, Mongoose CVE-2024-53900, Django CVE-2024-42005, vCenter CVE-2021-21972 → 2024-37085).
- **False-positive discipline is built in** — a global 7-Question Gate, a 4-gate validator, and a never-submit list protect the submission-validity ratio that manual hunters most often torch.
- **Deterministic, fail-closed scope safety** — code (not the LLM) decides whether a host may be touched: anchored-suffix matching, exclusions before allowlist, IP/CIDR refused, empty/unparseable input rejected.
- **Cross-target pattern learning** — a technique that paid off on one React/Next.js target surfaces automatically on the next one via tech-stack overlap matching, so the operator gets better over time.
- **Autonomous autopilot with a hard human boundary** — a closed scope→recon→rank→hunt→validate→report loop with circuit breakers and rate limits that **never auto-submits** and stops before any live credential attack.
- **372-test CI** — a stdlib-only linter plus a 372-function pytest suite gate every change.

## What's inside

| Layer | What you get |
|-------|--------------|
| **89 skills** | 48 `hunt-*` per-vuln-class + framework skills (SQLi, IDOR, XSS, SSRF, SSTI, OAuth, SAML, GraphQL, Next.js, Spring Boot, …) and 41 platform/methodology skills (recon/OSINT, cloud & enterprise identity, AD, mobile, reporting, LLM red-team, Web3). `bb-methodology` is the master router. |
| **40 commands** | Recon, scope, hunting, validation/reporting, regression retest, the credential pipeline, cloud/takeover/params, Web3, LLM red-team, KEV coverage, monitoring, and memory/intel — thin routers that invoke an engine script or dispatch an agent. |
| **30 agents** | An 11-agent bug-bounty pipeline (recon → rank → hunt → chain → validate → report, plus regression-retest and triage-dedup) plus 19 offensive specialists (binary exploit, crypto, forensics, malware, AD, container escape, API, privesc, payload crafting, …). |
| **61 engine tools** | Deterministic Python/shell execution: `hunt.py` orchestrator, recon/scan engines, the scope checker, the credential pipeline, a PoC-replay regression engine, finding dedup, a multi-provider LLM router, and an arsenal registry of ~50 external tools. |
| **6 MCP servers** | 2 proxy bridges (Burp, Caido) + 4 read-only intel feeds (HackerOne, Bugcrowd, Intigriti, Immunefi); all degrade gracefully to curl + OOB if not connected. |

Full breakdown: see **[docs/OVERVIEW.md](docs/OVERVIEW.md)** and **[CLAUDE.md](CLAUDE.md)**.

## Install

```bash
chmod +x install.sh && ./install.sh
```

## Quickstart

```bash
/recon target.com     # full recon pipeline
/hunt target.com      # scripted scan + manual deep-dive per vuln class
/validate             # 7-Question Gate + 4 gates on the current finding
/report               # write a submission-ready report (never auto-submitted)
```

Or run the whole closed loop autonomously:

```bash
/autopilot target.com --paranoid   # default — stops on every finding/signal
#                      --normal     # stops after each validation batch
#                      --yolo       # runs until surface exhausted (still needs report + write-method approval)
#                      --quick      # ~40% fewer tokens
```

## Architecture

UnifiedBugHunter is an 8-layer stack — Knowledge → Interface → Actor → Engine → Integration → State → Safety → Quality — with a request flowing top-to-bottom through each single-responsibility layer. See **[docs/OVERVIEW.md](docs/OVERVIEW.md)** for the full design and Mermaid diagrams.

## Safety

- **Deterministic scope checker** — fail-closed, anchored-suffix matching, IP/CIDR refused; every outbound request is scope-checked in code, not by the model.
- **Append-only audit log** — every request is logged with a non-secret 12-char session hash; raw cookies and tokens are never written.
- **Never auto-submits** — reports always require explicit human approval before submission.
- **Credential attacks are gated** — wordlist generation, employee OSINT, and password spraying require `--with-credential-attack`, and the credential agent hard-stops before any live spray.

## Docs

- [docs/OVERVIEW.md](docs/OVERVIEW.md) — architecture overview + diagrams
- [docs/overview.html](docs/overview.html) — presentation deck
- [CLAUDE.md](CLAUDE.md) — full skill/command/agent/tool inventory
- [USAGE.md](USAGE.md) — usage guide
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide

## License

MIT — see [LICENSE](LICENSE).
