---
name: code-patch
description: "Automated vulnerability patch generation methodology. Given vulnerable source code, produces minimal, correct, framework-appropriate fixes with before/after diffs. Covers all OWASP Top 10 classes: SQLi, XSS, SSRF, command injection, deserialization, IDOR, auth bypass, crypto flaws, path traversal, and mass assignment. Language-agnostic with specific fix patterns for Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, C#, and Rust."
---

# Code Patch Methodology

## Overview

This methodology produces secure patches for vulnerable code found during white-box code review. Every fix must be:
1. **Minimal** — change only the vulnerable lines, nothing else
2. **Correct** — eliminates the vulnerability without breaking functionality
3. **Context-aware** — uses the same framework and coding style as the original
4. **Tested** — verify with curl commands or unit tests

## Fix Strategy by Bug Class

### SQL Injection
| Pattern | Vulnerable | Fixed |
|---------|-----------|-------|
| String concat | `"SELECT * FROM t WHERE id = " + uid` | Parameterized query with placeholder |
| f-string | `f"SELECT * FROM t WHERE name = '{name}'"` | `cursor.execute("SELECT * FROM t WHERE name = %s", (name,))` |
| ORM raw() | `User.objects.raw("SELECT * FROM t WHERE id = " + id)` | `User.objects.filter(id=id)` |
| Stored procedure | `EXEC sp_getUser @id=' + id` | `EXEC sp_getUser @id = @id PARAMETER` |

**Framework-specific:**
```python
# Django ORM — use filter(), get(), exclude()
User.objects.filter(username=user_input)  # SAFE — ORM parameterizes

# Flask/SQLAlchemy — use text() with params
db.session.execute(text("SELECT * FROM users WHERE id = :uid"), {"uid": uid})

# Raw DBAPI2 — always %s placeholders
cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
```

### Cross-Site Scripting (XSS)
| Pattern | Vulnerable | Fixed |
|---------|-----------|-------|
| innerHTML | `element.innerHTML = userInput` | `element.textContent = userInput` |
| dangerouslySetInnerHTML | `<div dangerouslySetInnerHTML={{__html: input}} />` | `<div>{input}</div>` + DOMPurify |
| v-html | `<div v-html="userInput"></div>` | `<div>{{ userInput }}</div>` |
| Template safe | `{{ value|safe }}` in Django template | `{{ value }}` (auto-escaped) |
| mark_safe() | `return mark_safe(user_input)` | `return escape(user_input)` |

**Defense-in-depth:**
```python
# Django — set CSP headers
response['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"

# Flask-Talisman
from flask_talisman import Talisman
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'script-src': "'self'"
})
```

### Server-Side Request Forgery (SSRF)
```python
# VULNERABLE
def fetch_url(url):
    resp = requests.get(url)  # user-controlled URL
    return resp.text

# FIXED — allowlist + DNS validation + no redirects
ALLOWED_HOSTS = {"api.internal.com", "cdn.trusted.com"}

def fetch_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname
    if hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Host {hostname} not allowed")
    # Resolve DNS to prevent DNS rebinding
    resolved = socket.gethostbyname(hostname)
    if not ipaddress.ip_address(resolved).is_private:
        resp = requests.get(url, allow_redirects=False, timeout=5)
        return resp.text
    raise ValueError("Private IP resolved")
```

### Command Injection
```python
# VULNERABLE
result = subprocess.run(f"ping -c 4 {hostname}", shell=True, capture_output=True)

# FIXED — use list arguments, no shell=True
result = subprocess.run(["ping", "-c", "4", hostname], capture_output=True, timeout=10)

# BETTER — validate input with allowlist
import re
if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
    raise ValueError("Invalid hostname")
result = subprocess.run(["ping", "-c", "4", hostname], capture_output=True, timeout=10)
```

### Path Traversal
```python
# VULNERABLE
def read_file(filename):
    path = os.path.join(UPLOAD_DIR, filename)
    return open(path).read()

# FIXED — resolve real path and verify prefix
def read_file(filename):
    safe_dir = os.path.realpath(UPLOAD_DIR)
    requested = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not requested.startswith(safe_dir):
        raise PermissionError("Access denied")
    return open(requested).read()
```

### Insecure Deserialization
```python
# VULNERABLE
data = pickle.loads(request.data)  # arbitrary code execution

# FIXED — use safe format
data = json.loads(request.data)  # safe

# IF PICKLE IS REQUIRED — sign with HMAC
import hmac, hashlib
signature = hmac.new(SECRET_KEY, request.data, hashlib.sha256).hexdigest()
provided = request.headers.get("X-Signature")
if hmac.compare_digest(signature, provided):
    data = pickle.loads(request.data)
else:
    raise ValueError("Invalid signature")
```

### IDOR / Missing Authorization
```python
# VULNERABLE
def get_order(order_id):
    order = Order.query.get(order_id)  # no ownership check
    return order.to_dict()

# FIXED — verify ownership
def get_order(order_id, user_id):
    order = Order.query.filter_by(id=order_id, user_id=user_id).first()
    if not order:
        abort(403)
    return order.to_dict()

# For REST APIs — use scoped queries
class OrderViewSet(viewsets.ModelViewSet):
    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)
```

### Authentication Bypass
```python
# VULNERABLE — missing decorator on some routes
def admin_panel():
    return "Sensitive data"

# FIXED — add auth to every route
@login_required
@admin_required
def admin_panel():
    return "Sensitive data"

# Or better — global middleware
class AuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    def __call__(self, request):
        if not request.user.is_authenticated and request.path.startswith('/api/'):
            return JsonResponse({"error": "Unauthorized"}, status=401)
        return self.get_response(request)
```

### Mass Assignment
```ruby
# VULNERABLE (Rails)
User.create(params)

# FIXED — strong parameters
User.create(user_params)

private
def user_params
  params.require(:user).permit(:name, :email)
end
```

### Weak Cryptography
```python
# VULNERABLE
hash = md5(password).hexdigest()  # MD5 — fast, reversible

# FIXED — use modern KDF
from werkzeug.security import generate_password_hash
hash = generate_password_hash(password)  # pbkdf2:sha256

# Better yet — bcrypt or argon2
import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

## Verification Checklist

For every patch, verify:

```bash
# 1. Syntax check
python3 -c "import py_compile; py_compile.compile('fixed_file.py')"

# 2. Vulnerable input no longer works
curl -s -o /dev/null -w "%{http_code}" \
  -X GET "http://target.com/api/endpoint?param=' OR 1=1--"

# Should return 400/403/500 (rejected), not 200 with data

# 3. Legitimate input still works
curl -s -o /dev/null -w "%{http_code}" \
  -X GET "http://target.com/api/endpoint?param=legitimate_value"

# Should return 200

# 4. Unit tests (if available)
python3 -m pytest tests/test_endpoint.py -v
```

## Output Format

```markdown
## [HIGH] SQL Injection in /api/users/search

**Location:** app/routes/users.py:142
**CVSS:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

### Root Cause
User input from `request.args.get('q')` concatenated directly into SQL query string without parameterization.

### Vulnerable Code
```python
query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%'"
db.execute(query)
```

### Fix
```python
query = "SELECT * FROM users WHERE username LIKE %s"
db.execute(query, (f"%{search_term}%",))
```

### Diff
```diff
- query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%'"
- db.execute(query)
+ query = "SELECT * FROM users WHERE username LIKE %s"
+ db.execute(query, (f"%{search_term}%",))
```

### Verification
```bash
# Malicious input rejected → 400
curl -s http://target.com/api/users?q="' OR 1=1--" | grep -c "error"

# Legitimate input works → 200
curl -s http://target.com/api/users?q=admin | grep -c '"users"'
```

### Regression Risk
Low. Parameterized query is the standard ORM pattern; behavior identical for legitimate inputs.
```

## Language-Specific Quick Reference

| Language | SQLi Fix | XSS Fix | CMDi Fix | SSRF Fix |
|----------|----------|---------|----------|----------|
| Python | `%s` params + `cursor.execute` | `bleach.clean()` or template auto-escape | `subprocess.run([list])` no `shell=True` | URL allowlist + `allow_redirects=False` |
| JS/TS | `?` placeholder in `db.query()` | `textContent` or DOMPurify | `execFile()` not `exec()` | URL parser + hostname allowlist |
| Java | `PreparedStatement` | `Encode.forHtml()` or JSP auto-escape | `ProcessBuilder` list form | InetAddress validator |
| Go | `$1` in `db.QueryRow()` | `html/template` (not `text/template`) | `exec.Command()` list form | `net.URL` Hostname validation |
| Ruby | `?` in `ActiveRecord` | `h()` or `sanitize()` helper | `system()` with array args | `URI.parse` hostname allowlist |
| PHP | `PDO::prepare()` + `?` | `htmlspecialchars()` | `escapeshellarg()` + `exec()` | `parse_url()` hostname check |
| Rust | `sqlx::query!()` macro | `askama` auto-escape or ` ammonia` | `Command::new("arg")` | URL crate + allowlist |
