---
description: "Generate a security patch for a vulnerable code finding. Takes the finding from code-reviewer and produces a minimal, correct, framework-appropriate fix with before/after diff, verification steps, and regression risk assessment. Supports all OWASP Top 10 classes. Usage: /patch [path-to-vulnerable-file] [--lang py|js|java|go|rb|php|rs]"
---

# /patch

Generate a tested security patch for a confirmed vulnerability.

## When to Use This

After `/code-audit` or `/code-reviewer` identifies a vulnerability. Before submitting a bug bounty report (include fix recommendation in report).

## Usage

```
/patch                                          # Interactive — describe the vulnerable code
/patch app/routes/users.py:142                  # Patch a specific file:line
/patch --lang py                                # Force Python fix patterns
/patch --lang js                                # Force JavaScript/TypeScript fix patterns
/patch --output patch.diff                      # Save diff to file
/patch --verify                                 # Generate and run verification commands
```

## What This Does

1. **Analyzes** the vulnerable code (bug class, framework, root cause)
2. **Selects** the correct fix pattern for the bug class + language
3. **Generates** a minimal diff (only changed lines)
4. **Verifies** the fix with curl / unit test commands
5. **Assesses** regression risk

## Output

```
## [SEVERITY] Bug Class — Short Title

**Location:** path/to/file.py:42
**CVSS:** X.X

### Root Cause
One-line explanation.

### Vulnerable Code
```python
vulnerable code
```

### Fix
```python
fixed code
```

### Diff
```diff
--- a/path/to/file.py
+++ b/path/to/file.py
@@ -X,XX +X,XX @@
```

### Verification
```bash
curl commands that prove the fix works
```

### Regression Risk
Low / Medium / High — and why

### Framework Notes
Any framework-specific considerations
```

## After Patching

1. Run `/validate` on the original finding + patch
2. Include the fix recommendation in your `/report`
3. Run `python3 -m pytest tests/` to check no regressions
