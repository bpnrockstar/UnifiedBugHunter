# White-box code-review corpus — measuring SAST accuracy

The rest of `eval/` is **black-box**: it drives a headless agent at a live, self-grading
target and reads the oracle. This corpus is the **white-box** counterpart. It turns a
question the repo asserts but never proved — *how accurate is UBH's code review?* — into
a measured number: **precision / recall / F1 per vuln class + overall**, plus a TP/FP/FN
confusion summary.

It does that with ground truth we control: small, clearly-labeled
**INTENTIONALLY-VULNERABLE** source files, each paired with a **SAFE variant** that fixes
the bug. The vulnerable files are the positive cases (a finding is expected at a known
line); the safe files are the negative cases (zero findings expected). Run the SAST engine
over both, compare to `ground_truth.json`, and you get the score.

## Layout
```
eval/code_corpus/
├── README.md                 # this file
├── ground_truth.json         # the labels: expected findings + negative (safe) files
├── findings_sample.json      # committed SAST output (curated) — lets tests/CI score
│                             #   WITHOUT semgrep installed
├── run_eval_code.py          # scorer: run_sast (or a findings JSON) → P/R/F1 + confusion
├── vulnerable/               # one INTENTIONALLY-VULNERABLE file per class (+ a few .js)
│   ├── sqli.py / sqli.js
│   ├── xss.py / xss.js
│   ├── command_injection.py / command_injection.js
│   ├── ssrf.py
│   ├── path_traversal.py
│   ├── insecure_deserialization.py
│   ├── ssti.py
│   ├── weak_crypto.py
│   ├── jwt_alg_none.py
│   └── hardcoded_secret.py / hardcoded_secret.js
└── safe/                     # the matched SAFE variant of every file above (negatives)
    └── …same names…
```

Every vulnerable file opens with the marker comment
`# INTENTIONALLY VULNERABLE — eval fixture, do not deploy` and names its single intended
sink in a `VULN:` comment. The safe variants mark the fix with a `SAFE:` comment. These
are fixtures, not deployable code — secrets in them are fabricated and non-functional.

### Classes covered (10) — one vulnerable/safe pair each
`sqli`, `xss`, `command-injection`, `ssrf`, `path-traversal`,
`insecure-deserialization`, `ssti`, `weak-crypto`, `jwt-alg-none`, `hardcoded-secret`.
Python for all ten; JavaScript pairs for `sqli`, `xss`, `command-injection`,
`hardcoded-secret` (the classes whose JS sinks differ enough to be worth a second language).

## `ground_truth.json` schema
```jsonc
{
  "schema_version": 1,
  "line_tolerance": 2,                 // a finding's line may differ from the label by ±2
  "vuln_classes": ["sqli", "xss", …],  // the corpus taxonomy (10 classes)

  "expected": [                        // positive cases — each is one true vulnerability
    {
      "file": "vulnerable/sqli.py",    // path relative to eval/code_corpus/
      "line": 12,                      // 1-based line of the sink
      "vuln_class": "sqli",            // must be one of vuln_classes
      "language": "python",
      "cwe": "CWE-89",
      "note": "user_id interpolated into SQL string"
    }
    // …one entry per vulnerable file…
  ],

  "negatives": [                       // negative cases — SAFE files; expect ZERO findings
    { "file": "safe/sqli.py", "vuln_class": "sqli", "language": "python" }
    // …one entry per safe file…
  ]
}
```
A finding is keyed for matching by **{file, line, vuln_class}** (line compared within
`line_tolerance`). Negatives carry no line — any security finding on them is a false
positive.

## `run_eval_code.py`
### `score()` — the importable scorer (tests call this directly)
```python
score(findings: list[dict], ground_truth: dict) -> dict
```
- **`findings`** — a list of SAST findings (the normalized dicts `tools/sast_runner.run_sast`
  returns, or any list with `file`/`path`, `line`, `vuln_class`, and optionally
  `rule_id`/`message`).
- **`ground_truth`** — the parsed `ground_truth.json`.
- **returns**:
  ```jsonc
  {
    "overall":   {"tp","fp","fn","support","precision","recall","f1"},
    "per_class": {"<class>": {"tp","fp","fn","support","precision","recall","f1"}, …},
    "matched":   [ { …expected…, "matched_line": int, "rule_id": str } ],  // TPs
    "missed":    [ …expected… ],                                            // FNs
    "false_positives": [ …finding… ],                                       // FPs
    "negatives": {"files": int, "clean": int, "violated": int, "violations": […]}
  }
  ```

Other importable helpers: `load_ground_truth(path)`, `canonicalize_class(finding)`,
`normalize_findings(findings)`, `format_report(scored)`, `finding_file(finding)`.

### Scoring rules (and why)
- **True positive** — a finding on an expected file, of the expected canonical class,
  within `line_tolerance` of the expected line. Each label matches at most one finding.
- **Duplicate suppression** — engines routinely fire several rules for *one* bug on *one*
  line. The first is the TP; further same-file/same-class hits within tolerance of it are
  the *same* finding, not new FPs. They're suppressed so duplicate rulesets don't wreck
  precision.
- **False positive** — (a) any security finding on a SAFE file, or (b) a finding of an
  expected class on a vulnerable file at a location no label covers. A finding of a
  *different* (real) class on a vulnerable file that we simply didn't label is treated as
  out-of-taxonomy noise and **ignored** — the corpus doesn't penalize an engine for
  flagging an unrelated true issue.
- **False negative** — an expected label with no matching finding.

### Engine-label normalization
Engines disagree on class names: semgrep's auto ruleset routes JWT-alg-none through
`sast_runner` as `other`, calls command injection `cmd-injection`, weak crypto `crypto`,
etc. `canonicalize_class()` folds every engine label into the corpus taxonomy — by alias
first, then by `rule_id`/`message` keywords (so a `jwt-none-alg` rule recovers as
`jwt-alg-none` even when the runner labeled it `other`). The eval therefore measures *"did
we flag the right bug at the right place"*, not *"did the engine use our exact string"*.

## Running it
```bash
# Live: import tools/sast_runner.run_sast and scan the corpus. Uses semgrep if installed;
# the runner itself degrades to its regex fallback when semgrep is absent (no hard dep).
python3 eval/code_corpus/run_eval_code.py

# Offline / CI / no semgrep: score the committed findings fixture (deterministic).
python3 eval/code_corpus/run_eval_code.py --findings eval/code_corpus/findings_sample.json

# Machine-readable, or as a CI gate:
python3 eval/code_corpus/run_eval_code.py --json
python3 eval/code_corpus/run_eval_code.py --findings eval/code_corpus/findings_sample.json --min-f1 0.95
```
A completed scoring run exits 0 (use `--min-f1` to fail below a threshold).

## Graceful degradation (no semgrep required, ever)
`tools/sast_runner.py` mirrors `tools/secrets_hunter.sh` / `tools/cicd_scanner.sh`: a
missing scanner binary is a supported state, not an error. When semgrep is absent it
degrades to a built-in regex pass and labels the run `engine_used: "regex-fallback"`.
**The tests never require semgrep / osv-scanner** — they score the committed
`findings_sample.json` and exercise the runner's fallback path directly. The numbers in a
live run will track whatever engine is actually installed; the committed fixture keeps the
*scorer itself* under deterministic test.

## Two numbers, two purposes
- **Curated fixture (`findings_sample.json`)** → precision = recall = F1 = **1.00**. This
  is the "what good looks like" reference: it proves the *scorer* and the corpus labels are
  internally consistent. It is also the no-semgrep test input.
- **Live `run_sast`** → the *actual* accuracy of the installed engine on this corpus
  (with today's semgrep auto ruleset it under-detects a few classes and over-flags a couple
  of safe files). That gap, now visible, is the entire point: code-review accuracy is a
  measured number you can track and improve, not an assumption.

## Extending the corpus
1. Add `vulnerable/<class>.<ext>` (with the `INTENTIONALLY VULNERABLE` header + a `VULN:`
   sink comment) and a matched `safe/<class>.<ext>`.
2. Add one `expected` entry (file, line, vuln_class, language, cwe) and one `negatives`
   entry for the safe file in `ground_truth.json`.
3. If the class is new, add it to `vuln_classes` here and to `CORPUS_CLASSES` /
   `_CLASS_ALIASES` / `_KEYWORD_ROUTES` in `run_eval_code.py`.
4. Regenerate `findings_sample.json` from a real scan, or hand-curate the ideal finding.
```bash
python3 - <<'PY'
import sys, json; sys.path.insert(0, "tools")
import sast_runner as sr
print(json.dumps(sr.run_sast("eval/code_corpus")["findings"], indent=2, sort_keys=True))
PY
```

## ⚠️ Read before trusting the number
- **Single-sink fixtures ≠ real code.** Each file isolates one bug. This measures sink-level
  detection precision/recall, **not** taint-tracking across files, business-logic flaws, or
  chained bugs — where real review effort goes. A high score here is necessary, not
  sufficient.
- **The score tracks the installed engine + its ruleset version.** A different semgrep
  version (or a different scanner) will move the live numbers. Pin the engine when comparing
  runs over time.
- **Fixtures only.** Nothing here is deployable; the "secrets" are fabricated.
