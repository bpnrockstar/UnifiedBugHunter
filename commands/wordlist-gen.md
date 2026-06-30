---
description: Generate a company-specific password wordlist for spray attacks. Crawls the target website with cewler, dedups + length-filters, then applies hashcat rules to produce a ranked candidate list. Output -> recon/<target>/wordlists/.
argument-hint: <target> [--depth N] [--mode minimal|balanced|aggressive] [--filter strict|loose] [--min-len N] [--rate N]
allowed-tools: Bash
---

# /wordlist-gen

Generate a company-specific password wordlist by crawling the target website and applying hashcat mutation rules.

## Run This

Invoke the backing script directly with the user's arguments; do NOT re-implement
the crawl/dedup/mutation pipeline inline:

```bash
bash tools/wordlist_engine.sh $ARGUMENTS
```

## Usage

```
/wordlist-gen target.com
/wordlist-gen target.com --depth 3
/wordlist-gen target.com --mode aggressive       # 52k rules, for offline cracking only
/wordlist-gen target.com --filter loose          # keep raw cewler tokens (CSS/URL slugs)
/wordlist-gen target.com --min-len 6 --rate 3    # slower, longer-min crawl
```

## Pipeline

1. **cewler** crawls `https://<target>` (depth 2 by default, lowercase, polite rate limit) → `from-website.txt`
2. Awk dedup + filter → `cleaned.txt`
   - **strict** (default): start with letter, alphanum only, max 14 chars, drops 10+ char mixed tokens (kills API key examples, CSS colors, URL slugs)
   - **loose**: only length + printable filter (cewler raw)
3. **hashcat --stdout -r <rules>** applies password mutations (l33t, case, year suffix, exclamation, digit append) → `ranked.txt`

## Modes

| Mode | Rule file | Rules | Use case |
|---|---|---|---|
| `minimal` | `top10_2025.rule` | ~10 | Cautious spray — minimum noise per base word |
| `balanced` *(default)* | `best66.rule` | ~66 | Standard spray — best signal/cost ratio |
| `aggressive` | `OneRuleToRuleThemAll.rule` | 52,014 | **Offline cracking only** — too many candidates for spray |

## Output

```
recon/<target>/wordlists/
├── from-website.txt   # raw cewler output
├── cleaned.txt        # dedup + length-filtered
└── ranked.txt         # final spray candidates (use this)
```

## Example

```bash
$ /wordlist-gen quotes.toscrape.com --mode minimal
[+] Step 1/3: crawling https://quotes.toscrape.com (depth=2, min-len=5, rate=5/s)
[+] Crawled 3199 raw words
[+] Step 2/3: dedup + length filter (5-20 chars, printable ASCII)
[+] Cleaned -> 3159 unique words
[+] Step 3/3: applying rules (top10_2025.rule)
[+] Final wordlist: 31182 candidates
```

Sample mutations for the word "absurd":
```
absurdist        absurdist!       absurdist1       absurdist123
absurdist2025    Absurdist        ABSURDIST        absurdistabsurdist
```

## Why this beats generic wordlists

Password sprays with `rockyou.txt` fail fast — every WAF/lockout-detector knows those passwords. Company-specific wordlists succeed because employees pick passwords from their own world: product names, office cities, internal project codes, founder surnames. cewler harvests exactly those terms from the public website.

## Dependencies

Install once: `./install_tools.sh --with-credential-attack`

The script checks for `cewler` and `hashcat` and exits with a helpful hint if missing.

## What this does NOT do (use the companion commands)

This command only crawls + mutates. The rest of the credential-attack pipeline
ships as separate commands — chain them after this one:

- **No HIBP ranking** — pipe the output through `/breach-check <wordlist>`
  (`tools/breach_checker.py`) to rank candidates by real-world breach count via
  HIBP k-anonymity (no API key needed).
- **No OSINT input** — run `/osint-employees <target>` first to harvest employee
  names + email patterns (theHarvester + username-anarchy), then feed those into
  your spray user list.
- **No spray execution** — run `/spray <url> --users <f> --passes <f>` to actually
  spray (it enforces a typed-host confirm, lockout warning, and audit log).

## Underlying tool

`tools/wordlist_engine.sh <target> [flags]` — call directly if you prefer a non-slash interface.
