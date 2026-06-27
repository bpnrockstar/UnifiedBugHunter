# Supply-Chain-Attack-Recon — Extended Reference

This file contains extended content extracted from `SKILL.md` to keep the main document under the line limit.

---

  - CISA Log4j page: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a
  - Apache advisory: https://logging.apache.org/log4j/2.x/security.html
  - LunaSec breakdown: https://www.lunasec.io/docs/blog/log4j-zero-day/
  - GovCERT.ch tree of impacted products: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (KEV entry)
- **Recon takeaway:** SBOMs are the answer here. The recon skill's Step 8 (SBOM mining) earns its keep — pulling SPDX/CycloneDX from public release artefacts gives you exact transitive dependency versions, which you can then map to OSV / NVD for known CVEs. Most orgs underestimate their transitive depth.

### 9. tj-actions/changed-files GitHub Action compromise (CVE-2025-30066, March 2025)

- **Flow:** Attacker compromised the `tj-actions/changed-files` GitHub Action (used by ~23,000 repos) and modified all version tags v1–v45 to point to a malicious commit. The injected code ran `printenv` and dumped CI secrets to GitHub Actions logs — visible to anyone with read access on public repos.
- **Root cause:** Mutable tag references in GitHub Actions — `uses: tj-actions/changed-files@v35` resolves at run time, so an attacker who controls the repo can repoint old tags. Most consumers had not pinned to commit SHA (`@<sha>`).
- **Impact:** ~23,000 repositories impacted; CISA added to KEV; thousands of secrets (AWS keys, npm tokens, Docker Hub creds) leaked into public Action logs. Multiple downstream incidents (Coinbase, Cloudflare, others) traced back.
- **References:**
  - CISA KEV entry: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066
  - StepSecurity disclosure: https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised
  - Wiz analysis: https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066
  - Semgrep: https://semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/
- **Recon takeaway:** This is the highest-yield current recon vector. Grep public repos for `uses: <org>/<repo>@v\d+` (mutable tag) versus `uses: <org>/<repo>@<sha>` (pinned). Any unpinned third-party action = supply-chain risk. The skill's Step 6 should explicitly flag mutable-tag usage.

### 10. PyPI typosquats (`colourama`, `python3-dateutil`, `jeIlyfish`, et al.)

- **Flow:** Attackers register PyPI packages with names visually/typographically similar to popular ones — `colourama` for `colorama`, `python3-dateutil` for `python-dateutil`, `jeIlyfish` (capital-I instead of L) for `jellyfish`. Each contained `setup.py` post-install hooks exfiltrating SSH keys, GPG keys, GitHub tokens, or installing crypto-stealers targeting `~/.bitcoin/wallet.dat`.
- **Root cause:** PyPI permits visually-confusable names; pip resolves names by exact string match. No human-review gate on new package publication.
- **Impact:** Each campaign typically <10K installs before takedown, but `jeIlyfish` lived 1 year (Dec 2018 → Dec 2019). Cumulative: dozens of campaigns documented annually by Snyk/Phylum/Sonatype/ReversingLabs.
- **References:**
  - ReversingLabs jeIlyfish/python3-dateutil: https://www.reversinglabs.com/blog/mining-for-malicious-ruby-gems
  - Snyk colourama / pytagora analysis: https://snyk.io/blog/malicious-packages-found-to-be-typo-squatting-in-pypi/
  - Phylum 2024 typosquat report: https://blog.phylum.io/the-state-of-the-software-supply-chain/
  - Sonatype 2024 State of the Software Supply Chain (>700K malicious packages found): https://www.sonatype.com/state-of-the-software-supply-chain/
- **Recon takeaway:** Step 5 of the skill (typosquat candidate generation) maps directly here. For external recon, you LIST candidate typosquat names — you NEVER publish unless explicitly authorized. The deliverable is "these 17 typosquat variants of your top deps are currently unclaimed; recommendation: register them defensively."

### 11. Alex Birsan dependency-confusion disclosure (Feb 2021)

- **Flow:** Birsan extracted internal npm scope names from leaked `package.json` files (publicly cached on archive.org, accidentally-public GitHub repos, JS bundles) for Apple, Microsoft, PayPal, Shopify, Uber, Tesla, Yelp, and ~35 others. He published packages on public npm/PyPI/RubyGems with those internal names AND a higher semver. Most companies' build systems then resolved the public package over the internal one and executed his telemetry-only payload.
- **Root cause:** Package managers (npm, pip, gem) default to "highest version wins, regardless of registry." Internal-package names leaked to external sources. No scope-to-registry enforcement.
- **Impact:** $130K+ in bug bounties (highest known SINGLE researcher payout across multiple programs in 2021); birthed the entire "dependency confusion" attack class; npm/PyPI/Microsoft Azure Artifacts all issued mitigations.
- **References:**
  - Original Birsan write-up: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
  - Microsoft white paper: https://azure.microsoft.com/en-us/resources/3-ways-to-mitigate-risk-using-private-package-feeds/
  - GitHub post-mortem (npm side): https://github.blog/2021-02-12-how-to-prevent-dependency-confusion-on-public-package-registries/
  - Snyk research: https://snyk.io/blog/dependency-confusion-vulnerability-novel-supply-chain-attack/
- **Recon takeaway:** This is the founding citation for Step 3 + Step 4 of the skill. Internal scope discovery via JS bundles is the canonical recon path. Note Birsan's severity calibration: "name is unclaimed" alone was enough at most targets because their builds used `npm install` against a config that fell through to public npm — but the skill's severity table correctly notes this isn't universal.

### 12. XZ Utils (CVE-2024-3094, March 2024)

- **Flow:** "Jia Tan" (`JiaT75`) social-engineered the maintainer of `xz-utils` (an upstream OSS compression library used in nearly every Linux distro) over 2+ years. Once granted co-maintainer status, they inserted a multi-stage backdoor into `liblzma` build process — obfuscated as test fixtures — that would hijack SSH authentication via OpenSSH's systemd-notify integration.
- **Root cause:** Single-maintainer OSS burnout + nation-state-grade patience (Operation J / suspected APT). The backdoor was caught BEFORE major distros shipped it (only Fedora Rawhide and Debian unstable had it briefly) because Andres Freund noticed a 500ms SSH delay during a benchmark.
- **Impact:** Caught before mass deployment, near-miss event. Triggered industry-wide reassessment of "single-maintainer critical OSS" risk. CISA, NIST, OpenSSF all issued post-mortems.
- **References:**
  - CISA advisory: https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094
  - Andres Freund's original disclosure: https://www.openwall.com/lists/oss-security/2024/03/29/4
  - Russ Cox timeline: https://research.swtch.com/xz-timeline
  - Sam James technical breakdown: https://gist.github.com/thesamesam/223949d5a074ebc3dce9ee78baad9e27
- **Recon takeaway:** Hardest case for external recon — social-engineering a maintainer over years leaves few external signals. But: GitHub commit-history analysis (new contributors gaining commit access on critical libs, commits adding obfuscated test fixtures, build-only-on-release changes) is what Andres Freund effectively did. The skill's Step 2 (enumerate public repos) can be extended to "watch for high-trust grants to low-history accounts."

---

### Coverage map: cases → recon skill steps

| Step in skill | Anchoring case(s) |
|---|---|
| Step 1 — GitHub org discovery | Birsan 2021, XZ 2024 |
| Step 2 — Public repo artefact mining | Codecov 2021, XZ 2024, PHP 2021 |
| Step 3 — Internal package-name discovery | Birsan 2021 |
| Step 4 — Dependency-confusion check | Birsan 2021, ua-parser-js 2021 |
| Step 5 — Typosquat candidates | PyPI `colourama`/`jeIlyfish`, event-stream 2018 |
| Step 6 — GitHub Actions workflow injection | tj-actions/changed-files 2025, Codecov 2021 |
| Step 7 — Docker/container registry mining | Codecov 2021, 3CX 2023 |
| Step 8 — SBOM / artefact metadata | Log4Shell 2021, MOVEit 2023 |
| Step 9 — Internal registry URL leakage | Birsan 2021, SolarWinds 2020 |
| Step 10 — npm/PyPI org presence | ua-parser-js 2021, event-stream 2018 |

### Patterns across all 12 cases

- **Code-signing does NOT save you** — SolarWinds, 3CX, ua-parser-js all shipped legitimately-signed malicious code.
- **Pinning to mutable references is the recurring failure** — `curl | bash` (Codecov), `@v35` action tags (tj-actions), `^1.0.0` semver (Birsan, event-stream).
- **Maintainer-account compromise > technical CVE** for npm/PyPI ecosystem — 6 of 12 cases.
- **Cascading supply chain is now normal** — 3CX from X_TRADER; Codecov → HashiCorp → HashiCorp's downstream users. Assume your target's vendors' vendors are in scope conceptually.
- **CI runners are the highest-value foothold** — every case where attacker code executed on a CI runner yielded cloud / GitHub / secrets in bulk.

---

## Related Skills & Chains

- **`hunt-rce`** — Dependency confusion lands as RCE on whatever runner installs the package; CI runners are the highest-value target. Chain primitive: internal package name leaked in public JS bundle / SBOM / Docker image → publish malicious package to public npm/PyPI under same name with higher version → next `npm install` / `pip install` on CI runner executes attacker code in `preinstall` hook → `hunt-rce` post-foothold (env-var extraction yields AWS keys, GitHub PATs, Slack tokens) → CI-plane takeover.
- **`cloud-iam-deep`** — CI runners have IAM credentials; supply-chain RCE there is a credential-exfil bonanza. Chain primitive: malicious package executes on GitHub Actions runner → reads `$AWS_ACCESS_KEY_ID` / `$GITHUB_TOKEN` from env → `cloud-iam-deep` enumeration → IAM-privilege-escalation chain → production cloud-plane access.
- **`offensive-osint`** — Recon discipline overlaps heavily; SBOMs, JS bundles, GitHub org enumeration, Docker registry tags all live in both. Chain primitive: `offensive-osint` GitHub-org recon yields internal package names referenced in CI workflows → `supply-chain-attack-recon` cross-references these against public npm/PyPI for typosquat/confusion candidates.
- **`hunt-cloud-misconfig`** — Container registries (Docker Hub, GHCR, ECR public) frequently expose private images by accident. Chain primitive: SBOM mining reveals `internal-tools-v2:latest` referenced → check Docker Hub for accidentally-public mirror → `hunt-cloud-misconfig` registry enum → pull image → extract secrets baked into layers.
- **`triage-validation`** + **`redteam-report-template`** — Supply-chain RECON is in scope; actual publishing is EXTERNAL-OFFENSIVE and needs explicit written sign-off. Chain primitive: recon-only candidate list assembled → run through `triage-validation` 7-Question Gate (specifically: "can I demonstrate impact WITHOUT publishing?") → report as "dependency-confusion candidate inventory + reproduction steps" via `redteam-report-template`, never as a published-package PoC unless client signed off in writing.
