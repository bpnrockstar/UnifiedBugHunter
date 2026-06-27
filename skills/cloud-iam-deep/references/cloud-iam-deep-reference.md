# Cloud-Iam-Deep — Extended Reference

This file contains extended content extracted from `SKILL.md` to keep the main document under the line limit.

---

| Unauth role with `s3:PutObject` on web-hosting bucket | **High** (8.1) | Stored XSS / supply-chain |
| Unauth role with `kms:Decrypt` on a customer CMK | **High** (7.5-8.5) | Depends on ciphertext reachability |
| Unauth role with read-only on a single hardcoded non-sensitive resource | **Medium** (5.3) | Limited business impact |
| Unauth identities enabled but role policy denies everything | **Informational** | Best-practice deviation only |

### Disclosed cases / authoritative writeups

1. **Andres Riancho — "Misconfigured Cognito Identity Pools" (2020, refreshed 2023)** — original research establishing the attack class. `GetCredentialsForIdentity` against unauth pools with default `*` policies. [andresriancho.com](https://andresriancho.com/identity-pools-and-the-default-iam-role-trap/)
2. **Rhino Security Labs — Pacu `cognito__enum_identity_pools` module** — production tooling that automates Steps 1-5 of the chain. [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu/tree/master/pacu/modules/cognito__enum_identity_pools)
3. **NotSoSecure / Claranet — "Exploiting weak configurations in Amazon Cognito" (Nov 2023)** — walkthrough of identityPoolId extraction → assume guest role → S3/DynamoDB/Lambda enumeration. Calls out RUM, Amplify, Pinpoint as the three SDKs that commonly expose the pool ID in HTML. [notsosecure.com](https://www.notsosecure.com/exploiting-weak-configurations-in-amazon-cognito/)
4. **HackTricks Cloud — `aws-cognito-unauthenticated-enum`** — canonical playbook covering Steps 1-5. [cloud.hacktricks.wiki](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum.html)
5. **Spaceraccoon / Eugene Lim — "Mass Account Takeover via Cognito IdentityPool" (Medium, 2020)** — SaaS provider exposed IdentityPoolId in Amplify config; unauth role had `cognito-idp:AdminConfirmSignUp` + `AdminUpdateUserAttributes` on the linked User Pool — silent confirmation of any signup + email change = mass ATO.
6. **Datadog Security Labs — "Following AWS Logs Backwards: Cognito Identity Pool Abuse" (2024)** — telemetry across Datadog customer base showing real-world Cognito pool abuse. Non-trivial percentage of pools paired with policies broader than the minimum required. [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/abusing-aws-cognito-misconfigurations/)

### Reporting tip

Always include in the report:
- `sts get-caller-identity` output (proves the role ARN + account ID)
- Pacu `iam__enum_permissions` JSON output (proves the granted actions)
- A concrete data-pull PoC (one sample S3 object listing, one DynamoDB record with PII redacted)

Without all three, triagers downgrade to Medium. The 60-second test is `GetId → GetCredentialsForIdentity → sts get-caller-identity`. If you reach step 3 anonymously, you have a finding.

Cross-reference: `hunt-cloud-misconfig` → `CloudWatch RUM weaponization` covers the specific RUM-embedded variant of this attack class.

---

## Related Skills & Chains

- **`hunt-ssrf`** — Most external paths to a cloud credential begin with SSRF reaching the metadata service. Chain primitive: SSRF + IMDSv1 → instance role token → `cloud-iam-deep` privilege-escalation patterns reach prod S3 / Secrets Manager.
- **`hunt-cloud-misconfig`** — Public buckets and exposed configs are the most common credential-leak vector. Chain primitive: Cloud misconfig (`.env` in public S3) + leaked AWS access key → IAM enumeration → `iam:PassRole` chain to admin.
- **`supply-chain-attack-recon`** — CI/CD often holds long-lived deploy credentials. Chain primitive: Exposed GitHub Actions OIDC misconfig + assume-role permission → `cloud-iam-deep` cross-account role assumption.
- **`m365-entra-attack`** — Azure Managed Identity overlaps Entra service principals. Chain primitive: SSRF on Azure App Service → Managed Identity token → `m365-entra-attack` Graph API enumeration → cross-tenant escalation.
- **`security-arsenal`** — Load the Cloud IAM Privilege-Escalation Payload Pack (24+ AWS, 8+ Azure, 6+ GCP escalation patterns with `aws cli` one-liners).
- **`triage-validation`** — Apply the Server-State-vs-Policy gate: a permissive IAM policy alone is not a finding; demonstrate actual privileged action (e.g., read prod secret, create cross-account role) before reporting.
