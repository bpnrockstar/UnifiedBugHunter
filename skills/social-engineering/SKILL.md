---
name: social-engineering
description: "Social engineering methodology for authorized security assessments. Covers pretext development, phishing campaigns (GoPhish/SET/SMTP), vishing scripts, physical social engineering (USB drops, tailgating), OSINT for pretext personalization, evasion techniques (SPF/DKIM/DMARC configuration, landing page design), and reporting metrics. Use when planning authorized phishing simulations, pretext-driven assessments, or social engineering exercises. Only use with explicit written authorization."
---

# Social Engineering Methodology

Authorized social engineering methodology. Every technique here requires signed Rules of Engagement.

## 1. Pretext Development Framework

| Element | Description |
|---------|-------------|
| Persona | Name, role, company (credible to target) |
| Channel | Email, phone, SMS, chat, in-person, USB drop |
| Trigger | Expiring account, security incident, package, survey, policy update |
| Urgency | Must act NOW or face consequence |
| Authority | Internal IT, vendor partner, auditor, regulatory body |
| Ask | Click link, download file, share credentials, install software, transfer funds |
| Backstop | Cover story if questioned or caught |

## 2. Email Infrastructure

### SPF/DKIM/DMARC Setup

```dns
# SPF — authorize your sending IP
yourdomain.com.  TXT  "v=spf1 mx a:mail.yourdomain.com -all"

# DKIM — sign outgoing mail
default._domainkey.yourdomain.com.  TXT  "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb4...AQAB"

# DMARC — monitor mode (p=none) → later p=quarantine
_dmarc.yourdomain.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com"
```

### Phishing Tools

| Tool | Use | Install |
|------|-----|---------|
| GoPhish | Full campaign management | `wget https://github.com/gophish/gophish/releases/...` |
| SET (Social-Engineer Toolkit) | Cloning, payloads, phishing | `git clone https://github.com/trustedsec/social-engineer-toolkit.git && cd social-engineer-toolkit && pip3 install -r requirements.txt && python3 setup.py install` then run `setoolkit` |
| Evilginx2 | Reverse proxy (MFA bypass) | `git clone https://github.com/kgretzky/evilginx2` |
| Modlishka | Reverse proxy (MFA bypass) | `git clone https://github.com/drk1wi/Modlishka` |

## 3. Campaign Template

```markdown
CAMPAIGN: [name]
TARGET: [company]
METHOD: [email / phone / SMS / in-person]

PRETEXT: [one paragraph]
FROM: [sender name] <[sender email]>
SUBJECT: [phishing subject line]
LANDING PAGE: [URL]

KEY METRICS:
- Target: [N] employees
- Expected open: [P]%
- Expected click: [P]%
- Expected credential: [P]%

CONTINGENCY: [what to say if questioned]
```

## 4. Reporting

```markdown
## Results

| Metric | Count | % |
|--------|-------|---|
| Sent | N | 100% |
| Opened | N | P% |
| Clicked | N | P% |
| Credentials | N | P% |
| MFA bypassed | N | P% |
| Reported to IT | N | P% |

## Recommendations

1. [Training recommendation]
2. [Technical control — MFA, filters]
3. [Policy recommendation]
```
