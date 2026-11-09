# Threat Model

This document defines the adversaries, assets, trust boundaries, and security
goals used by the AuthLab experiments. It is deliberately narrower than a
production threat model: the goal is to isolate the authentication and recovery
decisions that the project measures.

## 1. Assets

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| Account access | RP session | The attacker's goal in every phishing/replay scenario |
| WebAuthn private key | Authenticator / sync fabric | Possession allows authentication; must never leave the authenticator |
| WebAuthn public key + credential ID | RP database | Used to verify assertions and bind the account |
| TOTP shared secret | RP database | Generates codes; compromise allows unlimited code generation |
| Recovery codes | Printed/offline copy; scrypt hash in DB | Bearer access to the account |
| Email reset token | Email inbox; SHA-256 hash in DB | Bearer access to password reset |
| Active sessions | Browser cookie; SHA-256 hash in DB | Bearer access without re-authentication |
| Sync account | Platform provider | Can restore or revoke synced passkeys |
| Audit log | RP database | Detection and forensics |

## 2. Actors

| Actor | Goal | Capabilities assumed |
| --- | --- | --- |
| Legitimate user | Access their account | Has the password, authenticator, recovery material |
| Remote phisher | Take over the account | Hosts a lookalike, relays HTTP/WebAuthn messages in real time, controls a subdomain under the RP's registrable domain |
| Replay attacker | Reuse a captured code/assertion | Can capture network/browser messages within the validity window |
| Device thief | Use a stolen device/key | Has physical possession, may clone a virtual authenticator and modify its counter |
| Recovery attacker | Abuse a recovery path | Has a recovery code, or access to the victim's email inbox |
| Malicious insider | Access data at rest | Can read the RP database, but not the authenticator's private key |
| Sync provider | Provide availability | Honest-but-curious; may be compromised in a stronger threat model |

## 3. Trust boundaries

```
+---------------------+        HTTPS / WebAuthn        +----------------------+
| Browser +           |<------------------------------>| RP server            |
| authenticator       |   challenge, credential,       | verification,        |
| (platform or USB)   |   session cookie               | sessions, recovery   |
+----------+----------+                                +----------+-----------+
           |                                                      |
           | platform sync (optional)                             | SQLite
           v                                                      v
+---------------------+                                +----------------------+
| Sync fabric         |                                | Credential DB,       |
| (iCloud/Google/PM)  |                                | audit log, tokens    |
+---------------------+                                +----------+-----------+
                                                                  |
                                                       email      v
                                                          +----------------+
                                                          | Email provider |
                                                          +----------------+
```

Boundary assumptions:

1. The browser correctly enforces the WebAuthn RP ID scoping rules.
2. The authenticator keeps the private key secret and enforces user
   verification.
3. The RP server is trusted to implement origin/RP ID/challenge checks and
   session management correctly.
4. The sync provider is trusted for availability and confidentiality of synced
   key material; this project models its observable protocol effect, not its
   internals.
5. The email provider is trusted for delivery. Email reset is therefore only as
   strong as the email account.

## 4. Adversary capabilities in scope

### A1. Real-time phishing relay

The attacker runs a reverse proxy. The victim visits the proxy, which fetches a
real challenge from the RP and forwards it to the victim's browser. The victim's
authenticator signs it. The proxy forwards the result to the RP. For password +
TOTP, the proxy simply reads the password and code and logs in itself.

### A2. Subdomain control

The attacker controls `evil.app.lvh.me`, a subdomain of the RP host
`app.lvh.me`. This is enough to obtain a WebAuthn assertion scoped to
`app.lvh.me` because the RP ID is a suffix of the origin host. It is **not**
enough to pass a strict origin check, because the signed origin is
`evil.app.lvh.me`.

### A3. Capture and replay

The attacker can capture a TOTP code or a serialized WebAuthn assertion and
replay it:
- against the same flow (same `flow_id`);
- against a fresh flow with a new challenge;
- in a new browser session.

### A4. Device loss or credential cloning

The attacker can remove a virtual authenticator, export/import a credential,
and choose a signature counter. This models a stolen device, a cloned
authenticator, or a sync restore. It does not model extraction from a secure
element.

### A5. Recovery-path attack

The attacker can obtain a recovery code or access the victim's email inbox.
They can attempt to reuse a code, replay a reset token, use an expired token,
or keep a pre-recovery session alive.

## 5. Out of scope

- Malware or a compromised browser/OS.
- Session hijacking after a successful login (XSS, cookie theft).
- SIM swap and SS7.
- Phishing the recovery email itself (discussed qualitatively).
- Physical coercion or "evil maid" attacks.
- Supply-chain compromise of the WebAuthn library, browser, or authenticator.
- Side-channel attacks on scrypt, HMAC, or signature verification.
- Quantum attacks.
- Denial of service and resource exhaustion.
- Social engineering of support staff.

## 6. Security goals

| ID | Goal | Primary controls | Experiment |
| --- | --- | --- | --- |
| G1 | A remote phisher cannot obtain account access | Origin-bound WebAuthn, challenge freshness, UV | P1–P7 |
| G2 | A captured code/assertion cannot be reused | TOTP counter, flow single-use, challenge | P1b, P1d, R1–R4 |
| G3 | A cloned credential is detected or its impact is bounded | Signature counter, revocation | R5–R7 |
| G4 | Device loss does not cause permanent lockout | Sync, backup key, recovery code | S1–S5 |
| G5 | Recovery material is single-use and short-lived | Atomic consumption, expiry | S6–S8 |
| G6 | Recovery revokes old sessions and rotates factors | Session revocation, TOTP/password rotation | S7 |
| G7 | The system resists account enumeration | Uniform messages, throttled verification | Implementation inspection (`recovery_home`), U2 |
| G8 | Tokens and codes are not stored in plaintext | SHA-256 (tokens), scrypt (codes) | Protocol checks |

## 7. Attack trees

### 7.1 Phishing a password + TOTP account

```
Take over account
├── Obtain password
│   ├── Phishing page (A1)                     [works]
│   ├── Credential stuffing                     [out of scope]
│   └── Malware/keylogger                       [out of scope]
├── Obtain TOTP code
│   ├── Real-time relay (A1)                   [works, 5/5]
│   ├── Replay a captured code (A3)
│   │   ├── Server stores last_step            [blocked, 5/5]
│   │   └── Stateless verifier                 [works, 5/5]
│   └── Guess within window                    [rate-limited]
└── Use both at the real RP                    [works]
```

### 7.2 Phishing a WebAuthn account

```
Take over account
├── Obtain an assertion for the real RP ID
│   ├── Control a subdomain (A2)
│   │   ├── RP checks origin strictly          [blocked, 0/5]
│   │   └── RP trusts clientDataJSON.origin    [works, 5/5]
│   ├── Use a different domain                 [browser refuses RP ID]
│   └── Compromise the authenticator           [out of scope]
├── Replay a captured assertion (A3)
│   ├── Same flow                              [blocked, 3/3]
│   └── Fresh flow/new challenge               [blocked, 3/3]
└── Steal the sync account                     [out of scope, discussed]
```

### 7.3 Recovery takeover

```
Take over account via recovery
├── Steal a recovery code (A5)
│   ├── Single-use enforcement                 [blocks reuse, 3/3]
│   └── First use                              [works by design]
├── Access the email inbox (A5)
│   ├── Token single-use                       [blocks replay, 3/3]
│   ├── Token expiry                           [blocks stale token, 3/3]
│   └── First use                              [works by design]
├── Keep a pre-recovery session                [revoked, 3/3]
└── Use the old password/TOTP                  [rotated, 3/3]
```

## 8. STRIDE summary

| Threat | Example | Mitigation in AuthLab | Residual risk |
| --- | --- | --- | --- |
| Spoofing | Lookalike origin | WebAuthn origin/RP ID binding | RP misconfiguration (P4/P7) |
| Tampering | Modify assertion/counter | Signature over authData + clientData; counter policy | Forged-high clone (R6) |
| Repudiation | Deny a login | Audit log | Log tampering if DB compromised |
| Information disclosure | Token/code leak | Hash at rest, HttpOnly cookie | Email/sync provider compromise |
| Denial of service | Lockout after loss | Backup key, recovery codes | No backup → lockout (S2/S3) |
| Elevation of privilege | Recovery bypass | Single-use tokens, revocation, rotation | Bearer recovery material |

## 9. Risk matrix (qualitative)

| Threat | Likelihood | Impact | Risk | Evidence |
| --- | --- | --- | --- | --- |
| Real-time password+TOTP phishing | High | High | **Critical** | P1 5/5 |
| WebAuthn relay with permissive RP | Medium (implementation bug) | High | **Critical** | P4/P7 5/5 |
| WebAuthn relay with strict RP | Medium | High | Low | P3/P6 0/5 |
| TOTP replay after takeover | High | Medium | Low (post-hoc) | P1b 5/5 blocked |
| Recovery-code reuse | Medium | High | Low | S6 3/3 blocked |
| Reset-token replay | Medium | High | Low | S7 3/3 blocked |
| Hardware key loss without backup | Medium | High | **High** | S3 3/3 lockout |
| Synced passkey clone | Low | High | Medium | R7 relaxed counter |
| Forged-high hardware clone | Low | High | Medium | R6 3/3 accepted |

## 10. Assumptions and open questions

- The lab uses HTTP on loopback. In production, HTTPS and `Secure` cookies are
  mandatory.
- The lab uses a Flask development server. A production deployment needs a
  hardened WSGI server, a shared session/flow store, and a shared TOTP counter
  store if multiple workers are used.
- The sync provider is modeled, not implemented. Real providers may have
  different counter and revocation semantics.
- The experiments do not test browser vulnerabilities or authenticator
  firmware. A compromised endpoint defeats all three methods.
- Recovery email is a trust anchor. If the email account is compromised, email
  reset is a takeover path regardless of the primary factor.

## 11. How the experiments map to the model

| Experiment | Adversary | Goal tested |
| --- | --- | --- |
| P1 | A1 | G1 against password+TOTP |
| P1b/P1c/P1d | A3 | G2 |
| P2/P3/P4 | A1 + A2 | G1 against passkeys |
| P5/P6/P7 | A1 + A2 | G1 against hardware keys |
| R1/R2 | A3 | G2 |
| R3/R4 | A3 | G2 |
| R5/R6/R7 | A4 | G3 |
| S1–S5 | A4 (loss) | G4 |
| S6–S8 | A5 | G5, G6 |
| U1/U2 | — | G7, usability |

The mapping is intentionally one-to-one: each scenario isolates one adversary
capability and one security goal, so a failure has a clear interpretation.
