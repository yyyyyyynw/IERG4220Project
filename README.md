# Beyond TOTP

**Evaluating phishing resistance and account recovery in synced passkeys and
hardware security keys.**

This repository contains a self-contained research testbed (`AuthLab`), a
controlled experiment suite, and the written report for a 4220 project. It
compares three authentication methods end to end:

| Method | Credential | Phishing resistance | Recovery story |
| --- | --- | --- | --- |
| Password + TOTP | Shared secret + 6-digit code | None against real-time relay | Email reset / recovery codes |
| Synced passkey | WebAuthn platform credential, backup eligible | Strong **iff** the RP checks the origin | Sync fabric / second device |
| Hardware FIDO2 key | Non-exportable roaming credential | Strong **iff** the RP checks the origin | Second key / recovery code |

The project combines protocol analysis with a reproducible browser lab. It does
**not** contain fabricated human-subject data: the automated measurements are
real, and the human study is shipped as a ready-to-run protocol.

---

## Quick start

Requirements: Python 3.11+, Google Chrome, macOS/Linux. Node is not required.

```bash
python3 -m pip install -r requirements.txt
python3 run.py
# open http://localhost:5010
```

Normal mode uses `RP_ID=localhost` and a local SQLite database. Register an
account, scan the TOTP QR code with any authenticator app, and enrol a passkey
or a hardware key. On a laptop the platform authenticator is the built-in
Touch ID / Windows Hello; a hardware key is a USB/NFC FIDO2 key.

> Use `http://localhost:5010`, not `http://127.0.0.1:5010`: the default RP ID is
> `localhost`, and a WebAuthn RP ID must be a suffix of the origin's host.

### Lab mode (what the experiments use)

The experiment harness starts its own servers on loopback and does not need the
normal app to be running:

```bash
python3 experiments/run_experiments.py   # ~6-10 min, real browser ceremonies
python3 experiments/analyze.py            # tables, Wilson CIs, figures
```

Outputs:

```
experiments/results/results.json    raw machine-readable measurements
experiments/results/summary.md      scenario table with 95% Wilson intervals
experiments/results/latency.csv     per-task timing
experiments/results/klm.md          analytic usability model
figures/*.png                       phishing, replay/recovery, latency, KLM
```

The suite uses Chrome DevTools Protocol (CDP) virtual authenticators, so it
needs no physical security key. It launches real Chrome, performs real
WebAuthn ceremonies, and drives a hostile reverse proxy at
`evil.app.lvh.me:5011`.

If `*.lvh.me` does not resolve on your network (it normally resolves to
`127.0.0.1` through public wildcard DNS), add:

```
127.0.0.1 app.lvh.me evil.app.lvh.me
```

Free ports `5010` and `5011` before running the suite:

```bash
pkill -f "run.py" || true
```

---

## Research questions

1. **Phishing.** Can a real-time adversary take over an account protected by
   password + TOTP, a synced passkey, or a hardware key?
2. **Replay.** What stops a captured TOTP code or a captured WebAuthn assertion
   from being used twice?
3. **Recovery.** What happens after device loss, key loss, or a lost phone —
   and does the recovery path reopen the phishing/replay hole?
4. **Usability.** How much time and cognitive work does each method add, and
   where does recovery dominate the burden?

## What was measured

- **P1–P7:** real-time phishing relay with three methods and three verifier
  policies (naive lookalike, strict origin check, deliberately permissive
  origin check).
- **R1–R7:** TOTP policy and window, assertion replay, hardware counter
  regression and forged-high-counter clones, synced-passkey counter policy.
- **S1–S8:** synced restore, platform/hardware loss, backup key, recovery code
  use and reuse, email reset single-use/expiry/session revocation.
- **U1–U2:** instrumented ceremony latency and error paths.
- **Protocol checks:** cookie flags, challenge entropy, reset-token hashing.

Headline result: WebAuthn is not automatically phishing-resistant. In this
lab, passkeys and hardware keys both resisted naive lookalikes and strict
origin-checking relays (0/3 and 0/5), but both were fully compromised when the
RP trusted the origin supplied in `clientDataJSON` (5/5 each). The credential
is not the whole security property; **verifier correctness is**.

See [`docs/REPORT.md`](docs/REPORT.md) for the full argument, results, threats,
limitations, and references. A Traditional Chinese executive summary is in
[`docs/SUMMARY_zh.md`](docs/SUMMARY_zh.md).

---

## Repository layout

```
authlab/                  Flask testbed (RP, TOTP, recovery, lab controls)
  routes/auth.py          registration, password + TOTP, sessions
  routes/passkeys.py      WebAuthn registration/authentication, origin policy
  routes/recovery.py      recovery codes, email reset, session revocation
  routes/lab.py           token-guarded test instrumentation
  security.py             scrypt, RFC 6238 TOTP, sessions, flows
  webauthn_service.py     explicit py_webauthn wrappers and counter policy
  static/app.js           browser WebAuthn serialization + timing capture
experiments/
  harness.py              Playwright/CDP lab, virtual authenticators, helpers
  phishing_server.py      hostile lookalike reverse proxy (research only)
  run_experiments.py      P/R/S/U scenarios, writes results.json
  analyze.py              Wilson CIs, latency stats, KLM, figures
  results/                generated results (checked in for this submission)
docs/
  REPORT.md               main report (English, with Chinese summary)
  SUMMARY_zh.md           Traditional Chinese executive summary
  PROJECT_GUIDE_zh.pdf    15-page illustrated Chinese guide for collaborators
  threat_model.md         assets, adversaries, trust boundaries, attack trees
  protocol_analysis.md    message-level analysis and sequence diagrams
  experiment_design.md    variables, controls, procedure, validity
  ethics.md               research ethics and safe-use boundaries
  slides.md               12–15 minute presentation deck
survey/
  study_protocol.md       human-subject protocol (not executed)
  questionnaire.md        SUS, NASA-TLX, trust, preference items
  analyze_survey.py       analysis pipeline with --selftest
README.md
```

## Safety

`experiments/phishing_server.py` is a deliberately hostile proxy. It is bound to
loopback, uses disposable accounts in a temporary database, and must never be
exposed to a network or pointed at a real service. See
[`docs/ethics.md`](docs/ethics.md).

## Environment used for the checked-in results

```
macOS 15.7.7 (arm64)
Python 3.11.1
Google Chrome 156.0.8078.80
Playwright 1.63.0 (Python)
py_webauthn 3.0.1
Flask 3.x, SQLite (WAL)
```

The full environment and timestamp are recorded in
`experiments/results/results.json` under `meta.environment`. The suite is
deterministic in its protocol outcomes; latency varies by machine.
