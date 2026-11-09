# Experiment Design

This document describes how the controlled experiments are built, what each
scenario varies, how the measurements are bounded, and how to reproduce or
extend them.

## 1. Questions and hypotheses

| RQ | Question | Hypothesis | Scenarios |
| --- | --- | --- | --- |
| RQ1 | Can a real-time phisher take over each method? | Password+TOTP yes; passkey/hardware only if the RP skips origin checking | P1–P7 |
| RQ2 | What stops replay of a captured code/assertion? | TOTP needs server counter; WebAuthn needs flow/challenge single-use | P1b–P1d, R1–R4 |
| RQ3 | What do counters prove about clones? | Rollback detection only; synced passkeys need relaxation | R5–R7 |
| RQ4 | Does device loss/backup/recovery work? | Sync and backup keys survive; no-backup cases lock out; recovery codes are single-use | S1–S8 |
| RQ5 | What is the usability cost? | Passkeys/hardware lower login effort; recovery dominates hardware cost | U1–U2, KLM |

## 2. Apparatus and isolation

| Component | Setting |
| --- | --- |
| Real RP | `http://app.lvh.me:5010` |
| Phishing proxy | `http://evil.app.lvh.me:5011` |
| Server | Flask development server, threaded, loopback only |
| Browser | Google Chrome 156.0.8078.80, headless, launched by Playwright |
| Automation | Playwright 1.63.0 Python |
| Authenticators | Chrome CDP `WebAuthn.addVirtualAuthenticator`, CTAP2.1 |
| Database | Temporary SQLite file per `Lab`, WAL mode |
| Secure context | `--unsafely-treat-insecure-origin-as-secure=http://app.lvh.me:5010,http://evil.app.lvh.me:5011` |
| Proxy bypass | `--no-proxy-server` |

Each `Lab` instance:

1. Creates a temporary directory and SQLite database.
2. Creates a Flask app with a random `SECRET_KEY`, a random lab token, and the
   experiment configuration.
3. Starts the real RP and the phishing proxy on ports 5010/5011.
4. Launches Chrome once.
5. Creates a fresh browser context and CDP session per `Client`.
6. Tears everything down and deletes the temporary database.

Because the database is per `Lab`, all users and credentials in a run are
disposable. There is no external service, no real email, and no real user data.

## 3. Scenario structure

Every scenario follows the same shape:

```
setup:    create user, enroll credential(s)
act:      perform the attack / defense / recovery action
observe:  URL, dashboard status, HTTP status, error text, DB state
record:   success boolean, elapsed_ms, diagnostic fields
repeat:   3–5 times (10 for latency)
```

### 3.1 Phishing scenarios

| ID | Varies | Setup | Action | Success means |
| --- | --- | --- | --- | --- |
| P1 | Method = password+TOTP | User with password+TOTP | Proxy relays password and current TOTP to real RP | Attacker reaches dashboard |
| P1b | Replay after relay | Same as P1, attacker already logged in | Replay same code in fresh session | Replay accepted |
| P1c | Code age | Same as P1 | Use code 2 steps old | Old code accepted |
| P1d | Verifier policy | User with TOTP | Call lab verifier twice with `enforce_replay=False` | Both accepted |
| P2 | Method = passkey, naive | Passkey enrolled | Lookalike asks for its own RP ID | Assertion obtained |
| P3 | Method = passkey, strict relay | Passkey enrolled | Proxy relays real challenge; strict origin | Attacker reaches dashboard |
| P4 | Method = passkey, permissive relay | Passkey enrolled | Same assertion; permissive origin | Attacker reaches dashboard |
| P5 | Method = hardware, naive | Hardware key enrolled | Lookalike asks for its own RP ID | Assertion obtained |
| P6 | Method = hardware, strict relay | Hardware key enrolled | Proxy relays; strict origin | Attacker reaches dashboard |
| P7 | Method = hardware, permissive relay | Hardware key enrolled | Proxy relays; permissive origin | Attacker reaches dashboard |

**Independent variable:** method and verifier policy. **Control:** same phishing
page, same challenge generation, same browser, same user password, same
credential type per method. **Confound avoided:** P3/P4 and P6/P7 use the same
credential and the same assertion flow; only the verifier's origin policy
changes.

### 3.2 Replay and counter scenarios

| ID | Varies | Action | Success means |
| --- | --- | --- | --- |
| R1 | Verifier state | Naive (no counter) vs hardened (counter) on same code | Hardened rejects second use |
| R2 | Time offset | Verify codes at offsets −2, −1, 0, +1, +2 | Expected set accepted |
| R3 | Replay target | Same flow vs fresh flow with passkey assertion | Both rejected |
| R4 | Replay target | Same flow vs fresh flow with hardware assertion | Both rejected |
| R5 | Clone counter | Hardware clone with counter below stored | Clone rejected |
| R6 | Clone counter | Hardware clone with counter above stored | Clone accepted (documented limit) |
| R7 | Backup flags | Synced passkey with zero/non-monotonic counter | Credential accepted |

**R2 note:** each offset is verified with `update=False` and
`enforce_replay=False`, so the offsets are independent. Otherwise the first
accepted offset would advance `last_step` and contaminate the rest.

**R5/R6 note:** the harness exports the credential from authenticator A,
removes A, and re-imports it into B with a chosen `signCount`. The virtual
authenticator increments the counter on use, so a clone imported with 0 arrives
with 1. The stored counter is 1; `1 <= 1` triggers the regression check.

### 3.3 Sync, loss, backup, recovery

| ID | Setup | Action | Success means |
| --- | --- | --- | --- |
| S1 | Passkey on A, export/import to B with BE/BS, mark server synced | Log in on B | Login succeeds |
| S2 | Platform credential on A only, remove A | Log in | Login fails (lockout) |
| S3 | Hardware key on A only, remove A | Log in | Login fails (lockout) |
| S4 | Hardware key A, enroll backup B, remove A | Log in with B | Login succeeds |
| S5 | Hardware key A, remove A, keep recovery codes | Use recovery code | Login succeeds |
| S6 | Recovery codes | Use code, log out, reuse same code | Second use blocked |
| S7 | Email reset token | Reset, replay token, check old session/password, new login | All invariants hold |
| S8 | Email reset token | Expire token in DB, submit | HTTP 400 |

**S2 vs S1:** S2 models a device-bound platform credential with no sync. It is
not a contradiction of S1; it is the control condition that shows what sync
buys.

**S3 vs S4:** S3 is the no-backup control; S4 is the backup-key treatment.

**S7 invariants:** first reset HTTP 200; replay HTTP 400; pre-reset session
redirected to `/login`; old password rejected; new password + rotated TOTP
accepted.

### 3.4 Usability

| ID | What is measured | n |
| --- | --- | ---: |
| U1 | Registration, password+TOTP login, passkey enroll/login, hardware enroll/login, email request/submit, recovery-code login | 10 per login task, 3 for recovery |
| U2 | Wrong password, wrong TOTP, no passkey credential, no hardware credential | 3 per probe |

U1 timing starts at the first page action and ends at the successful dashboard
redirect (login) or the "enrolled" confirmation (enrolment). It includes
network and server time on loopback and excludes human decision/typing time.
U2 timing includes Playwright wait timeouts, so it is reported as "observed UI
time", not server latency.

## 4. The phishing proxy

`experiments/phishing_server.py` is a Flask app that serves a lookalike login
page and relays to the real RP.

### 4.1 Password + TOTP relay

```
browser -> proxy: username, password, totp
proxy -> real RP: POST /login/password
proxy -> real RP: POST /login/totp (if redirected)
proxy -> real RP: GET /dashboard
proxy -> browser: {ok, stage, final_url, elapsed_ms}
```

The proxy keeps its own `requests.Session`, so the real RP's session cookie
stays with the attacker. The victim's browser never receives it. This models a
classic real-time phishing kit.

### 4.2 WebAuthn relay

```
browser -> proxy: POST /phish/webauthn/options {kind, username, policy}
proxy -> real RP: POST /webauthn/login/options
proxy -> browser: {phish_id, flow_id, options}

browser: navigator.credentials.get(options)  # signs over evil origin
browser -> proxy: POST /phish/webauthn/verify {phish_id, flow_id, credential, policy}
proxy -> real RP: POST /lab/webauthn/login/verify {flow_id, credential, policy}
proxy -> real RP: GET /dashboard (if verify succeeded)
proxy -> browser: {ok, origin, policy, elapsed_ms}
```

The proxy does not tamper with the assertion; it forwards it verbatim. The only
difference between success and failure is the verifier's origin policy.

### 4.3 Naive lookalike

The page can also call `navigator.credentials.get` with
`rpId = location.hostname` (the attacker's host). No credential exists for that
RP ID, so the browser fails. This is the control that distinguishes "RP ID
scoping" from "origin checking".

## 5. Instrumentation boundaries

| Measurement | Starts | Ends | Includes | Excludes |
| --- | --- | --- | --- | --- |
| Registration | Click submit | `/enroll` load | scrypt, DB, redirect | TOTP scan, user reading |
| Password+TOTP login | Click password submit | `/dashboard` load | password verify, TOTP verify, redirect | Human typing/reading |
| Passkey/hardware login | Click login button | `/dashboard` load | options, authenticator, verify, session | Human biometric/decision |
| Passkey/hardware enrolment | Click enroll | status `ok` | options, create, verify | Harness's 0.9 s reload wait |
| Email request | Click request | reset link rendered | token creation, DB | Real email delivery |
| Email reset | POST token | response | validation, scrypt, rotation | Email reading |
| Recovery-code login | Click submit | `/dashboard` load | normalize, scrypt, DB, session | Finding/typing code |
| U2 error time | Click submit | error rendered | server response + Playwright timeout | — |

The browser-side timing is captured with `performance.now()` in
`authlab/static/app.js` and stored in `sessionStorage` for inspection. The
reported U1 latency is wall-clock time measured around the Playwright action,
not the sessionStorage value; the proxy scenarios also record server-side
verify time.

## 6. Metrics

### 6.1 Primary

- **Attack success:** attacker reaches `/dashboard` or proxy confirms a
  dashboard session.
- **Defense success:** attack/misuse blocked (complement for attack scenarios).
- **Task success:** legitimate user completes login/recovery.
- **Latency:** wall-clock milliseconds as bounded above.

### 6.2 Secondary

- HTTP status codes and error strings.
- Signature counter before/after.
- `backup_eligible` / `backup_state`.
- Session revocation and remaining recovery codes.
- Cookie flags, challenge length, token length, token hash at rest.

### 6.3 Statistics

- Raw counts and rates.
- 95% Wilson score interval for each rate.
- Mean, median, standard deviation, min, max, p95 for latency.
- KLM point estimates for human task time.

No p-values: the independent variable is a protocol policy, not a random
treatment, and n is small. The Wilson interval is reported for transparency,
not as a population estimate.

## 7. Validity

### 7.1 Internal

- Fresh DB and browser context per trial.
- Same server code and browser build.
- Strict/permissive switch changes only the expected origin.
- R2 disables state updates so offsets are independent.
- R3/R4 capture the real assertion and test two replay targets.

### 7.2 Construct

- "Attack success" is account takeover, not merely an error-free request.
- "Defense success" is the complement; the proxy checks the dashboard.
- Latency is ceremony time, not human time; KLM covers human time
  analytically.

### 7.3 External

- Virtual authenticators implement CTAP2.1 and produce real signatures.
- The phishing proxy is a real reverse proxy.
- Limitations: loopback, Chrome only, no vendor sync, no real email, no human
  subjects. See `docs/REPORT.md` §8.7.

### 7.4 Reliability

- 3–5 trials per scenario; protocol outcomes were stable across trials.
- Latency has low variance on loopback (SD 1–9 ms for login).
- The 8 s timeouts in R5/S2/S3 inflate "elapsed" but the outcome is binary and
  stable.

## 8. Reproducing

```bash
# 1. dependencies
python3 -m pip install -r requirements.txt

# 2. free ports
pkill -f "run.py" || true

# 3. DNS (only if *.lvh.me does not resolve)
# 127.0.0.1 app.lvh.me evil.app.lvh.me

# 4. run
python3 experiments/run_experiments.py   # ~6-10 min on the checked-in machine

# 5. analyze
python3 experiments/analyze.py
```

Outputs:

```
experiments/results/results.json
experiments/results/scenarios.csv
experiments/results/latency.csv
experiments/results/summary.md
experiments/results/latency.md
experiments/results/klm.md
experiments/results/analysis.json
figures/phishing.png
figures/replay_recovery.png
figures/totp_window.png
figures/latency.png
figures/klm.png
```

## 9. Results schema

`results.json`:

```json
{
  "meta": {
    "project": "...",
    "generated_utc": "...",
    "environment": {
      "python": "...", "platform": "...", "chrome": "...",
      "rp_id": "app.lvh.me", "origin": "...", "phishing_origin": "...",
      "authenticator": "...", "counter_policy": "strict"
    },
    "duration_seconds": 345.85
  },
  "scenarios": [
    {
      "id": "P1", "category": "phishing", "name": "...",
      "method": "password_totp", "outcome": "attack",
      "trials": 5, "successes": 5, "rate": 1.0,
      "mean_ms": 48.015, "median_ms": 46.055,
      "details": [{"success": true, "elapsed_ms": 48.0, "...": "..."}]
    }
  ],
  "latency": {"samples": {"password_totp_login": [156.0]}, "n": {"...": 10}},
  "error_paths": {"trials": [{"name": "...", "blocked": true}]},
  "protocol_checks": {"session_cookie_httponly": true}
}
```

`analyze.py` adds `scenarios.csv`, `latency.csv`, `summary.md`, `latency.md`,
`klm.md`, `analysis.json`, and the five figures. It also applies the
security-relevant direction (for defensive probes, observed = trials − attack
successes) and the special TOTP-window summary.

## 10. Extending the suite

To add a scenario:

1. Write `scenario_<id>(lab) -> dict` in `run_experiments.py`.
2. Use `_new_user`, `_client`, `_close`, and the existing helpers.
3. Return `summarize(id, category, name, method, outcome, success_meaning,
   trials, expected)`.
4. Add it to the `scenarios` list in `main()`.
5. Add a label/direction/method entry in `analyze.py`.
6. Run the suite and `analyze.py`.

To test a new browser or physical authenticator:

- Replace `channel="chrome"` and the CDP virtual authenticator with a real
  profile/device.
- Keep the same phishing proxy and scenario functions.
- Record the device model and firmware in `meta.environment`.

To test a real sync provider:

- Replace the export/import with the provider's restore flow.
- Keep the server-side `mark-synced` call or replace it with a flag from the
  provider.
- Add revocation and sync-account compromise scenarios.

## 11. Known measurement caveats

1. **Enrolment latency** is dominated by Chrome's virtual authenticator
   credential creation (~1 s), not by the server. Do not compare it directly to
   physical-key enrolment.
2. **U2 error times** include Playwright wait timeouts (3 s / 8 s). They are
   not server latencies.
3. **R5/S2/S3 elapsed times** include an 8 s wait for a redirect that never
   happens. The outcome is the signal, not the time.
4. **Loopback** removes WAN latency; real deployments will add network time.
5. **Virtual counters** may differ from physical-key counters, especially for
   synced credentials.
6. **The permissive verifier is a lab-only vulnerability.** It exists to show
   the consequence of an origin-check bug; it is disabled outside lab mode.
