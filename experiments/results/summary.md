# Controlled experiment results

Generated from `experiments/results/results.json` (2026-11-09T13:40:40.445651+00:00).

Rates are security-relevant outcomes with 95% Wilson intervals. For defensive probes the observed metric is trials − attack successes. `Direction` states whether a higher rate is desirable.

| ID | Scenario | Method | Observed | 95% CI | Direction | Reading |
| --- | --- | --- | ---: | --- | --- | --- |
| P1 | Password + TOTP relay | Password + TOTP | 5/5 (100%) | 0.57–1.00 | lower better | Attack succeeded 5/5 (100%); lower is better. |
| P1b | Replay phished TOTP | Password + TOTP | 5/5 (100%) | 0.57–1.00 | higher better | Defence held in 5/5 (100%); higher is better. |
| P1c | Expired TOTP | Password + TOTP | 3/3 (100%) | 0.44–1.00 | higher better | Defence held in 3/3 (100%); higher is better. |
| P1d | Naive TOTP double use | Password + TOTP | 5/5 (100%) | 0.57–1.00 | lower better | Without server-side replay state the same code worked twice (5/5). |
| P2 | Passkey, lookalike RP ID | Synced passkey | 3/3 (100%) | 0.44–1.00 | higher better | Defence held in 3/3 (100%); higher is better. |
| P3 | Passkey, strict origin relay | Synced passkey | 5/5 (100%) | 0.57–1.00 | higher better | Defence held in 5/5 (100%); higher is better. |
| P4 | Passkey, permissive origin relay | Synced passkey | 5/5 (100%) | 0.57–1.00 | lower better | Attack succeeded 5/5 (100%); lower is better. |
| P5 | Hardware, lookalike RP ID | Hardware FIDO2 key | 3/3 (100%) | 0.44–1.00 | higher better | Defence held in 3/3 (100%); higher is better. |
| P6 | Hardware, strict origin relay | Hardware FIDO2 key | 5/5 (100%) | 0.57–1.00 | higher better | Defence held in 5/5 (100%); higher is better. |
| P7 | Hardware, permissive origin relay | Hardware FIDO2 key | 5/5 (100%) | 0.57–1.00 | lower better | Attack succeeded 5/5 (100%); lower is better. |
| R1 | TOTP replay policy | Password + TOTP | 5/5 (100%) | 0.57–1.00 | higher better | Defence held in 5/5 (100%); higher is better. |
| R2 | TOTP time window | Password + TOTP | 5/5 (100%) | 0.57–1.00 | descriptive | Only offsets −1, 0, +1 were accepted; ±2 were rejected. |
| R3 | Passkey assertion replay | Synced passkey | 3/3 (100%) | 0.44–1.00 | higher better | Defence held in 3/3 (100%); higher is better. |
| R4 | Hardware assertion replay | Hardware FIDO2 key | 3/3 (100%) | 0.44–1.00 | higher better | Defence held in 3/3 (100%); higher is better. |
| R5 | Hardware counter regression | Hardware FIDO2 key | 3/3 (100%) | 0.44–1.00 | higher better | Defence held in 3/3 (100%); higher is better. |
| R6 | Hardware forged high counter | Hardware FIDO2 key | 3/3 (100%) | 0.44–1.00 | lower better | A forged counter above the stored value was accepted (3/3); counter checks catch only lagging clones. |
| R7 | Synced passkey counter policy | Synced passkey | 3/3 (100%) | 0.44–1.00 | higher better | The synced credential was accepted under the relaxed counter policy. |
| S1 | Synced passkey restore | Synced passkey | 5/5 (100%) | 0.57–1.00 | higher better | Task completed in 5/5 (100%); higher is better. |
| S2 | Platform credential loss | Synced passkey | 3/3 (100%) | 0.44–1.00 | descriptive | No credential remained; login was impossible in all trials. |
| S3 | Hardware key loss | Hardware FIDO2 key | 3/3 (100%) | 0.44–1.00 | descriptive | No credential remained; login was impossible in all trials. |
| S4 | Hardware backup key | Hardware FIDO2 key | 3/3 (100%) | 0.44–1.00 | higher better | Task completed in 3/3 (100%); higher is better. |
| S5 | Hardware recovery code | Hardware FIDO2 key | 3/3 (100%) | 0.44–1.00 | higher better | Task completed in 3/3 (100%); higher is better. |
| S6 | Recovery code reuse | All methods | 3/3 (100%) | 0.44–1.00 | higher better | The second use of the recovery code was rejected in all trials. |
| S7 | Email reset invariants | All methods | 3/3 (100%) | 0.44–1.00 | higher better | Defence held in 3/3 (100%); higher is better. |
| S8 | Expired reset token | All methods | 3/3 (100%) | 0.44–1.00 | higher better | Defence held in 3/3 (100%); higher is better. |

## TOTP acceptance window (R2)

| Offset (30 s steps) | Accepted | Rate |
| ---: | ---: | ---: |
| -2 | 0/5 | 0% |
| -1 | 5/5 | 100% |
| +0 | 5/5 | 100% |
| +1 | 5/5 | 100% |
| +2 | 0/5 | 0% |

## Error paths (U2)

| Probe | Method | Blocked | Median latency | Feedback |
| --- | --- | ---: | ---: | --- |
| wrong password | Password + TOTP | 3/3 | 780 ms | Invalid username or password. |
| wrong TOTP | Password + TOTP | 3/3 | 3838 ms | Invalid or already-used code. |
| no passkey credential | Synced passkey | 3/3 | 9847 ms | Cancelled or no matching credential. |
| no hardware credential | Hardware FIDO2 key | 3/3 | 9873 ms | Cancelled or no matching credential. |

## Protocol checks

- `session_cookie_httponly`: `True`
- `session_cookie_samesite`: `Lax`
- `session_cookie_secure`: `False`
- `challenge_b64url_length`: `86`
- `challenge_entropy_bytes`: `64`
- `recovery_token_length`: `43`
- `recovery_token_hashed_at_rest`: `True`
- `recovery_token_plaintext_absent`: `True`
