# Keystroke-Level Model (analytic usability estimate)

This is an analytical model, **not** human-subject data. Operator times follow Card, Moran & Newell: M = 1.35 s, P = 1.10 s, K = 0.20 s, H = 0.40 s, B = 1.00 s. R is the measured ceremony median from this lab. The model assumes an experienced user and no errors.

| Task | Operators | Estimate (s) | Assumptions |
| --- | --- | ---: | --- |
| Password + TOTP login | `2M + 3P + 36K + 2R (measured)` | 13.5 | 10-char username, 20-char password, 6-digit code. |
| Synced passkey login | `M + P + B + R` | 3.5 | One tap, one biometric/PIN check, measured ceremony. |
| Hardware key login | `M + H + P + B + R` | 4.0 | Reach key, touch, local PIN/biometric (UV required). |
| Recovery-code login | `2M + H + 2P + 19K + R` | 9.2 | 10-character username, 8-character code, one separator. |
| Email reset (happy path) | `3M + 2H + 3P + 50K + 2R` | 18.2 | Excludes 30 s assumed email delivery; two 20-char password entries. |

The email-reset row is the least comparable: real delivery latency is environmental and is reported separately from the model.
