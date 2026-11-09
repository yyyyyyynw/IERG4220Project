# Instrumented ceremony latency

Wall-clock time from the first page action to the successful dashboard redirect (login) or the enrolled confirmation (enrolment). Values are milliseconds, measured in headless Chrome with CDP virtual authenticators on loopback; they exclude human decision time and network latency beyond loopback.

| Task | n | Mean | Median | SD | Min | Max | p95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| registration | 10 | 389 | 389 | 4 | 383 | 399 | 399 |
| password_totp_login | 10 | 158 | 158 | 3 | 152 | 163 | 163 |
| passkey_enroll | 10 | 1025 | 1024 | 6 | 1017 | 1034 | 1034 |
| passkey_login | 10 | 103 | 103 | 1 | 101 | 104 | 104 |
| hardware_enroll | 10 | 1035 | 1031 | 8 | 1029 | 1056 | 1056 |
| hardware_login | 10 | 100 | 100 | 3 | 93 | 105 | 105 |
| recovery_email_request | 3 | 89 | 89 | 3 | 87 | 92 | 92 |
| recovery_email_reset | 3 | 42 | 42 | 0 | 42 | 42 | 42 |
| recovery_code_login | 3 | 91 | 94 | 6 | 84 | 94 | 94 |

The enrolment figure is dominated by credential creation in Chrome's virtual authenticator (roughly 1 s here). It does **not** include the 0.9 s wait the harness performs afterwards to let the page reload. The login ceremony itself is about 0.1 s. See `docs/experiment_design.md` for the full instrumentation boundary.
