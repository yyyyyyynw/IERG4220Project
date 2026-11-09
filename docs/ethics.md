# Ethics Statement

This project is a security evaluation of authentication protocols. It involves
two very different kinds of research activity, with different ethical
requirements:

1. **Automated protocol experiments** against a testbed that I built and
   control. These were executed for this report.
2. **A human-subject usability study**, specified but **not executed**. It
   would require ethics review before any participant is recruited.

## 1. Automated experiments

### 1.1 Scope and isolation

All automated experiments run against:

- `http://app.lvh.me:5010` — the real AuthLab RP, bound to `127.0.0.1`;
- `http://evil.app.lvh.me:5011` — a deliberately hostile reverse proxy, also
  bound to `127.0.0.1`;
- a temporary SQLite database created for the run and deleted afterwards;
- disposable accounts with randomly generated usernames and a fixed test
  password.

No real service, account, credential, or person is targeted. The hostnames
resolve to loopback through public wildcard DNS; they do not reach the
internet. Chrome is launched with `--no-proxy-server` so ambient proxy settings
cannot route the traffic elsewhere.

### 1.2 The phishing page

The phishing page is clearly labeled:

> RESEARCH PHISHING SIMULATION · evil.app.lvh.me · not a real login

It is served only on loopback, only during an experiment, and only to an
automated browser controlled by the harness. It does not collect data from
people. It is not a reusable phishing kit: it relays to a hard-coded local RP
and requires the per-run lab token for the permissive verifier.

### 1.3 Credentials and data

- All credentials are generated for the experiment and discarded with the
  temporary database.
- No real passwords, TOTP secrets, recovery codes, email addresses, or personal
  data are used.
- The audit log contains only synthetic usernames and event metadata.
- No data leaves the machine.

### 1.4 Dual use

The code demonstrates a verifier bug (`policy=permissive`) and a relay
technique. This is necessary to show why origin checking matters, but it is
dual-use. Safeguards:

- the permissive endpoint is disabled unless `AUTHLAB_LAB=1`;
- it requires a random per-run token;
- it is bound to loopback;
- the README and code comments state that it must not be exposed or pointed at
  a real service;
- the report explains the defensive lesson, not an operational attack kit.

Researchers who reuse this code should keep the lab-only boundary and should
not deploy the permissive verifier.

### 1.5 Responsible disclosure

The "permissive origin check" is a demonstration of a class of implementation
bug, not a disclosure of a specific vendor vulnerability. If a real deployment
is found to have this bug, the responsible path is private disclosure to the
vendor, a coordinated fix, and public discussion only after remediation.

## 2. Human-subject study (not executed)

`survey/study_protocol.md` describes a within-subject usability study. It is a
plan, not a claim that data were collected. If it is run, the following are
required.

### 2.1 Ethics review

- Submit the protocol, consent form, questionnaire, and data-management plan to
  the institution's ethics review board (IRB or equivalent).
- Do not recruit participants before approval.
- Report any protocol changes to the board.

### 2.2 Informed consent

Participants should receive, in plain language:

- the purpose of the study;
- what they will be asked to do (register, log in, recover an account, respond
  to a simulated phishing page);
- the risks (frustration, time, mild stress from the phishing simulation);
- the benefits (none direct; contribution to usable-security research);
- data collected, storage, retention, and who can access it;
- the right to withdraw at any time without penalty;
- contact information for the research team and the ethics board.

### 2.3 Deception and debriefing

The study necessarily simulates phishing. Participants should be told in the
consent form that some tasks involve simulated attacks, without revealing the
exact manipulation if that would invalidate the task. A full debrief should
follow, explaining:

- which page was simulated;
- what was measured;
- that no real credentials were sent anywhere;
- how to recognize similar attacks in real life.

Participants should be able to withdraw their data after the debrief.

### 2.4 Data minimization and security

- Collect only what the analysis needs: participant ID, condition order,
  timings, success/error counts, questionnaire responses, and optional
  demographics.
- Do not collect real passwords, real email addresses, or real recovery codes.
  Use study-specific accounts.
- Store data on an encrypted, access-controlled machine.
- Replace direct identifiers with a study ID as soon as possible.
- Define a retention period and delete raw data afterwards.
- Report aggregate results, not individual identities.

### 2.5 Power and sample size

The protocol targets 30 participants for a within-subject design. This is a
pragmatic sample for a course project, not a definitive estimate. A formal
power analysis should be done before recruitment; the analysis plan should be
preregistered or at least fixed before looking at the data.

### 2.6 Compensation and burden

- Compensate participants for their time at the institution's standard rate.
- Keep sessions under 60 minutes.
- Allow breaks.
- Do not penalize withdrawal.
- Be mindful of participants with disabilities, older adults, and people who
  are unfamiliar with passkeys; provide accessible instructions and support.

### 2.7 Vulnerable participants

Do not recruit people who are in a dependent relationship with the researcher
(students in the researcher's class, employees) without safeguards. If the
study is conducted with students, use a different recruiter or anonymize the
researcher's access to identities.

## 3. Ethics of the claims

- Do not describe the automated results as human usability data. The report
  labels KLM estimates as analytic and the human protocol as not executed.
- Do not generalize from 3–5 trials to population attack rates. The report
  reports Wilson intervals and explains that the scenarios are deterministic
  protocol properties.
- Do not claim that a method is "secure" or "insecure" without stating the
  verifier assumptions. The central finding is conditional: passkeys and
  hardware keys are phishing-resistant **if** the RP checks the origin.
- Do not use the project to justify blaming users for phishing. The experiments
  evaluate systems, not victim behavior.

## 4. Open science and reproducibility

- The testbed, harness, scenario definitions, raw results, and analysis code
  are included so others can reproduce and critique the work.
- The report records versions and the raw result hash.
- The human study materials are included so the usability claims can be tested
  independently.
- Reusers must preserve the lab-only safety boundaries and the ethics
  requirements for any human-subject extension.

## 5. Checklist for a future run

- [ ] Ethics approval obtained.
- [ ] Consent form reviewed and translated if needed.
- [ ] Study accounts only; no real credentials.
- [ ] Phishing page labeled and local.
- [ ] Debrief script prepared.
- [ ] Data storage encrypted and access-controlled.
- [ ] Retention period defined.
- [ ] Analysis plan fixed before data collection.
- [ ] Results reported in aggregate.
- [ ] Raw data deleted at the end of the retention period.
