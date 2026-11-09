# Human-Subject Study Protocol

**Working title:** Usability and perceived security of password + TOTP,
synced passkeys, and hardware security keys, including account recovery.

**Status:** Protocol only. No human data were collected for the 4220 report.
This document is included so the usability claims can be tested rather than
asserted.

---

## 1. Purpose

The automated experiments measure protocol outcomes and ceremony latency. They
do not measure human time, error rates, cognitive load, trust, or preference.
This study fills that gap with a controlled, within-subject comparison of three
authentication methods and their recovery paths.

## 2. Research questions

- **RQ-U1:** How long does a successful login take for each method, including
  human interaction?
- **RQ-U2:** What is the success/error rate for each method?
- **RQ-U3:** How do perceived usability (SUS), cognitive workload (NASA-TLX),
  and trust differ?
- **RQ-U4:** Which method do participants prefer, and why?
- **RQ-U5:** How do recovery-code and email-reset tasks compare in time,
  success, and workload?
- **RQ-U6:** Does prior experience with passkeys or security keys moderate the
  results?

## 3. Design

**Within-subject, three conditions, counterbalanced.**

| Condition | Primary login | Recovery |
| --- | --- | --- |
| C1 | Password + TOTP | Recovery code + email reset |
| C2 | Synced passkey | Restore on a second device / recovery code |
| C3 | Hardware FIDO2 key | Backup key / recovery code |

Each participant completes all three conditions. Condition order is assigned
with a balanced Latin square (six orders for three conditions) to control for
learning and fatigue:

```
ABC, ACB, BAC, BCA, CAB, CBA
```

Participants are randomized to an order in blocks of six. Each condition has:

1. A short training/practice task.
2. A registration/enrolment task.
3. Three login trials (one practice, two measured).
4. A recovery task (counterbalanced within condition).
5. Post-condition questionnaires.

## 4. Participants

- **Target N:** 30 (10 per order block, 5 per exact order). This is a pragmatic
  sample for a course project, not a definitive power calculation.
- **Inclusion:** age 18+, able to use a browser, able to consent.
- **Exclusion:** prior participation in a similar study, researcher/student
  dependency, inability to complete the tasks with reasonable accommodation.
- **Recruitment:** campus mailing lists, posted flyers, and course
  announcements. Do not recruit from a course where the researcher has
  grading power without an independent recruiter.
- **Compensation:** standard local rate (e.g., gift card or course credit),
  prorated or full for withdrawal.
- **Accessibility:** offer larger text, keyboard-only instructions, and a
  support person; do not exclude participants with disabilities without an
  accessibility assessment.

A formal power analysis should be completed before recruitment. For a
within-subject design with three levels and a medium-to-large effect
(`f = 0.25–0.40`), N=30 is a reasonable starting point, but the analysis should
be treated as exploratory if the achieved sample is smaller.

## 5. Materials

- AuthLab running on a study laptop at `http://localhost:5010` (normal mode,
  lab mode off).
- A platform authenticator (Touch ID / Windows Hello) for C2.
- Two hardware FIDO2 keys (primary + backup) for C3.
- A TOTP app on a study phone or a desktop authenticator for C1.
- Printed recovery codes in a sealed envelope for the recovery task.
- A study email inbox that the participant can access for the email-reset task.
- Stopwatch or browser-side timing; the harness can log timings.
- Questionnaires (paper or online form).
- Consent form and debrief script.

All accounts are study-specific. Participants must not enter personal
passwords, personal email addresses, or real recovery codes.

## 6. Procedure

### 6.1 Before the session

- Confirm ethics approval and consent form.
- Prepare a fresh database and study accounts.
- Randomize the condition order.
- Test the hardware keys, platform authenticator, TOTP app, and email inbox.
- Prepare the debrief and compensation.

### 6.2 Session timeline (≈60 minutes)

| Time | Activity |
| ---: | --- |
| 0–5 | Welcome, consent, demographics, prior experience |
| 5–10 | Overview of the three methods (neutral wording) |
| 10–20 | Condition 1: training, enrolment, logins, recovery |
| 20–23 | Questionnaires (SUS, TLX, trust) |
| 23–33 | Condition 2 |
| 33–36 | Questionnaires |
| 36–46 | Condition 3 |
| 46–49 | Questionnaires |
| 49–55 | Final preference/ranking, open-ended questions |
| 55–60 | Debrief, compensation, thanks |

### 6.3 Condition script

For each condition:

1. **Training (2 min).** Show the login page and explain the factor. Do not
   demonstrate the exact credential; let the participant try.
2. **Enrolment (3 min).** Ask the participant to register a study account and
   enrol the factor. Record time and errors. For C1, scan the TOTP QR code.
   For C2, create a passkey. For C3, register the hardware key and set a PIN if
   required.
3. **Login trials (4 min).** Log out. Ask the participant to log in. Record
   time, success, and errors. Repeat twice.
4. **Recovery task (3 min).** Depending on the counterbalanced assignment:
   - use a recovery code;
   - request and complete an email reset;
   - restore a synced passkey on a second device;
   - use a backup hardware key.
5. **Questionnaires (3 min).** SUS, NASA-TLX, trust, perceived security.

### 6.4 Phishing discrimination task (optional, 5 min)

Show four screenshots: a genuine login page and three lookalikes (different
domain, subdomain, and a relay-style page). Ask the participant to judge
"real / fake" and explain why. Record accuracy, confidence, and rationale. This
task is optional and should be counterbalanced; it tests recognition, not
login performance.

### 6.5 Debrief

- Explain the purpose and the conditions.
- Reveal which pages were simulated.
- Confirm that no real credentials were sent anywhere.
- Explain how to recognize phishing and how to use recovery safely.
- Offer to withdraw data.
- Provide compensation.

## 7. Measures

### 7.1 Performance

- Login time (seconds) per trial, from first click to dashboard.
- Login success (binary) per trial.
- Errors (count and type: wrong password, wrong code, no credential, timeout,
  user confusion).
- Enrolment time and success.
- Recovery time and success.
- Phishing discrimination accuracy and confidence (optional).

### 7.2 Questionnaires

- **SUS:** 10 items, 1–5, scored 0–100 [1].
- **NASA-TLX:** six subscales (mental, physical, temporal, performance, effort,
  frustration), 0–100 [2].
- **Trust:** 5 items, 1–5 (see questionnaire).
- **Perceived security:** 3 items, 1–5.
- **Preference:** rank the three methods and give a reason.
- **Open-ended:** what was easy, what was frustrating, what would you change.

### 7.3 Demographics and covariates

- Age range, gender (optional), education, tech proficiency.
- Prior use of TOTP, passkeys, hardware keys.
- Device ownership (phone, laptop, security key).
- Accessibility needs (optional).

## 8. Analysis plan

### 8.1 Descriptive

- Mean, SD, median, IQR for time, SUS, TLX, trust, perceived security.
- Success rates with 95% Wilson intervals.
- Error counts by type.

### 8.2 Inferential

- **Login time:** repeated-measures ANOVA if normal; otherwise Friedman test.
  Post-hoc pairwise Wilcoxon signed-rank with Holm–Bonferroni correction.
- **Success:** Cochran's Q for the three conditions; pairwise McNemar with Holm
  correction.
- **SUS/TLX/trust:** Friedman + pairwise Wilcoxon with Holm correction.
- **Preference:** chi-square goodness of fit or descriptive ranking.
- **Moderation:** mixed-effects model with condition, prior experience, and
  their interaction; random intercept for participant.
- **Effect sizes:** partial eta squared for ANOVA, rank-biserial correlation or
  Cohen's d for pairwise comparisons, odds ratios for success.
- **Alpha:** 0.05, two-tailed, with Holm–Bonferroni across the family of
  pairwise tests.

### 8.3 Missing data

- Report dropout and missing items.
- Do not impute the primary outcomes; use available-case analysis and a
  sensitivity analysis if missingness is non-trivial.
- If a participant cannot complete a condition, code it as a failure and
  report it; do not silently exclude.

### 8.4 Qualitative

- Two coders independently code open-ended responses into themes (e.g., speed,
  trust, device dependence, recovery anxiety).
- Resolve disagreements by discussion; report Cohen's kappa.
- Use representative quotes with study IDs, not names.

## 9. Sample size and power

N=30 is a pragmatic target. A formal power analysis should be run for the
primary outcome (login time) using a pilot estimate. If the achieved sample is
smaller, report the study as exploratory and emphasize effect sizes and
confidence intervals over p-values.

## 10. Data management

- Store data on an encrypted, access-controlled laptop.
- Use study IDs, not names, in the analysis file.
- Keep the linkage key separate and encrypted.
- Do not record real passwords, real email addresses, or real recovery codes.
- Retain raw data for the approved period (e.g., 12 months), then delete.
- Report aggregate results only.
- Share de-identified data only if consent and ethics approval allow it.

## 11. Ethics

See `docs/ethics.md`. Key points: ethics approval, informed consent, minimal
deception with debrief, right to withdraw, data minimization, accessible
participation, and no real credentials. The phishing simulation must be
clearly labeled and local; participants must be told in the debrief.

## 12. Threats to validity

| Threat | Mitigation |
| --- | --- |
| Order/learning effects | Balanced Latin square; practice trial |
| Fatigue | 60-minute cap; breaks |
| Researcher effects | Scripted instructions; neutral wording |
| Device differences | Same study devices; record models |
| Prior experience | Measure and model as a covariate |
| Demand characteristics | Neutral wording; no "correct" method |
| Small sample | Report CIs and effect sizes; exploratory framing |
| Ecological validity | Use realistic tasks and a realistic recovery flow; acknowledge lab setting |

## 13. Pilot

Run 3–5 pilot participants before the main study to:

- check timing and task clarity;
- test the accessibility of instructions;
- validate the questionnaire wording;
- calibrate the recovery task;
- estimate variance for the power analysis.

Pilot data are not included in the main analysis.

## 14. Deliverables

- `survey/questionnaire.md` — instrument and coding.
- `survey/analyze_survey.py` — scoring and analysis pipeline.
- `survey/responses_template.csv` — empty data template.
- This protocol.
- A final report with descriptive statistics, inferential tests, effect sizes,
  qualitative themes, and limitations.

## References

[1] J. Brooke. "SUS: A Quick and Dirty Usability Scale." In *Usability
Evaluation in Industry*, 1996.

[2] S. G. Hart and L. E. Staveland. "Development of NASA-TLX (Task Load Index):
Results of Empirical and Theoretical Research." In *Human Mental Workload*,
1988.
