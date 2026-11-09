# Study Questionnaire

**Study:** Usability and perceived security of password + TOTP, synced
passkeys, and hardware security keys.

All items are administered after each condition. Condition labels (C1/C2/C3)
are mapped to methods by the study script; do not reveal the mapping in a way
that biases responses. Use study IDs only; do not write names or real contact
details on this form.

---

## Part A. Demographics and prior experience (once, at the start)

**A1. Participant ID:** `P______`

**A2. Age range:**  
☐ 18–24 ☐ 25–34 ☐ 35–44 ☐ 45–54 ☐ 55–64 ☐ 65+

**A3. Gender (optional):**  
☐ Woman ☐ Man ☐ Non-binary ☐ Prefer not to say ☐ Self-describe: ______

**A4. Highest education:**  
☐ Secondary ☐ Bachelor's ☐ Master's ☐ Doctorate ☐ Other: ______

**A5. How would you describe your technical proficiency?**  
☐ 1 Novice ☐ 2 ☐ 3 ☐ 4 ☐ 5 Expert

**A6. Have you used a TOTP authenticator app before?**  
☐ Never ☐ Once or twice ☐ Regularly

**A7. Have you used a passkey (Touch ID, Windows Hello, iCloud Keychain,
Google Password Manager, etc.) before?**  
☐ Never ☐ Once or twice ☐ Regularly

**A8. Have you used a hardware security key (YubiKey, etc.) before?**  
☐ Never ☐ Once or twice ☐ Regularly

**A9. Which devices do you use daily? (select all)**  
☐ Laptop/desktop ☐ Smartphone ☐ Tablet ☐ Security key ☐ Other: ______

**A10. Do you have any accessibility needs we should accommodate? (optional)**  
____________________________________________________________

---

## Part B. Post-condition questionnaire

Complete once after each condition. Circle or tick one response per item.

### B1. System Usability Scale (SUS)

**Scale:** 1 = Strongly disagree, 2 = Disagree, 3 = Neutral, 4 = Agree,
5 = Strongly agree.

| # | Item | 1 | 2 | 3 | 4 | 5 |
| ---: | --- | :---: | :---: | :---: | :---: | :---: |
| 1 | I think that I would like to use this system frequently. | ☐ | ☐ | ☐ | ☐ | ☐ |
| 2 | I found the system unnecessarily complex. | ☐ | ☐ | ☐ | ☐ | ☐ |
| 3 | I thought the system was easy to use. | ☐ | ☐ | ☐ | ☐ | ☐ |
| 4 | I think that I would need the support of a technical person to be able to use this system. | ☐ | ☐ | ☐ | ☐ | ☐ |
| 5 | I found the various functions in this system were well integrated. | ☐ | ☐ | ☐ | ☐ | ☐ |
| 6 | I thought there was too much inconsistency in this system. | ☐ | ☐ | ☐ | ☐ | ☐ |
| 7 | I would imagine that most people would learn to use this system very quickly. | ☐ | ☐ | ☐ | ☐ | ☐ |
| 8 | I found the system very cumbersome to use. | ☐ | ☐ | ☐ | ☐ | ☐ |
| 9 | I felt very confident using the system. | ☐ | ☐ | ☐ | ☐ | ☐ |
| 10 | I needed to learn a lot of things before I could get going with this system. | ☐ | ☐ | ☐ | ☐ | ☐ |

**Scoring:** odd items contribute `score − 1`; even items contribute
`5 − score`. Sum the ten contributions and multiply by 2.5. Range 0–100.
Higher is better. Do not reverse the raw items before entering them into the
CSV; the analysis script handles the reversal.

### B2. NASA Task Load Index (NASA-TLX)

**Scale:** 0 = very low, 100 = very high. Mark a number or tick a 20-step scale.

| Subscale | Definition | Rating (0–100) |
| --- | --- | ---: |
| Mental demand | How much thinking, deciding, calculating, remembering, looking, searching, etc. was required? | ______ |
| Physical demand | How much physical activity was required (clicking, typing, reaching for a device)? | ______ |
| Temporal demand | How much time pressure did you feel? | ______ |
| Performance | How successful do you think you were in accomplishing the task? (0 = perfect, 100 = failure) | ______ |
| Effort | How hard did you have to work to accomplish your level of performance? | ______ |
| Frustration | How insecure, discouraged, irritated, stressed, and annoyed were you? | ______ |

**Scoring:** the analysis script uses the unweighted mean of the six subscales
(0–100). Higher is worse. If you use the weighted TLX, record the pairwise
weights separately and state the method in the report.

### B3. Trust and perceived security

**Scale:** 1 = Strongly disagree, 2 = Disagree, 3 = Neutral, 4 = Agree,
5 = Strongly agree.

| # | Item | 1 | 2 | 3 | 4 | 5 |
| ---: | --- | :---: | :---: | :---: | :---: | :---: |
| T1 | I trust this method to protect my account. | ☐ | ☐ | ☐ | ☐ | ☐ |
| T2 | I believe this method would prevent someone else from accessing my account. | ☐ | ☐ | ☐ | ☐ | ☐ |
| T3 | I feel confident that I can use this method correctly. | ☐ | ☐ | ☐ | ☐ | ☐ |
| T4 | I would recommend this method to a friend. | ☐ | ☐ | ☐ | ☐ | ☐ |
| T5 | I worry that this method could be bypassed by an attacker. (reverse) | ☐ | ☐ | ☐ | ☐ | ☐ |
| S1 | This method feels secure. | ☐ | ☐ | ☐ | ☐ | ☐ |
| S2 | This method is convenient for daily use. | ☐ | ☐ | ☐ | ☐ | ☐ |
| S3 | This method would be easy to recover if I lost my device. | ☐ | ☐ | ☐ | ☐ | ☐ |
| S4 | I would use this method for my most important account. | ☐ | ☐ | ☐ | ☐ | ☐ |

**Coding:** T5 is reverse-scored (`6 − score`). Report T1–T4 and S1–S4 as mean
scores; report T5 separately if the reverse wording causes confusion.

### B4. Recovery task

| # | Item | 1 | 2 | 3 | 4 | 5 |
| ---: | --- | :---: | :---: | :---: | :---: | :---: |
| R1 | The recovery task was easy to understand. | ☐ | ☐ | ☐ | ☐ | ☐ |
| R2 | I knew what to do at each step. | ☐ | ☐ | ☐ | ☐ | ☐ |
| R3 | I would be able to recover my account on my own. | ☐ | ☐ | ☐ | ☐ | ☐ |
| R4 | The recovery task felt secure. | ☐ | ☐ | ☐ | ☐ | ☐ |
| R5 | I am concerned about losing access to my account. (reverse) | ☐ | ☐ | ☐ | ☐ | ☐ |

### B5. Open-ended

**B5.1 What was easy about this method?**

____________________________________________________________

**B5.2 What was frustrating or confusing?**

____________________________________________________________

**B5.3 If you lost your device tomorrow, what would you do?**

____________________________________________________________

**B5.4 Any other comments?**

____________________________________________________________

---

## Part C. Final comparison (once, at the end)

**C1. Rank the three methods from most preferred (1) to least preferred (3).**
Use the method labels shown by the study script (A/B/C), not the condition
numbers if that would reveal the mapping.

| Rank | Method label |
| ---: | --- |
| 1 | ______ |
| 2 | ______ |
| 3 | ______ |

**C2. Which method felt most secure?** ______

**C3. Which method was easiest to use?** ______

**C4. Which method would you use for your most important account?** ______

**C5. Did your opinion change after trying the methods? If so, how?**

____________________________________________________________

**C6. Would you recommend a passkey or a security key to a friend? Why?**

____________________________________________________________

---

## Part D. Optional phishing discrimination task

If included, show four screenshots in randomized order: one genuine login page
and three lookalikes (different domain, subdomain, relay-style). For each:

| # | Screenshot | Real or fake? | Confidence (1–5) | Cue(s) used |
| ---: | --- | --- | :---: | --- |
| 1 | ______ | ☐ Real ☐ Fake | ______ | ______ |
| 2 | ______ | ☐ Real ☐ Fake | ______ | ______ |
| 3 | ______ | ☐ Real ☐ Fake | ______ | ______ |
| 4 | ______ | ☐ Real ☐ Fake | ______ | ______ |

**Scoring:** accuracy (0–4), mean confidence, and a qualitative list of cues
(URL, lock icon, domain, layout, certificate, etc.). Do not treat the lock icon
as a reliable signal; discuss it in the debrief.

---

## Part E. Session log (researcher use)

| Field | Value |
| --- | --- |
| Date/time | |
| Condition order | |
| Device/browser | |
| Authenticator model | |
| Recovery task assigned | |
| Login times (s) | |
| Login success (Y/N) | |
| Error notes | |
| SUS / TLX / trust entered | ☐ |
| Debrief completed | ☐ |
| Compensation | |

---

## Data dictionary (CSV)

`survey/analyze_survey.py` expects one row per participant per condition with
at least:

```
participant_id, condition, order,
login_time_s, login_success, errors,
sus_1..sus_10,
tlx_mental, tlx_physical, tlx_temporal, tlx_performance, tlx_effort,
tlx_frustration,
trust_1..trust_5, security_1..security_4,
recovery_time_s, recovery_success,
preference_rank
```

Condition values: `password_totp`, `synced_passkey`, `hardware_key`.
Success values: `1`/`0`. Missing values: leave blank or use `NA`; the script
reports missingness rather than imputing.

## References

- J. Brooke. "SUS: A Quick and Dirty Usability Scale." 1996.
- S. G. Hart and L. E. Staveland. "Development of NASA-TLX." 1988.
