"""Analyze the human-subject questionnaire and task data.

Usage
-----
    python survey/analyze_survey.py survey/responses.csv --out survey/results
    python survey/analyze_survey.py --selftest

The input is one row per participant per condition (see
``survey/responses_template.csv``). The script computes SUS, NASA-TLX, trust
and perceived-security scores, descriptive statistics, Friedman tests, pairwise
Wilcoxon tests with Holm correction, Cochran's Q and McNemar tests for
success, and effect sizes.

``--selftest`` generates clearly labelled **synthetic** data in memory and runs
the whole pipeline. It does not read or write study data. No human-subject data
are included in this repository.
"""
from __future__ import annotations

import argparse
import csv
import math
import os
import random
import statistics as stats
import sys
import tempfile

try:
    from scipy import stats as sps
except Exception:  # pragma: no cover
    sps = None

CONDITIONS = ["password_totp", "synced_passkey", "hardware_key"]
CONDITION_LABELS = {
    "password_totp": "Password + TOTP",
    "synced_passkey": "Synced passkey",
    "hardware_key": "Hardware key",
}
SUS_ITEMS = [f"sus_{i}" for i in range(1, 11)]
TLX_ITEMS = ["tlx_mental", "tlx_physical", "tlx_temporal",
             "tlx_performance", "tlx_effort", "tlx_frustration"]
TRUST_ITEMS = [f"trust_{i}" for i in range(1, 6)]
SECURITY_ITEMS = [f"security_{i}" for i in range(1, 5)]


def number(value):
    if value is None:
        return None
    text = str(value).strip()
    if text == "" or text.upper() in {"NA", "N/A", "NAN", "NULL", "-"}:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return (0.0, 0.0)
    phat = k / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def sus_score(row: dict):
    values = [number(row.get(item)) for item in SUS_ITEMS]
    if any(v is None for v in values):
        return None
    contributions = []
    for index, value in enumerate(values, start=1):
        if index % 2 == 1:
            contributions.append(value - 1)
        else:
            contributions.append(5 - value)
    return sum(contributions) * 2.5


def tlx_score(row: dict):
    values = [number(row.get(item)) for item in TLX_ITEMS]
    if any(v is None for v in values):
        return None
    return sum(values) / len(values)


def trust_score(row: dict):
    values = [number(row.get(item)) for item in TRUST_ITEMS]
    if any(v is None for v in values):
        return None
    # T5 is negatively worded; reverse it.
    values[-1] = 6 - values[-1]
    return sum(values) / len(values)


def security_score(row: dict):
    values = [number(row.get(item)) for item in SECURITY_ITEMS]
    if any(v is None for v in values):
        return None
    return sum(values) / len(values)


def load_rows(path: str):
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = [dict(row) for row in reader]
    clean = []
    for row in rows:
        condition = (row.get("condition") or "").strip()
        if condition not in CONDITIONS:
            continue
        record = {
            "participant_id": (row.get("participant_id") or "").strip(),
            "condition": condition,
            "order": (row.get("order") or "").strip(),
            "login_time_s": number(row.get("login_time_s")),
            "login_success": number(row.get("login_success")),
            "errors": number(row.get("errors")),
            "recovery_time_s": number(row.get("recovery_time_s")),
            "recovery_success": number(row.get("recovery_success")),
            "preference_rank": number(row.get("preference_rank")),
            "sus": sus_score(row),
            "tlx": tlx_score(row),
            "trust": trust_score(row),
            "security": security_score(row),
        }
        clean.append(record)
    return clean


def describe(values):
    clean = [v for v in values if v is not None]
    if not clean:
        return {"n": 0, "mean": None, "sd": None, "median": None,
                "q1": None, "q3": None, "min": None, "max": None}
    ordered = sorted(clean)
    n = len(ordered)
    q1 = ordered[max(0, int(0.25 * (n - 1)))]
    q3 = ordered[min(n - 1, int(0.75 * (n - 1)))]
    return {
        "n": n,
        "mean": stats.mean(ordered),
        "sd": stats.stdev(ordered) if n > 1 else 0.0,
        "median": stats.median(ordered),
        "q1": q1,
        "q3": q3,
        "min": ordered[0],
        "max": ordered[-1],
    }


def paired_by_participant(rows, field):
    """Return {participant: {condition: value}} for complete triples."""
    table = {}
    for row in rows:
        pid = row["participant_id"]
        value = row.get(field)
        if value is None:
            continue
        table.setdefault(pid, {})[row["condition"]] = value
    complete = {
        pid: cond for pid, cond in table.items()
        if all(c in cond for c in CONDITIONS)
    }
    return complete


def holm(pvalues):
    """Holm-Bonferroni adjusted p-values, preserving input order."""
    indexed = sorted(enumerate(pvalues), key=lambda pair: pair[1])
    m = len(pvalues)
    adjusted = [None] * m
    running = 0.0
    for rank, (index, p) in enumerate(indexed):
        value = min(1.0, (m - rank) * p)
        running = max(running, value)
        adjusted[index] = running
    return adjusted


def rank_biserial(diffs):
    nonzero = [d for d in diffs if d != 0]
    if not nonzero:
        return 0.0
    ranks = sps.rankdata([abs(d) for d in nonzero])
    positive = sum(r for r, d in zip(ranks, nonzero) if d > 0)
    negative = sum(r for r, d in zip(ranks, nonzero) if d < 0)
    total = positive + negative
    return (positive - negative) / total if total else 0.0


def friedman_and_pairs(rows, field, label):
    """Friedman test + pairwise Wilcoxon with Holm; returns (text, results)."""
    table = paired_by_participant(rows, field)
    if len(table) < 3:
        return (f"### {label}\n\nNot enough complete triples "
                f"(n={len(table)}); skipped.\n", [])
    samples = {c: [table[pid][c] for pid in sorted(table)] for c in CONDITIONS}
    arrays = [samples[c] for c in CONDITIONS]
    if sps is None:
        return (f"### {label}\n\nSciPy unavailable; skipped inferential tests.\n", [])
    try:
        stat, p = sps.friedmanchisquare(*arrays)
    except Exception as exc:
        return (f"### {label}\n\nFriedman failed: {exc}\n", [])
    k = len(CONDITIONS)
    n = len(table)
    kendall_w = stat / (n * (k - 1)) if n and k > 1 else None

    lines = [
        f"### {label}",
        "",
        f"Friedman χ²({k - 1}) = {stat:.3f}, p = {p:.4g}, "
        f"Kendall's W = {kendall_w:.3f} (n = {n}).",
        "",
    ]
    results = [{"metric": field, "test": "friedman", "stat": stat,
                "p": p, "n": n, "effect": kendall_w}]

    if p < 0.05:
        pair_rows = []
        pvals = []
        for i in range(k):
            for j in range(i + 1, k):
                a, b = CONDITIONS[i], CONDITIONS[j]
                diffs = [samples[a][idx] - samples[b][idx]
                         for idx in range(n)]
                if all(d == 0 for d in diffs):
                    pval = 1.0
                    wstat = 0.0
                else:
                    try:
                        wstat, pval = sps.wilcoxon(samples[a], samples[b],
                                                   zero_method="wilcox")
                    except Exception:
                        wstat, pval = 0.0, 1.0
                pvals.append(pval)
                pair_rows.append({
                    "a": a, "b": b, "stat": wstat, "p": pval,
                    "median_diff": stats.median(diffs),
                    "effect": rank_biserial(diffs),
                    "n": n,
                })
        adjusted = holm(pvals)
        for pair, adj in zip(pair_rows, adjusted):
            pair["p_holm"] = adj
            pair["significant"] = adj < 0.05
            results.append({
                "metric": field, "test": "wilcoxon",
                "a": pair["a"], "b": pair["b"],
                "stat": pair["stat"], "p": pair["p"],
                "p_holm": adj, "effect": pair["effect"],
                "median_diff": pair["median_diff"], "n": n,
            })
        lines += [
            "| Comparison | Median diff | Rank-biserial | p | p (Holm) |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
        for pair in pair_rows:
            lines.append(
                f"| {CONDITION_LABELS[pair['a']]} vs "
                f"{CONDITION_LABELS[pair['b']]} | "
                f"{pair['median_diff']:.3f} | {pair['effect']:.3f} | "
                f"{pair['p']:.4g} | {pair['p_holm']:.4g} |"
            )
        lines.append("")
    else:
        lines.append("No significant omnibus difference; pairwise tests "
                     "not interpreted.\n")
    return ("\n".join(lines) + "\n", results)


def cochran_q(rows, field="login_success"):
    table = paired_by_participant(rows, field)
    if len(table) < 3:
        return (f"Not enough complete triples for Cochran's Q "
                f"(n={len(table)}).\n", None)
    n = len(table)
    k = len(CONDITIONS)
    values = {c: [table[pid][c] for pid in sorted(table)] for c in CONDITIONS}
    sums = [sum(values[c]) for c in CONDITIONS]
    total = sum(sums)
    subject_sums = [
        sum(values[c][idx] for c in CONDITIONS) for idx in range(n)
    ]
    denominator = k * total - sum(s * s for s in sums)
    if denominator == 0:
        return ("Cochran's Q undefined (no variation).\n", None)
    q = (k - 1) * (k * sum(s * s for s in subject_sums) - total * total) / denominator
    p = sps.chi2.sf(q, k - 1) if sps else None
    lines = [
        f"Cochran's Q({k - 1}) = {q:.3f}, p = {p:.4g} (n = {n})."
        if p is not None else f"Cochran's Q({k - 1}) = {q:.3f} (n = {n}).",
        "",
    ]
    return ("\n".join(lines), {"test": "cochran_q", "stat": q, "p": p, "n": n})


def mcnemar_pairs(rows, field="login_success"):
    table = paired_by_participant(rows, field)
    if len(table) < 3:
        return ("Not enough complete triples for McNemar.\n", [])
    ids = sorted(table)
    lines = [
        "| Comparison | Concordant success | Discordant (A only / B only) | p | p (Holm) |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    pairs = []
    pvals = []
    for i in range(len(CONDITIONS)):
        for j in range(i + 1, len(CONDITIONS)):
            a, b = CONDITIONS[i], CONDITIONS[j]
            both = sum(1 for pid in ids
                       if table[pid][a] == 1 and table[pid][b] == 1)
            a_only = sum(1 for pid in ids
                         if table[pid][a] == 1 and table[pid][b] == 0)
            b_only = sum(1 for pid in ids
                         if table[pid][a] == 0 and table[pid][b] == 1)
            discordant = a_only + b_only
            if discordant == 0:
                p = 1.0
            else:
                p = min(1.0, 2 * sps.binomtest(
                    min(a_only, b_only), discordant, 0.5
                ).pvalue)
            pvals.append(p)
            pairs.append({"a": a, "b": b, "both": both,
                          "a_only": a_only, "b_only": b_only, "p": p})
    adjusted = holm(pvals)
    results = []
    for pair, adj in zip(pairs, adjusted):
        pair["p_holm"] = adj
        lines.append(
            f"| {CONDITION_LABELS[pair['a']]} vs "
            f"{CONDITION_LABELS[pair['b']]} | {pair['both']} | "
            f"{pair['a_only']} / {pair['b_only']} | {pair['p']:.4g} | "
            f"{pair['p_holm']:.4g} |"
        )
        results.append({"test": "mcnemar", **pair})
    return ("\n".join(lines) + "\n", results)


def summarize_success(rows, field, label):
    lines = [f"### {label}", "",
             "| Condition | Success | 95% Wilson CI |", "| --- | ---: | --- |"]
    for condition in CONDITIONS:
        values = [row.get(field) for row in rows
                  if row["condition"] == condition and row.get(field) is not None]
        k = sum(1 for v in values if v >= 0.5)
        n = len(values)
        lo, hi = wilson(k, n)
        lines.append(
            f"| {CONDITION_LABELS[condition]} | {k}/{n} | "
            f"{lo:.2f}–{hi:.2f} |"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def build_report(rows, source):
    lines = [
        "# Survey analysis",
        "",
        f"Source: `{source}`. Rows: {len(rows)}. "
        f"Participants: {len(set(r['participant_id'] for r in rows))}.",
        "",
        "> This report is generated only if a response file is supplied. "
        "The repository contains no human-subject data.",
        "",
        "## Descriptive statistics",
        "",
    ]
    metrics = [
        ("login_time_s", "Login time (s)"),
        ("recovery_time_s", "Recovery time (s)"),
        ("sus", "SUS (0–100)"),
        ("tlx", "NASA-TLX (0–100)"),
        ("trust", "Trust (1–5)"),
        ("security", "Perceived security (1–5)"),
        ("errors", "Errors (count)"),
    ]
    for field, label in metrics:
        lines += [f"### {label}", "",
                  "| Condition | n | Mean | SD | Median | IQR | Min | Max |",
                  "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
        for condition in CONDITIONS:
            values = [row.get(field) for row in rows
                      if row["condition"] == condition]
            d = describe(values)
            if d["n"] == 0:
                continue
            iqr = f"{d['q1']:.2f}–{d['q3']:.2f}"
            lines.append(
                f"| {CONDITION_LABELS[condition]} | {d['n']} | "
                f"{d['mean']:.2f} | {d['sd']:.2f} | {d['median']:.2f} | "
                f"{iqr} | {d['min']:.2f} | {d['max']:.2f} |"
            )
        lines.append("")

    lines += ["## Success rates", "",
              summarize_success(rows, "login_success", "Login success"),
              summarize_success(rows, "recovery_success", "Recovery success")]

    lines += ["## Inferential tests", ""]
    inferential = []
    for field, label in [
        ("login_time_s", "Login time"),
        ("recovery_time_s", "Recovery time"),
        ("sus", "SUS"),
        ("tlx", "NASA-TLX"),
        ("trust", "Trust"),
        ("security", "Perceived security"),
        ("errors", "Errors"),
    ]:
        text, result = friedman_and_pairs(rows, field, label)
        lines.append(text)
        inferential.extend(result)

    lines += ["## Login success: Cochran's Q and McNemar", ""]
    qtext, qresult = cochran_q(rows)
    lines.append(qtext)
    mtext, mresults = mcnemar_pairs(rows)
    lines.append(mtext)
    if qresult:
        inferential.append(qresult)
    inferential.extend(mresults)

    lines += ["## Preference", ""]
    pref = [row["preference_rank"] for row in rows
            if row.get("preference_rank") is not None]
    if pref:
        counts = {c: 0 for c in CONDITIONS}
        for row in rows:
            rank = row.get("preference_rank")
            if rank == 1:
                counts[row["condition"]] += 1
        lines += ["| Condition | First-choice count |", "| --- | ---: |"]
        for condition in CONDITIONS:
            lines.append(
                f"| {CONDITION_LABELS[condition]} | {counts[condition]} |"
            )
        lines.append("")
    else:
        lines += ["No preference ranks supplied.\n"]

    lines += [
        "## Notes",
        "",
        "- SUS: odd items `score − 1`, even items `5 − score`, sum × 2.5.",
        "- NASA-TLX: unweighted mean of six subscales; higher is worse.",
        "- Trust: T5 is reverse-scored.",
        "- Pairwise Wilcoxon p-values use Holm–Bonferroni within each metric.",
        "- McNemar uses an exact binomial test; Holm correction across pairs.",
        "- Friedman requires at least three complete participant triples.",
        "- Missing values are reported, not imputed.",
        "",
    ]
    return "\n".join(lines) + "\n", inferential


def selftest() -> int:
    if sps is None:
        print("SciPy is required for --selftest", file=sys.stderr)
        return 2
    rng = random.Random(4220)
    rows = []
    base = {
        "password_totp": {"time": 18.0, "sus": 62, "tlx": 55, "trust": 2.8,
                          "security": 3.0, "success": 0.85, "rec": 24.0},
        "synced_passkey": {"time": 6.0, "sus": 84, "tlx": 28, "trust": 4.2,
                           "security": 4.3, "success": 0.97, "rec": 10.0},
        "hardware_key": {"time": 7.0, "sus": 80, "tlx": 32, "trust": 4.0,
                         "security": 4.2, "success": 0.95, "rec": 14.0},
    }
    for pid in range(1, 13):
        order = CONDITIONS[:]
        rng.shuffle(order)
        for rank, condition in enumerate(order, start=1):
            spec = base[condition]
            row = {
                "participant_id": f"P{pid:02d}",
                "condition": condition,
                "order": str(rank),
                "login_time_s": max(1.0, rng.gauss(spec["time"], 1.5)),
                "login_success": 1 if rng.random() < spec["success"] else 0,
                "errors": max(0, int(rng.gauss(0.4, 0.8))),
                "recovery_time_s": max(1.0, rng.gauss(spec["rec"], 3.0)),
                "recovery_success": 1 if rng.random() < 0.9 else 0,
                "preference_rank": rank,
            }
            for index in range(1, 11):
                # SUS = 12.5 * (mean_odd - mean_even) + 50.  Generate odd
                # and even items with different means so the synthetic SUS
                # lands near the target instead of collapsing to 50.
                odd_mean = 4.0
                even_mean = 4.0 - (spec["sus"] - 50) / 12.5
                mean = odd_mean if index % 2 == 1 else even_mean
                row[f"sus_{index}"] = max(1, min(5, round(
                    rng.gauss(mean, 0.5)
                )))
            for item in TLX_ITEMS:
                row[item] = max(0, min(100, rng.gauss(spec["tlx"], 8)))
            for index in range(1, 6):
                if index == 5:
                    # T5 is reverse-worded; generate a low raw value so the
                    # reverse-scored trust mean stays near the target.
                    row[f"trust_{index}"] = max(1, min(5, round(
                        6 - rng.gauss(spec["trust"], 0.6)
                    )))
                else:
                    row[f"trust_{index}"] = max(1, min(5, round(
                        rng.gauss(spec["trust"], 0.6)
                    )))
            for index in range(1, 5):
                row[f"security_{index}"] = max(1, min(5, round(
                    rng.gauss(spec["security"], 0.6)
                )))
            rows.append(row)

    # Reuse the normal scoring path by writing a temporary CSV.  The file is
    # deleted immediately; no synthetic data are left behind.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "selftest.csv")
        fields = list(rows[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        loaded = load_rows(path)
    report, _ = build_report(loaded, "SELFTEST — synthetic data, not real")
    print("SELFTEST ONLY — the following uses synthetic data.\n")
    print(report)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", help="responses CSV")
    parser.add_argument("--out", default="survey/results",
                        help="output directory (default: survey/results)")
    parser.add_argument("--selftest", action="store_true",
                        help="run on synthetic in-memory data")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if not args.input:
        parser.error("input CSV required (or use --selftest)")

    rows = load_rows(args.input)
    if not rows:
        print("No valid rows found. Check the condition values and headers.",
              file=sys.stderr)
        return 1

    report, inferential = build_report(rows, args.input)
    os.makedirs(args.out, exist_ok=True)
    report_path = os.path.join(args.out, "survey_report.md")
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write(report)
    csv_path = os.path.join(args.out, "inferential_tests.csv")
    fields = ["metric", "test", "a", "b", "stat", "p", "p_holm",
              "effect", "median_diff", "n", "both", "a_only", "b_only"]
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in inferential:
            writer.writerow(row)
    print(f"[+] wrote {report_path}")
    print(f"[+] wrote {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
