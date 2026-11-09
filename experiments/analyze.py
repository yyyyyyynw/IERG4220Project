"""Turn ``experiments/results/results.json`` into tables, CIs, and figures.

Run after the experiment suite::

    python experiments/analyze.py

Outputs
-------
experiments/results/scenarios.csv
experiments/results/latency.csv
experiments/results/summary.md
experiments/results/latency.md
experiments/results/klm.md
experiments/results/analysis.json
figures/phishing.png
figures/replay_recovery.png
figures/latency.png
figures/totp_window.png
figures/klm.png
"""
from __future__ import annotations

import csv
import json
import math
import os
import statistics as stats

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS = os.path.join(HERE, "results")
FIGURES = os.path.join(ROOT, "figures")
RESULT_JSON = os.path.join(RESULTS, "results.json")

# How to read the raw "successes" counter for each scenario.
#   attack_success  : higher rate = worse (attacker won)
#   defense_blocked : higher rate = better (attack or misuse was stopped)
#   task_success    : higher rate = better (legitimate user completed task)
#   characterization: neither good nor bad; describes a property
DIRECTION = {
    "P1": "attack_success",
    "P1b": "defense_blocked",
    "P1c": "defense_blocked",
    "P1d": "attack_success",
    "P2": "defense_blocked",
    "P3": "defense_blocked",
    "P4": "attack_success",
    "P5": "defense_blocked",
    "P6": "defense_blocked",
    "P7": "attack_success",
    "R1": "defense_blocked",
    "R2": "characterization",
    "R3": "defense_blocked",
    "R4": "defense_blocked",
    "R5": "defense_blocked",
    "R6": "attack_success",
    "R7": "task_success",
    "S1": "task_success",
    "S2": "characterization",
    "S3": "characterization",
    "S4": "task_success",
    "S5": "task_success",
    "S6": "defense_blocked",
    "S7": "defense_blocked",
    "S8": "defense_blocked",
}

LABELS = {
    "P1": "Password + TOTP relay",
    "P1b": "Replay phished TOTP",
    "P1c": "Expired TOTP",
    "P1d": "Naive TOTP double use",
    "P2": "Passkey, lookalike RP ID",
    "P3": "Passkey, strict origin relay",
    "P4": "Passkey, permissive origin relay",
    "P5": "Hardware, lookalike RP ID",
    "P6": "Hardware, strict origin relay",
    "P7": "Hardware, permissive origin relay",
    "R1": "TOTP replay policy",
    "R2": "TOTP time window",
    "R3": "Passkey assertion replay",
    "R4": "Hardware assertion replay",
    "R5": "Hardware counter regression",
    "R6": "Hardware forged high counter",
    "R7": "Synced passkey counter policy",
    "S1": "Synced passkey restore",
    "S2": "Platform credential loss",
    "S3": "Hardware key loss",
    "S4": "Hardware backup key",
    "S5": "Hardware recovery code",
    "S6": "Recovery code reuse",
    "S7": "Email reset invariants",
    "S8": "Expired reset token",
}

# These scenarios count "attack succeeded" in results.json, but their
# direction is defensive, so the reported metric is trials - successes.
DEFENSE_INVERTED = {"P1b", "P1c", "P2", "P3", "P5", "P6"}

METHODS = {
    "P1": "password_totp", "P1b": "password_totp", "P1c": "password_totp",
    "P1d": "password_totp", "P2": "synced_passkey", "P3": "synced_passkey",
    "P4": "synced_passkey", "P5": "hardware_key", "P6": "hardware_key",
    "P7": "hardware_key", "R1": "password_totp", "R2": "password_totp",
    "R3": "synced_passkey", "R4": "hardware_key", "R5": "hardware_key",
    "R6": "hardware_key", "R7": "synced_passkey", "S1": "synced_passkey",
    "S2": "synced_passkey", "S3": "hardware_key", "S4": "hardware_key",
    "S5": "hardware_key", "S6": "all", "S7": "all", "S8": "all",
}

METHOD_LABEL = {
    "password_totp": "Password + TOTP",
    "synced_passkey": "Synced passkey",
    "hardware_key": "Hardware FIDO2 key",
    "all": "All methods",
}

COLORS = {
    "password_totp": "#d97706",
    "synced_passkey": "#2563eb",
    "hardware_key": "#059669",
    "all": "#6b7280",
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 0.0)
    phat = k / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def pct(k: int, n: int) -> str:
    if n == 0:
        return "n/a"
    return f"{k}/{n} ({100 * k / n:.0f}%)"


def interpretation(scenario: dict) -> str:
    sid = scenario["id"]
    direction = DIRECTION.get(sid, "characterization")
    k = scenario["successes"]
    n = scenario["trials"]
    special = {
        "R2": "Only offsets −1, 0, +1 were accepted; ±2 were rejected.",
        "P1d": "Without server-side replay state the same code worked twice (5/5).",
        "R6": "A forged counter above the stored value was accepted (3/3); "
              "counter checks catch only lagging clones.",
        "R7": "The synced credential was accepted under the relaxed counter policy.",
        "S2": "No credential remained; login was impossible in all trials.",
        "S3": "No credential remained; login was impossible in all trials.",
        "S6": "The second use of the recovery code was rejected in all trials.",
    }
    if sid in special:
        return special[sid]
    if direction == "attack_success":
        return f"Attack succeeded {pct(k, n)}; lower is better."
    if direction == "defense_blocked":
        return f"Defence held in {pct(k, n)}; higher is better."
    if direction == "task_success":
        return f"Task completed in {pct(k, n)}; higher is better."
    return f"Observation recorded {pct(k, n)}."


def build_scenarios(data: dict) -> list[dict]:
    rows = []
    for scenario in data["scenarios"]:
        sid = scenario["id"]
        raw_k, n = scenario["successes"], scenario["trials"]
        direction = DIRECTION.get(sid, "characterization")
        if sid == "R2":
            # Five offsets were probed and all five behaved as specified.
            k = n = 5
        elif sid in DEFENSE_INVERTED:
            k = n - raw_k
        else:
            k = raw_k
        lo, hi = wilson(k, n)
        rows.append({
            "id": sid,
            "label": LABELS.get(sid, scenario.get("name", sid)),
            "category": scenario.get("category", ""),
            "method": METHODS.get(sid, scenario.get("method", "")),
            "method_label": METHOD_LABEL.get(
                METHODS.get(sid, scenario.get("method", "")), ""),
            "direction": direction,
            "trials": n,
            "successes": k,
            "raw_successes": raw_k,
            "rate": round(k / n, 4) if n else None,
            "wilson_low": round(lo, 4),
            "wilson_high": round(hi, 4),
            "mean_ms": scenario.get("mean_ms"),
            "median_ms": scenario.get("median_ms"),
            "interpretation": interpretation({**scenario, "successes": k}),
        })
    return rows


def write_scenarios_csv(rows: list[dict]) -> None:
    path = os.path.join(RESULTS, "scenarios.csv")
    fields = ["id", "label", "category", "method", "method_label", "direction",
              "trials", "successes", "raw_successes", "rate", "wilson_low",
              "wilson_high", "mean_ms", "median_ms", "interpretation"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fields})


def summary_markdown(rows: list[dict], data: dict) -> str:
    lines = [
        "# Controlled experiment results",
        "",
        f"Generated from `experiments/results/results.json` "
        f"({data['meta']['environment']['date_utc']}).",
        "",
        "Rates are security-relevant outcomes with 95% Wilson intervals. "
        "For defensive probes the observed metric is trials − attack "
        "successes. `Direction` states whether a higher rate is desirable.",
        "",
        "| ID | Scenario | Method | Observed | 95% CI | Direction | Reading |",
        "| --- | --- | --- | ---: | --- | --- | --- |",
    ]
    for row in rows:
        ci = f"{row['wilson_low']:.2f}–{row['wilson_high']:.2f}"
        direction = {
            "attack_success": "lower better",
            "defense_blocked": "higher better",
            "task_success": "higher better",
            "characterization": "descriptive",
        }[row["direction"]]
        lines.append(
            f"| {row['id']} | {row['label']} | {row['method_label']} | "
            f"{pct(row['successes'], row['trials'])} | {ci} | {direction} | "
            f"{row['interpretation']} |"
        )

    lines += ["", "## TOTP acceptance window (R2)", "",
              "| Offset (30 s steps) | Accepted | Rate |", "| ---: | ---: | ---: |"]
    for detail in next(s for s in data["scenarios"] if s["id"] == "R2")["details"]:
        lines.append(
            f"| {detail['offset_steps']:+d} | "
            f"{detail['accepted']}/{detail['trials']} | "
            f"{100 * detail['rate']:.0f}% |"
        )

    lines += ["", "## Error paths (U2)", "",
              "| Probe | Method | Blocked | Median latency | Feedback |",
              "| --- | --- | ---: | ---: | --- |"]
    grouped: dict[str, list[dict]] = {}
    for trial in data["error_paths"]["trials"]:
        grouped.setdefault(trial["name"], []).append(trial)
    for name, trials in grouped.items():
        blocked = sum(1 for t in trials if t.get("blocked"))
        times = [t["elapsed_ms"] for t in trials if t.get("elapsed_ms")]
        lines.append(
            f"| {name} | {METHOD_LABEL.get(trials[0]['method'], trials[0]['method'])} | "
            f"{blocked}/{len(trials)} | "
            f"{stats.median(times):.0f} ms | {trials[0].get('status', '')} |"
        )

    lines += ["", "## Protocol checks", ""]
    for key, value in data["protocol_checks"].items():
        lines.append(f"- `{key}`: `{value}`")
    return "\n".join(lines) + "\n"


def latency_stats(samples: dict) -> list[dict]:
    rows = []
    for name, values in samples.items():
        clean = sorted(values)
        n = len(clean)
        if n == 0:
            continue
        mean = stats.mean(clean)
        sd = stats.stdev(clean) if n > 1 else 0.0
        p95 = clean[min(n - 1, int(math.ceil(0.95 * n)) - 1)]
        rows.append({
            "task": name,
            "n": n,
            "mean_ms": round(mean, 1),
            "median_ms": round(stats.median(clean), 1),
            "stdev_ms": round(sd, 1),
            "min_ms": round(clean[0], 1),
            "max_ms": round(clean[-1], 1),
            "p95_ms": round(p95, 1),
        })
    return rows


def write_latency(rows: list[dict]) -> None:
    path = os.path.join(RESULTS, "latency.csv")
    fields = ["task", "n", "mean_ms", "median_ms", "stdev_ms",
              "min_ms", "max_ms", "p95_ms"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def latency_markdown(rows: list[dict]) -> str:
    lines = [
        "# Instrumented ceremony latency",
        "",
        "Wall-clock time from the first page action to the successful "
        "dashboard redirect (login) or the enrolled confirmation "
        "(enrolment). Values are milliseconds, measured in headless Chrome "
        "with CDP virtual authenticators on loopback; they exclude human "
        "decision time and network latency beyond loopback.",
        "",
        "| Task | n | Mean | Median | SD | Min | Max | p95 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['task']} | {row['n']} | {row['mean_ms']:.0f} | "
            f"{row['median_ms']:.0f} | {row['stdev_ms']:.0f} | "
            f"{row['min_ms']:.0f} | {row['max_ms']:.0f} | "
            f"{row['p95_ms']:.0f} |"
        )
    lines += [
        "",
        "The enrolment figure is dominated by credential creation in Chrome's "
        "virtual authenticator (roughly 1 s here). It does **not** include the "
        "0.9 s wait the harness performs afterwards to let the page reload. "
        "The login ceremony itself is about 0.1 s. See "
        "`docs/experiment_design.md` for the full instrumentation boundary.",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# KLM analytic usability model
# ---------------------------------------------------------------------------
K = 0.20   # keystroke, average typist (Card, Moran & Newell)
P = 1.10   # pointing / click
H = 0.40   # hand move between devices
M = 1.35   # mental preparation
B = 1.00   # biometric or local PIN verification
EMAIL_DELIVERY = 30.0  # out-of-band email delivery, excluded from the sum


def klm_tasks(medians: dict[str, float]) -> list[dict]:
    """Analytic Keystroke-Level Model for one login (seconds)."""
    r = medians
    r_pw = r.get("password_totp_login", 0) / 1000
    r_pk = r.get("passkey_login", 0) / 1000
    r_hw = r.get("hardware_login", 0) / 1000
    r_rc = r.get("recovery_code_login", 0) / 1000
    r_em = r.get("recovery_email_reset", 0) / 1000

    tasks = [
        {
            "task": "Password + TOTP login",
            "operators": "2M + 3P + 36K + 2R",
            "estimate_s": 2 * M + 3 * P + 36 * K + 2 * r_pw,
            "notes": "10-char username, 20-char password, 6-digit code.",
        },
        {
            "task": "Synced passkey login",
            "operators": "M + P + B + R",
            "estimate_s": M + P + B + r_pk,
            "notes": "One tap, one biometric/PIN check, measured ceremony.",
        },
        {
            "task": "Hardware key login",
            "operators": "M + H + P + B + R",
            "estimate_s": M + H + P + B + r_hw,
            "notes": "Reach key, touch, local PIN/biometric (UV required).",
        },
        {
            "task": "Recovery-code login",
            "operators": "2M + H + 2P + 19K + R",
            "estimate_s": 2 * M + H + 2 * P + 19 * K + r_rc,
            "notes": "10-character username, 8-character code, one separator.",
        },
        {
            "task": "Email reset (happy path)",
            "operators": "3M + 2H + 3P + 50K + 2R",
            "estimate_s": 3 * M + 2 * H + 3 * P + 50 * K + 2 * r_em,
            "notes": (f"Excludes {EMAIL_DELIVERY:.0f} s assumed email "
                      "delivery; two 20-char password entries."),
        },
    ]
    for task in tasks:
        task["estimate_s"] = round(task["estimate_s"], 2)
        task["operators"] = task["operators"].replace(
            "R", "R (measured)"
        ) if task["task"].startswith("Password") else task["operators"]
    return tasks


def klm_markdown(tasks: list[dict]) -> str:
    lines = [
        "# Keystroke-Level Model (analytic usability estimate)",
        "",
        "This is an analytical model, **not** human-subject data. Operator "
        "times follow Card, Moran & Newell: M = 1.35 s, P = 1.10 s, "
        "K = 0.20 s, H = 0.40 s, B = 1.00 s. R is the measured ceremony "
        "median from this lab. The model assumes an experienced user and no "
        "errors.",
        "",
        "| Task | Operators | Estimate (s) | Assumptions |",
        "| --- | --- | ---: | --- |",
    ]
    for task in tasks:
        lines.append(
            f"| {task['task']} | `{task['operators']}` | "
            f"{task['estimate_s']:.1f} | {task['notes']} |"
        )
    lines += [
        "",
        "The email-reset row is the least comparable: real delivery latency "
        "is environmental and is reported separately from the model.",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------
def setup_style() -> None:
    plt.rcParams.update({
        "figure.dpi": 160,
        "savefig.dpi": 160,
        "font.size": 9,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.alpha": 0.25,
        "grid.linewidth": 0.6,
        "axes.titlesize": 10,
        "axes.titleweight": "bold",
        "figure.facecolor": "white",
    })


def save(fig, name: str) -> str:
    os.makedirs(FIGURES, exist_ok=True)
    path = os.path.join(FIGURES, name)
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return path


def fig_phishing(data: dict) -> None:
    ids = ["P1", "P2", "P3", "P4", "P5", "P6", "P7"]
    by_id = {s["id"]: s for s in data["scenarios"]}
    values = [100 * by_id[i]["successes"] / by_id[i]["trials"] for i in ids]
    colors = []
    for i in ids:
        method = METHODS[i]
        colors.append(COLORS[method])
    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    bars = ax.bar(range(len(ids)), values, color=colors, width=0.68)
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 2,
                f"{value:.0f}%", ha="center", va="bottom", fontsize=8)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Account takeover success (%)")
    ax.set_xticks(range(len(ids)))
    ax.set_xticklabels([
        "P1\npassword\nrelay", "P2\npasskey\nlookalike",
        "P3\npasskey\nstrict", "P4\npasskey\npermissive",
        "P5\nhardware\nlookalike", "P6\nhardware\nstrict",
        "P7\nhardware\npermissive",
    ], fontsize=7)
    ax.set_title("Phishing outcomes by verifier policy", pad=24)
    handles = [plt.Rectangle((0, 0), 1, 1, color=COLORS[m])
               for m in ("password_totp", "synced_passkey", "hardware_key")]
    ax.legend(handles, ["Password + TOTP", "Synced passkey",
                        "Hardware key"], frameon=False, fontsize=8,
              loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3)
    save(fig, "phishing.png")


def fig_replay_recovery(data: dict) -> None:
    by_id = {s["id"]: s for s in data["scenarios"]}

    def rate(sid: str) -> float:
        s = by_id[sid]
        k = s["successes"]
        if sid in DEFENSE_INVERTED:
            k = s["trials"] - k
        return 100 * k / s["trials"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.6, 3.4))

    replay_ids = ["P1b", "P1c", "R1", "R3", "R4", "R5"]
    replay_labels = ["TOTP\nreplay", "Expired\nTOTP", "TOTP\npolicy",
                     "Passkey\nreplay", "Hardware\nreplay",
                     "Counter\nregression"]
    vals = [rate(i) for i in replay_ids]
    bars = ax1.bar(range(len(vals)), vals, color="#334155", width=0.65)
    for bar, value in zip(bars, vals):
        ax1.text(bar.get_x() + bar.get_width() / 2, value + 2,
                 f"{value:.0f}%", ha="center", fontsize=7)
    ax1.set_ylim(0, 112)
    ax1.set_title("Replay defences held")
    ax1.set_ylabel("Trials defended (%)")
    ax1.set_xticks(range(len(vals)))
    ax1.set_xticklabels(replay_labels, fontsize=7)

    rec_ids = ["S1", "S2", "S3", "S4", "S5"]
    rec_labels = ["Synced\nrestore", "Platform\nlost\n(lockout)",
                  "Key\nlost\n(lockout)", "Backup\nkey", "Recovery\ncode"]
    vals2 = [rate(i) for i in rec_ids]
    colors2 = ["#2563eb", "#94a3b8", "#94a3b8", "#059669", "#059669"]
    bars2 = ax2.bar(range(len(vals2)), vals2, color=colors2, width=0.65)
    for bar, value in zip(bars2, vals2):
        ax2.text(bar.get_x() + bar.get_width() / 2, value + 2,
                 f"{value:.0f}%", ha="center", fontsize=7)
    ax2.set_ylim(0, 112)
    ax2.set_title("Recovery / loss outcomes")
    ax2.set_ylabel("Observed outcome (%)")
    ax2.set_xticks(range(len(vals2)))
    ax2.set_xticklabels(rec_labels, fontsize=7)
    fig.text(0.76, -0.02,
             "Grey bars show lockout rate (the loss outcome);\n"
             "coloured bars show successful recovery.",
             ha="center", va="top", fontsize=6.5, color="#475569")
    save(fig, "replay_recovery.png")


def fig_totp_window(data: dict) -> None:
    r2 = next(s for s in data["scenarios"] if s["id"] == "R2")
    offsets = [d["offset_steps"] for d in r2["details"]]
    rates = [100 * d["rate"] for d in r2["details"]]
    colors = ["#059669" if 0 < r == 100 else "#cbd5e1" for r in rates]
    fig, ax = plt.subplots(figsize=(4.2, 2.6))
    bars = ax.bar([str(o) for o in offsets], rates, color=colors, width=0.6)
    for bar, value in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 3,
                f"{value:.0f}%", ha="center", fontsize=8)
    ax.set_ylim(0, 112)
    ax.set_xlabel("Time-step offset (30 s)")
    ax.set_ylabel("Accepted (%)")
    ax.set_title("TOTP acceptance window")
    save(fig, "totp_window.png")


def fig_latency(latency_rows: list[dict]) -> None:
    keep = [
        ("password_totp_login", "Password+TOTP"),
        ("passkey_login", "Passkey"),
        ("hardware_login", "Hardware"),
        ("recovery_code_login", "Recovery code"),
    ]
    rows = {r["task"]: r for r in latency_rows}
    fig, ax = plt.subplots(figsize=(5.4, 2.8))
    xs = list(range(len(keep)))
    medians = [rows[k]["median_ms"] for k, _ in keep]
    lows = [rows[k]["median_ms"] - rows[k]["min_ms"] for k, _ in keep]
    highs = [rows[k]["max_ms"] - rows[k]["median_ms"] for k, _ in keep]
    colors = [COLORS[{"password_totp_login": "password_totp",
                      "passkey_login": "synced_passkey",
                      "hardware_login": "hardware_key",
                      "recovery_code_login": "all"}[k]]
              for k, _ in keep]
    ax.bar(xs, medians, color=colors, width=0.6)
    ax.errorbar(xs, medians, yerr=[lows, highs], fmt="none",
                ecolor="#0f172a", capsize=4, linewidth=1)
    ax.set_xticks(xs)
    ax.set_xticklabels([label for _, label in keep])
    ax.set_ylabel("Login time (ms)")
    ax.set_title("Measured login ceremony (median, min–max)")
    ax.set_ylim(0, max(m + h for m, h in zip(medians, highs)) * 1.18)
    for x, value, high in zip(xs, medians, highs):
        ax.text(x, value + high + 4, f"{value:.0f}",
                ha="center", fontsize=7)
    save(fig, "latency.png")


def fig_klm(tasks: list[dict]) -> None:
    fig, ax = plt.subplots(figsize=(5.6, 2.9))
    names = [t["task"] for t in tasks]
    values = [t["estimate_s"] for t in tasks]
    colors = ["#d97706", "#2563eb", "#059669", "#6b7280", "#ef4444"]
    bars = ax.barh(range(len(names)), values,
                   color=colors[:len(names)], height=0.62)
    for bar, value in zip(bars, values):
        ax.text(value + 0.3, bar.get_y() + bar.get_height() / 2,
                f"{value:.1f}s", va="center", fontsize=8)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels([n.replace(" login", "").replace(" (happy path)", "")
                        for n in names], fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Estimated task time (s)")
    ax.set_title("KLM analytic estimate (excludes human error)")
    save(fig, "klm.png")


def main() -> int:
    with open(RESULT_JSON, encoding="utf-8") as handle:
        data = json.load(handle)

    os.makedirs(RESULTS, exist_ok=True)
    setup_style()

    rows = build_scenarios(data)
    write_scenarios_csv(rows)
    with open(os.path.join(RESULTS, "summary.md"), "w", encoding="utf-8") as handle:
        handle.write(summary_markdown(rows, data))

    latency_rows = latency_stats(data["latency"]["samples"])
    write_latency(latency_rows)
    with open(os.path.join(RESULTS, "latency.md"), "w", encoding="utf-8") as handle:
        handle.write(latency_markdown(latency_rows))

    medians = {r["task"]: r["median_ms"] for r in latency_rows}
    tasks = klm_tasks(medians)
    with open(os.path.join(RESULTS, "klm.md"), "w", encoding="utf-8") as handle:
        handle.write(klm_markdown(tasks))

    analysis = {
        "generated_from": RESULT_JSON,
        "environment": data["meta"]["environment"],
        "scenarios": rows,
        "latency": latency_rows,
        "klm": tasks,
        "totp_window": next(
            s for s in data["scenarios"] if s["id"] == "R2"
        )["details"],
        "protocol_checks": data["protocol_checks"],
        "error_paths": data["error_paths"],
    }
    with open(os.path.join(RESULTS, "analysis.json"), "w",
              encoding="utf-8") as handle:
        json.dump(analysis, handle, indent=2)

    fig_phishing(data)
    fig_replay_recovery(data)
    fig_totp_window(data)
    fig_latency(latency_rows)
    fig_klm(tasks)

    print(f"[+] wrote {os.path.join(RESULTS, 'summary.md')}")
    print(f"[+] wrote {os.path.join(RESULTS, 'latency.md')}")
    print(f"[+] wrote {os.path.join(RESULTS, 'klm.md')}")
    print(f"[+] wrote {len(rows)} scenario rows")
    print(f"[+] wrote 5 figures to {FIGURES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
