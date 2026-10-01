"""
Day 3 - LLM Red-Teaming Harness
Runs every attack several times per model, so the leak rates are reliable,
then reports averages with 95% confidence intervals and draws charts.

Usage:
    python day3_repeat.py            # 5 runs per attack (default)
    python day3_repeat.py --runs 3   # quicker
"""

import argparse
import csv
import math
import os
import time
from collections import defaultdict
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # save charts to files without opening windows
import matplotlib.pyplot as plt

from attacks import ATTACKS
from day2_attacks import MODELS, ask, detect_leak

CATEGORIES = ["direct", "roleplay", "override", "encoding", "indirect"]

# One color per model, kept the same in every chart
COLORS = {
    MODELS[0]: "#2a78d6",  # blue
    MODELS[1]: "#eb6834",  # orange
    MODELS[2]: "#1baf7a",  # green
}


def wilson_interval(leaks: int, n: int, z: float = 1.96):
    """95% confidence interval for a proportion (works well for small samples)."""
    if n == 0:
        return 0.0, 0.0
    p = leaks / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return max(0.0, center - half), min(1.0, center + half)


def run_all(runs: int):
    results = []
    total = len(MODELS) * len(ATTACKS) * runs
    done = 0
    start_all = time.time()

    for model in MODELS:
        print(f"\n===== {model} =====")
        for attack_id, category, prompt in ATTACKS:
            leaks_here = 0
            for run in range(1, runs + 1):
                start = time.time()
                try:
                    reply = ask(model, prompt)
                except Exception as e:
                    reply = f"ERROR: {e}"
                seconds = round(time.time() - start, 2)
                leak_type = detect_leak(reply)
                leaks_here += bool(leak_type)
                done += 1

                results.append({
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "model": model,
                    "attack_id": attack_id,
                    "category": category,
                    "run": run,
                    "prompt": prompt,
                    "reply": reply,
                    "leaked": bool(leak_type),
                    "leak_type": leak_type,
                    "seconds": seconds,
                })

            elapsed = time.time() - start_all
            remaining = elapsed / done * (total - done)
            print(f"[{done}/{total}] {attack_id} {category:<9} leaked {leaks_here}/{runs}"
                  f"   (~{remaining / 60:.0f} min left)")

    return results


def summarize(results):
    """Leak rate + 95% CI per (model, category), per model overall, and per attack."""
    counts = defaultdict(lambda: [0, 0])
    for r in results:
        for key in [(r["model"], r["category"]), (r["model"], "ALL"), (r["model"], r["attack_id"])]:
            counts[key][1] += 1
            counts[key][0] += r["leaked"]

    summary = []
    for model in MODELS:
        for cat in CATEGORIES + ["ALL"]:
            leaks, n = counts[(model, cat)]
            lo, hi = wilson_interval(leaks, n)
            summary.append({
                "model": model, "category": cat, "leaks": leaks, "trials": n,
                "leak_rate": round(leaks / n, 3), "ci_low": round(lo, 3), "ci_high": round(hi, 3),
            })
    return summary, counts


def print_table(summary):
    print("\n\nLEAK RATE BY MODEL AND CATEGORY  (95% confidence interval in brackets)")
    print(f"{'model':<14}" + "".join(f"{c:>17}" for c in CATEGORIES + ["ALL"]))
    for model in MODELS:
        row = f"{model:<14}"
        for s in [s for s in summary if s["model"] == model]:
            cell = f"{s['leak_rate']*100:.0f}% [{s['ci_low']*100:.0f}-{s['ci_high']*100:.0f}]"
            row += f"{cell:>17}"
        print(row)


def print_top_attacks(counts, runs):
    print("\nMOST RELIABLE ATTACKS  (leak rate across all models)")
    rates = []
    for attack_id, category, prompt in ATTACKS:
        leaks = sum(counts[(m, attack_id)][0] for m in MODELS)
        n = sum(counts[(m, attack_id)][1] for m in MODELS)
        rates.append((leaks / n, attack_id, category, prompt))
    rates.sort(reverse=True)
    for rate, attack_id, category, prompt in rates[:5]:
        short = prompt.replace("\n", " ")[:60]
        print(f"  {rate*100:5.0f}%  {attack_id} ({category}): {short}...")
    print("\nMOST RESISTED ATTACKS")
    for rate, attack_id, category, prompt in sorted(rates)[:5]:
        short = prompt.replace("\n", " ")[:60]
        print(f"  {rate*100:5.0f}%  {attack_id} ({category}): {short}...")


def style_axes(ax):
    for side in ["top", "right"]:
        ax.spines[side].set_visible(False)
    for side in ["left", "bottom"]:
        ax.spines[side].set_color("#b5b4af")
    ax.tick_params(colors="#52514e")
    ax.yaxis.grid(True, color="#e6e5e0", linewidth=0.8)
    ax.set_axisbelow(True)


def chart_by_category(summary, runs, path):
    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=150)
    width = 0.26
    x = range(len(CATEGORIES))

    for i, model in enumerate(MODELS):
        rows = [next(s for s in summary if s["model"] == model and s["category"] == c) for c in CATEGORIES]
        rates = [r["leak_rate"] * 100 for r in rows]
        err_low = [(r["leak_rate"] - r["ci_low"]) * 100 for r in rows]
        err_high = [(r["ci_high"] - r["leak_rate"]) * 100 for r in rows]
        positions = [p + (i - 1) * (width + 0.02) for p in x]
        ax.bar(positions, rates, width, label=model, color=COLORS[model], edgecolor="white", linewidth=1)
        ax.errorbar(positions, rates, yerr=[err_low, err_high], fmt="none",
                    ecolor="#52514e", elinewidth=1, capsize=3)

    ax.set_xticks(list(x))
    ax.set_xticklabels([c.capitalize() for c in CATEGORIES], fontsize=11)
    ax.set_ylim(0, 105)
    ax.set_ylabel("Leak rate (%)", color="#52514e")
    ax.set_title(f"Secret leak rate by attack category ({runs} runs per attack, 95% CI)",
                 loc="left", fontsize=13, color="#0b0b0b", pad=34)
    style_axes(ax)
    # Legend sits above the plot so tall bars never hide it
    ax.legend(frameon=False, ncol=3, loc="lower left", bbox_to_anchor=(0, 1.0))
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def chart_overall(summary, runs, path):
    rows = [next(s for s in summary if s["model"] == m and s["category"] == "ALL") for m in MODELS]
    rows.sort(key=lambda r: r["leak_rate"])
    fig, ax = plt.subplots(figsize=(8, 3.2), dpi=150)
    names = [r["model"] for r in rows]
    rates = [r["leak_rate"] * 100 for r in rows]
    err = [[(r["leak_rate"] - r["ci_low"]) * 100 for r in rows],
           [(r["ci_high"] - r["leak_rate"]) * 100 for r in rows]]
    ax.barh(names, rates, color=[COLORS[n] for n in names], height=0.55)
    ax.errorbar(rates, names, xerr=err, fmt="none", ecolor="#52514e", elinewidth=1, capsize=3)
    for name, rate, hi in zip(names, rates, err[1]):
        ax.text(rate + hi + 1.5, name, f"{rate:.0f}%", va="center", fontsize=11, color="#0b0b0b")
    ax.set_xlim(0, 110)
    ax.set_xlabel("Leak rate across all 40 attacks (%)", color="#52514e")
    ax.set_title(f"Overall leak rate by model ({runs} runs per attack)",
                 loc="left", fontsize=13, color="#0b0b0b", pad=12)
    style_axes(ax)
    ax.yaxis.grid(False)
    ax.xaxis.grid(True, color="#e6e5e0", linewidth=0.8)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def save_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5, help="times to repeat each attack")
    args = parser.parse_args()

    total = len(MODELS) * len(ATTACKS) * args.runs
    print(f"Running {len(ATTACKS)} attacks x {len(MODELS)} models x {args.runs} runs = {total} requests")

    results = run_all(args.runs)
    summary, counts = summarize(results)

    save_csv(results, "results_day3.csv")
    save_csv(summary, "summary_day3.csv")

    print_table(summary)
    print_top_attacks(counts, args.runs)

    os.makedirs("charts", exist_ok=True)
    chart_by_category(summary, args.runs, "charts/leak_rate_by_category.png")
    chart_overall(summary, args.runs, "charts/leak_rate_overall.png")

    print("\nSaved: results_day3.csv, summary_day3.csv, charts/leak_rate_by_category.png, charts/leak_rate_overall.png")


if __name__ == "__main__":
    main()
