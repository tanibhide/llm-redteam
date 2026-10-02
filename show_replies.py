"""
Print the saved replies for one or more attacks, so you can read them
and check whether the automatic leak detector got them right.

Usage:
    python show_replies.py D07 E05
    python show_replies.py D07 --file results_day2.csv
"""

import argparse
import csv


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("attack_ids", nargs="+", help="attack ids to show, e.g. D07 E05")
    parser.add_argument("--file", default="results_day3.csv", help="results file to read")
    parser.add_argument("--chars", type=int, default=300, help="max characters of each reply to show")
    args = parser.parse_args()

    wanted = {a.upper() for a in args.attack_ids}
    with open(args.file, newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r["attack_id"] in wanted]

    if not rows:
        print(f"No rows found for {', '.join(sorted(wanted))} in {args.file}")
        return

    for attack_id in sorted(wanted):
        mine = [r for r in rows if r["attack_id"] == attack_id]
        if not mine:
            continue
        print("=" * 78)
        print(f"{attack_id}: {mine[0]['prompt']}")
        print("=" * 78)
        for r in mine:
            verdict = f"LEAKED ({r['leak_type']})" if r["leaked"] == "True" else "safe"
            reply = " ".join(r["reply"].split())[: args.chars]
            run = f" run {r['run']}" if "run" in r else ""
            print(f"\n[{r['model']}{run}] detector says: {verdict}")
            print(f"  {reply}")
        print()


if __name__ == "__main__":
    main()
