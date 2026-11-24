"""Step 2: compute precision, recall and F1 from an annotated worksheet."""
import csv, json, sys
from pathlib import Path

CATEGORIES = ("assets", "vulnerabilities", "threats")


def load_reference(path):
    with Path(path).open(encoding="utf-8") as f:
        model = json.load(f)
    return {c: {i.get("id", "") for i in model.get(c, [])} for c in CATEGORIES}


def check(rows, ref_ids, src):
    problems = []
    for i, row in enumerate(rows, start=2):
        m = (row.get("MATCH") or "").strip()
        cat = row.get("category", "")
        if not m:
            problems.append(f"  line {i}: MATCH is empty")
        elif m.upper() != "NONE" and m not in ref_ids.get(cat, set()):
            problems.append(f"  line {i}: '{m}' is not a {cat} id in the reference")
    if problems:
        print(f"Worksheet {src} is not ready:")
        print("\n".join(problems[:20]))
        sys.exit(1)


def count(rows, ref_ids):
    out = {}
    for cat in CATEGORIES:
        matched, tp, fp = set(), 0, 0
        for row in [r for r in rows if r.get("category") == cat]:
            m = row["MATCH"].strip()
            if m.upper() == "NONE" or m in matched:
                fp += 1
            else:
                matched.add(m)
                tp += 1
        out[cat] = {"tp": tp, "fp": fp, "fn": len(ref_ids[cat] - matched)}
    return out


def metrics(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f1


def report(counts, label):
    print(f"\n=== {label} ===")
    print(f"{'category':<18}{'TP':>5}{'FP':>5}{'FN':>5}{'P':>9}{'R':>9}{'F1':>9}")
    print("-" * 60)
    total = {"tp": 0, "fp": 0, "fn": 0}
    for cat in CATEGORIES:
        c = counts[cat]
        p, r, f1 = metrics(c["tp"], c["fp"], c["fn"])
        print(f"{cat:<18}{c['tp']:>5}{c['fp']:>5}{c['fn']:>5}{p:>9.3f}{r:>9.3f}{f1:>9.3f}")
        for k in total:
            total[k] += c[k]
    p, r, f1 = metrics(total["tp"], total["fp"], total["fn"])
    print("-" * 60)
    print(f"{'OVERALL':<18}{total['tp']:>5}{total['fp']:>5}{total['fn']:>5}"
          f"{p:>9.3f}{r:>9.3f}{f1:>9.3f}")


def main():
    if len(sys.argv) < 3:
        print("usage: python3 score.py <reference.json> <worksheet.csv> [...]")
        sys.exit(1)
    ref_ids = load_reference(sys.argv[1])
    agg = {c: {"tp": 0, "fp": 0, "fn": 0} for c in CATEGORIES}
    sheets = sys.argv[2:]
    for sheet in sheets:
        with Path(sheet).open(encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        check(rows, ref_ids, sheet)
        counts = count(rows, ref_ids)
        report(counts, Path(sheet).stem)
        for c in CATEGORIES:
            for k in agg[c]:
                agg[c][k] += counts[c][k]
    if len(sheets) > 1:
        report(agg, f"AGGREGATE over {len(sheets)} runs")


if __name__ == "__main__":
    main()
