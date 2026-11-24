"""Step 1: build the matching worksheet from a reference and a generated model."""
import csv, json, sys
from pathlib import Path

CATEGORIES = ("assets", "vulnerabilities", "threats")


def load(path):
    with Path(path).open(encoding="utf-8") as f:
        return json.load(f)


def elements(model, category):
    return [{"id": i.get("id", ""), "description": i.get("description", "")}
            for i in model.get(category, [])]


def main():
    if len(sys.argv) != 3:
        print("usage: python3 make_worksheet.py <reference.json> <generated.json>")
        sys.exit(1)

    reference = load(sys.argv[1])
    generated = load(sys.argv[2])
    out = Path("worksheets") / f"{Path(sys.argv[2]).stem}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)

    rows = 0
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "generated_id", "generated_description",
                    "MATCH", "reference_options"])
        for cat in CATEGORIES:
            ref = elements(reference, cat)
            menu = " | ".join(f"{r['id']}: {r['description'][:45]}" for r in ref)
            for item in elements(generated, cat):
                w.writerow([cat, item["id"], item["description"], "", menu])
                rows += 1

    print(f"Worksheet written: {out}")
    print(f"{rows} generated elements to annotate.")
    print("Fill the MATCH column with a reference id or NONE, then run score.py")


if __name__ == "__main__":
    main()
