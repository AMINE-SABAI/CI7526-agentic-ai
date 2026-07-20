import json

with open("NIST_SP-800-53_rev5_catalog.json", encoding="utf-8") as f:
    data = json.load(f)

catalog = data["catalog"]
controls = []

for group in catalog.get("groups", []):
    family = group.get("title", "")
    for ctrl in group.get("controls", []):
        guidance = ""
        for part in ctrl.get("parts", []):
            if part.get("name") == "guidance" and part.get("prose"):
                guidance = part["prose"]
                break
        controls.append({
            "id": ctrl["id"].upper(),
            "family": family,
            "title": ctrl["title"],
            "guidance": guidance[:300]
        })

with open("nist_controls.json", "w", encoding="utf-8") as f:
    json.dump(controls, f, indent=2)

print(f"{len(controls)} controls extracted into nist_controls.json")