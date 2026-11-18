"""Analyses the ambiguous-case run.  Usage:  python analyze_ambiguous.py   (or --mock)

Labels: uses labels.csv (column labeller_label, filled by an independent labeller BEFORE the run).
If any label is missing it falls back to the design labels and says so in the summary."""
import argparse
import csv
import json
import math
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ORDER = ["RBA", "RAZTA-rules", "RAZTA-rules+regex", "RAZTA-models", "RAZTA-models+tighten", "RAZTA-models+bounded"]
PAIRS = [("RAZTA-rules", "RAZTA-models"), ("RAZTA-models", "RAZTA-models+tighten"),
         ("RAZTA-models", "RAZTA-models+bounded"), ("RAZTA-rules+regex", "RAZTA-models+bounded"),
         ("RBA", "RAZTA-models+bounded")]


def wilson(k, n, z=1.96):
    if n == 0:
        return 0, 0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h), min(1, c + h)


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def load_labels(rows):
    path = os.path.join(HERE, "labels.csv")
    design = {r["id"]: r["design_truth"] for r in rows}
    lab = {}
    if os.path.exists(path):
        for r in csv.DictReader(open(path, encoding="utf-8-sig")):
            col = next((k for k in r if k and k.startswith("labeller_label")), None)
            v = (r.get(col) or "").strip().lower() if col else ""
            if v in ("allow", "deny"):
                lab[r["id"]] = v
    if set(lab) >= set(design):
        agree = sum(lab[i] == design[i] for i in design)
        return lab, f"independent labeller (agreement with design labels: {agree}/{len(design)})"
    return design, "DESIGN labels (labels.csv not filled in yet - fill it before reporting)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true")
    a = ap.parse_args()
    d = os.path.join(HERE, "results_ambiguous_mock" if a.mock else "results_ambiguous")
    latest = {}
    for line in open(os.path.join(d, "raw.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        latest[(r["system"], r["id"])] = r
    rows = list(latest.values())
    truth, label_src = load_labels(rows)
    systems = [s for s in ORDER if any(r["system"] == s for r in rows)]
    ids = sorted({r["id"] for r in rows})
    by = {s: {r["id"]: r for r in rows if r["system"] == s} for s in systems}

    lines = ["# Ambiguous-case experiment: results", "", f"Labels used: {label_src}", "",
             "| System | Correct | 95% CI | Wrongly allowed (should be refused) | Wrongly refused (should be allowed) |",
             "|---|---|---|---|---|"]
    stats = {}
    for s in systems:
        rr = by[s]
        ok = [i for i in ids if i in rr and rr[i]["decision"] == truth[i]]
        fa = [i for i in ids if i in rr and truth[i] == "deny" and rr[i]["decision"] == "allow"]
        fr = [i for i in ids if i in rr and truth[i] == "allow" and rr[i]["decision"] == "deny"]
        lo, hi = wilson(len(ok), len(rr))
        stats[s] = dict(ok=set(ok), fa=fa, fr=fr, n=len(rr))
        lines.append(f"| {s} | {len(ok)}/{len(rr)} | {lo:.2f}-{hi:.2f} | {len(fa)} {fa or ''} | {len(fr)} {fr or ''} |")

    lines += ["", "## Paired comparisons (exact McNemar test on the same 16 cases)", "",
              "| A | B | A right, B wrong | B right, A wrong | p |", "|---|---|---|---|---|"]
    for x, y in PAIRS:
        if x in stats and y in stats:
            b = len(stats[x]["ok"] - stats[y]["ok"])
            c = len(stats[y]["ok"] - stats[x]["ok"])
            lines.append(f"| {x} | {y} | {b} | {c} | {mcnemar_exact(b, c):.3f} |")

    lines += ["", "## Case by case", "", "| Case | Label | " + " | ".join(systems) + " |",
              "|---|---|" + "---|" * len(systems)]
    for i in ids:
        cells = []
        for s in systems:
            r = by[s].get(i)
            if not r:
                cells.append("-")
                continue
            mark = "ok" if r["decision"] == truth[i] else "WRONG"
            cells.append(f"{r['decision']} ({r.get('band') or '-'}) {mark}")
        lines.append(f"| {i} | {truth[i]} | " + " | ".join(cells) + " |")

    js = [r for r in rows if r["system"].startswith("RAZTA-models+") and r.get("just_claim") is not None]
    if js:
        lines += ["", "## What the justification agent extracted (model) and what code found", "",
                  "| Case | Mode | Claim | Ref | Record check | Red flags | Assessment | Plausibility | Band change |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for r in sorted(js, key=lambda r: (r["id"], r["system"])):
            lines.append(f"| {r['id']} | {r['system'].split('+')[1]} | {r['just_claim']} | {r.get('just_ref') or ''} | "
                         f"{r['just_verification']} | {r.get('just_flags') or ''} | {r.get('just_assessment')} | "
                         f"{r.get('just_plausibility')} | {r.get('just_adjust'):+d}"
                         + (" (screened: instructions in text)" if r.get("just_injection") else "") + " |")

    lat = [r["latency_s"] for r in rows if r["system"].startswith("RAZTA-models") and r.get("latency_s")]
    if lat:
        lines += ["", f"Mean decision time with models: {sum(lat) / len(lat):.1f} s (n = {len(lat)})."]
    metas = [json.loads(l) for l in open(os.path.join(d, "run_meta.jsonl"), encoding="utf-8")] \
        if os.path.exists(os.path.join(d, "run_meta.jsonl")) else []
    if metas:
        lines += ["", "Run log: " + "; ".join(f"{m['finished']} LLM calls {m['llm_calls']}, cache hits "
                                               f"{m['llm_cache_hits']}, degraded {m['degraded']}" for m in metas)]
    open(os.path.join(d, "summary.md"), "w", encoding="utf-8").write("\n".join(lines) + "\n")

    with open(os.path.join(d, "table.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "label"] + systems)
        for i in ids:
            w.writerow([i, truth[i]] + [by[s].get(i, {}).get("decision", "") for s in systems])

    os.makedirs(os.path.join(d, "charts"), exist_ok=True)
    fig, ax = plt.subplots(figsize=(8, 3.6))
    xs = range(len(systems))
    ax.bar([x - 0.2 for x in xs], [len(stats[s]["fa"]) for s in systems], 0.4, label="Attacks let in", color="#c0392b")
    ax.bar([x + 0.2 for x in xs], [len(stats[s]["fr"]) for s in systems], 0.4, label="Staff refused", color="#e8833a")
    ax.set_xticks(list(xs))
    ax.set_xticklabels([s.replace("RAZTA-", "R-") for s in systems], rotation=20, ha="right", fontsize=8)
    ax.set_ylabel("Errors (of 8 each)")
    ax.yaxis.get_major_locator().set_params(integer=True)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(d, "charts", "ambiguous_errors.png"), dpi=200)
    print("\n".join(lines))
    print(f"\nSaved {d}/summary.md, table.csv and charts/ambiguous_errors.png")


if __name__ == "__main__":
    main()
