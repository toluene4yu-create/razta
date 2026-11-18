"""Summarises the chaos experiment: availability, protection and fail-closed behaviour per condition.

Usage:  python analyze_chaos.py          (real run)
        python analyze_chaos.py --mock   (dry run)
Writes results_chaos/summary.csv, summary.md and chaos_overview.png
"""
import argparse
import csv
import json
import math
import os

from chaos import CONDITIONS

HERE = os.path.dirname(os.path.abspath(__file__))


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0, c - h) * 100, min(1, c + h) * 100)


def correct(r):
    if r["truth"] in ("continue", "terminate"):
        return r["decision"] == "allow" and (r["session_outcome"] or "continue") == r["truth"]
    return r["decision"] == r["truth"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true")
    a = ap.parse_args()
    outdir = os.path.join(HERE, "results_chaos_mock" if a.mock else "results_chaos")
    rows = [json.loads(l) for l in open(os.path.join(outdir, "raw.jsonl"), encoding="utf-8")]
    by = {}
    for r in rows:
        by.setdefault(r["condition"], {})[r["id"]] = r          # last row wins if a condition was rerun
    order = [c[0] for c in CONDITIONS if c[0] in by]
    desc = {c[0]: c[4] for c in CONDITIONS}
    summary = []
    for cid in order:
        rs = list(by[cid].values())
        legit = [r for r in rs if r["truth"] in ("allow", "continue", "terminate")]
        attacks = [r for r in rs if r["truth"] == "deny"]
        admitted = sum(r["decision"] == "allow" for r in legit)
        att_in = sum(r["decision"] == "allow" for r in attacks)
        hij = [r for r in rs if r["truth"] == "terminate"]
        ben = [r for r in rs if r["truth"] == "continue"]
        fc = sum(r["fail_closed"] for r in rs)
        deg = sum(bool(r["degraded_inputs"]) or r["llm_degraded"] for r in rs)
        lat = [r["latency_s"] for r in rs if r["latency_s"] is not None and r["category"] != "enumeration_probe"]
        s = dict(condition=cid, description=desc[cid], n=len(rs),
                 correct=sum(correct(r) for r in rs),
                 legit_admitted=admitted, legit=len(legit),
                 availability_pct=round(100 * admitted / max(1, len(legit)), 1),
                 availability_ci=" to ".join(f"{x:.1f}" for x in wilson(admitted, len(legit))),
                 attacks_admitted=att_in, attacks=len(attacks),
                 hijacks_ended=sum((r["session_outcome"] == "terminate") for r in hij), hijacks=len(hij),
                 benign_kept=sum((r["decision"] == "allow" and r["session_outcome"] == "continue") for r in ben),
                 benign=len(ben),
                 fail_closed=fc, fail_closed_pct=round(100 * fc / len(rs), 1),
                 sessions_suspended=sum(r["session_fault"] for r in rs),
                 degraded=deg, unhandled=sum(r["unhandled"] for r in rs),
                 mean_latency_s=round(sum(lat) / max(1, len(lat)), 1),
                 max_latency_s=round(max(lat), 1) if lat else 0)
        summary.append(s)
    with open(os.path.join(outdir, "summary.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        w.writeheader()
        w.writerows(summary)
    L = ["| Cond. | Fault | Correct | Legit. admitted | Attacks admitted | Hijacks ended | Benign kept | "
         "Refused, verification incomplete | Degraded | Mean time (s) |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    for s in summary:
        L.append(f"| {s['condition']} | {s['description']} | {s['correct']}/{s['n']} | {s['legit_admitted']}/{s['legit']} "
                 f"({s['availability_pct']}%) | {s['attacks_admitted']}/{s['attacks']} | {s['hijacks_ended']}/{s['hijacks']} | "
                 f"{s['benign_kept']}/{s['benign']} | {s['fail_closed']}/{s['n']} | {s['degraded']} | {s['mean_latency_s']} |")
    tot_un = sum(s["unhandled"] for s in summary)
    tot_att = sum(s["attacks_admitted"] for s in summary)
    L.append(f"\nUnhandled crashes across all conditions: {tot_un}. Attacks admitted across all fault conditions: "
             f"{sum(s['attacks_admitted'] for s in summary if s['condition'] != 'N0')}.")
    open(os.path.join(outdir, "summary.md"), "w", encoding="utf-8").write("\n".join(L))
    print("\n".join(L))
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        ids = [s["condition"] for s in summary]
        x = range(len(ids))
        fig, ax = plt.subplots(figsize=(12, 4.2))
        ax.bar([i - 0.27 for i in x], [s["availability_pct"] for s in summary], 0.27, label="legitimate requests admitted (%)",
               color="#2b6cd4")
        ax.bar(list(x), [100 * s["fail_closed"] / s["n"] for s in summary], 0.27,
               label="requests refused because verification could not complete (%)", color="#9aa0a6")
        ax.bar([i + 0.27 for i in x], [100 * s["attacks_admitted"] / max(1, s["attacks"]) for s in summary], 0.27,
               label="attacks admitted (%)", color="#d93025")
        ax.set_xticks(list(x))
        ax.set_xticklabels(ids)
        ax.set_ylim(0, 105)
        ax.set_ylabel("% of requests")
        ax.spines[["top", "right"]].set_visible(False)
        ax.legend(frameon=False, fontsize=9, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3)
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, "chaos_overview.png"), dpi=200)
        print("Chart written:", os.path.join(outdir, "chaos_overview.png"))
    except Exception as e:
        print("Chart skipped:", e)
    print(f"\nTotal unhandled crashes: {tot_un}; attacks admitted in all runs: {tot_att}")


if __name__ == "__main__":
    main()
