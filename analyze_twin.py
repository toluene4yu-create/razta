"""Summarises the twin-challenge experiment (Increment 7).

Usage:  python analyze_twin.py          (real run)
        python analyze_twin.py --mock   (plumbing test)
Writes results_twin/summary.md, summary_A.csv, summary_B.csv, answers.csv, twin_partA.png, twin_partB.png
"""
import argparse
import csv
import json
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ORDER_A = ["C0", "C1", "C2", "C3", "C4"]
ORDER_C = ["PC-C1", "PC-C2", "PC-C4"]
ORDER_B = ["B-rule", "B-model", "B-hybrid"]
NAMES = {"C0": "No twin challenge", "C1": "Twin, rule judge", "C2": "Twin, model judge",
         "C3": "Twin, model judge, guards off", "C4": "Twin, hybrid judge", "B-rule": "Rule judge",
         "B-model": "Model judge", "B-hybrid": "Hybrid judge", "PC-C1": "Fresh set, rule judge",
         "PC-C2": "Fresh set, model judge", "PC-C4": "Fresh set, hybrid judge"}


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0, c - h) * 100, 1), round(min(1, c + h) * 100, 1))


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return round(min(1.0, 2 * p), 4)


def part_summary(md, A, order, title, outdir, csvname):
    sumA = []
    by = {c: {r["id"]: r for r in A if r["condition"] == c} for c in order}
    for c in order:
        rs = list(by[c].values())
        if not rs:
            continue
        legit = [r for r in rs if r["truth"] == "allow"]
        att = [r for r in rs if r["truth"] == "deny"]
        li = sum(r["decision"] == "allow" for r in legit)
        ai = sum(r["decision"] == "allow" for r in att)
        lat = [r["latency_s"] for r in rs if r["latency_s"]]
        q = [r["questions"] for r in rs if r["questions"]]
        by_actor = {}
        for r in att:
            k = r["actor"] + ("_simswap" if "SIM swap" in r["note"] else "")
            by_actor.setdefault(k, [0, 0])
            by_actor[k][0] += r["decision"] == "allow"
            by_actor[k][1] += 1
        s = dict(condition=c, name=NAMES[c], n=len(rs),
                 correct=sum((r["decision"] == "allow") == (r["truth"] == "allow") for r in rs),
                 legit_admitted=li, legit=len(legit), FRR_pct=round(100 * (len(legit) - li) / max(1, len(legit)), 1),
                 FRR_CI=wilson(len(legit) - li, len(legit)),
                 attacks_admitted=ai, attacks=len(att), FAR_pct=round(100 * ai / max(1, len(att)), 1),
                 FAR_CI=wilson(ai, len(att)),
                 by_attacker="; ".join(f"{k} {v[0]}/{v[1]} admitted" for k, v in sorted(by_actor.items())),
                 mean_questions=round(sum(q) / len(q), 2) if q else 0,
                 mean_latency_s=round(sum(lat) / len(lat), 1) if lat else None,
                 injections_flagged=sum(r["twin_injection_flagged"] for r in rs),
                 questions_rejected=sum(bool(r["question_rejected"]) for r in rs),
                 refused_legit="|".join(r["id"] for r in legit if r["decision"] != "allow"),
                 admitted_attacks="|".join(r["id"] for r in att if r["decision"] == "allow"))
        sumA.append(s)
    if sumA:
        with open(os.path.join(outdir, csvname), "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(sumA[0]))
            w.writeheader()
            w.writerows(sumA)
        md += [title, "",
               "| Condition | Correct | Legitimate admitted | Attacks admitted | Questions per attempt | Mean time (s) |",
               "|---|---|---|---|---|---|"]
        for s in sumA:
            md.append(f"| {s['name']} | {s['correct']}/{s['n']} | {s['legit_admitted']}/{s['legit']} "
                      f"(FRR {s['FRR_pct']}%, CI {s['FRR_CI'][0]}-{s['FRR_CI'][1]}) | {s['attacks_admitted']}/{s['attacks']} "
                      f"(FAR {s['FAR_pct']}%, CI {s['FAR_CI'][0]}-{s['FAR_CI'][1]}) | {s['mean_questions']} | {s['mean_latency_s']} |")
        md.append("")
        for s in sumA:
            md.append(f"- **{s['name']}**: by attacker: {s['by_attacker'] or 'n/a'}; legitimate refused: "
                      f"{s['refused_legit'] or 'none'}; attacks admitted: {s['admitted_attacks'] or 'none'}; "
                      f"injections screened: {s['injections_flagged']}; model questions replaced by template: "
                      f"{s['questions_rejected']}")
        md.append("")
        pairs = [(x, y) for x, y in [("C0", "C2"), ("C1", "C2"), ("C2", "C3"), ("C2", "C4"), ("C1", "C4"), ("PC-C1", "PC-C2"), ("PC-C2", "PC-C4"), ("PC-C1", "PC-C4")] if x in order and y in order]
        md.append("Paired exact McNemar tests on correct/incorrect per attempt:")
        for x, y in pairs:
            if by[x] and by[y]:
                ids = set(by[x]) & set(by[y])
                ok = lambda r: (r["decision"] == "allow") == (r["truth"] == "allow")
                b = sum(ok(by[x][i]) and not ok(by[y][i]) for i in ids)
                cc = sum(not ok(by[x][i]) and ok(by[y][i]) for i in ids)
                md.append(f"- {NAMES[x]} vs {NAMES[y]}: {b} attempts only the first got right, {cc} only the second; "
                          f"p = {mcnemar_exact(b, cc)}")
        md.append("")

    return sumA


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--dir", default="results_twin2", help="results folder (run 1 is results_twin)")
    a = ap.parse_args()
    outdir = os.path.join(HERE, a.dir + ("_mock" if a.mock else ""))
    rows = {}
    for line in open(os.path.join(outdir, "raw.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        rows[(r["condition"], r["id"])] = r                       # last row wins if rerun
    rows = list(rows.values())
    C = [r for r in rows if r["part"] == "C"]
    A = [r for r in rows if r["part"] == "A"]
    B = [r for r in rows if r["part"] == "B"]
    md = ["# Twin-challenge experiment (Increment 7)", ""]

    sumA = part_summary(md, A, ORDER_A, "## Part A: 28 access attempts on day 30 (14 legitimate, 14 attacks)", outdir, "summary_A.csv")
    sumC = part_summary(md, C, ORDER_C, "## Part C: FRESH held-out set, 30 attempts (15 legitimate, 15 attacks)", outdir, "summary_C.csv")
    # ---------------- answers (judge level): the same answers judged by the rule and by the model
    ans = []
    for r in A + B + C:
        for i, e in enumerate(r.get("twin_log") or []):
            should = "accept" if r["actor"] == "self" else "reject"
            ans.append(dict(condition=r["condition"], id=r["id"], actor=r["actor"], style=r["style"], fact=e["fact"],
                            question=e["question"], answer=e["answer"], verdict=e["verdict"],
                            rule_verdict=e["rule_verdict"], should=should, injected=e["injected"]))
    if ans:
        with open(os.path.join(outdir, "answers.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(ans[0]))
            w.writeheader()
            w.writerows(ans)
        md += ["## Answers judged (each answer typed at a twin question)", "",
               "| Condition | Answers | Real user's answer accepted | Attacker's answer accepted | Real user said 'unsure' |",
               "|---|---|---|---|---|"]
        for c in ORDER_A + ORDER_C + ORDER_B:
            xs = [x for x in ans if x["condition"] == c]
            if not xs:
                continue
            le = [x for x in xs if x["should"] == "accept" and not x["answer"].lower().startswith("sorry")]
            at = [x for x in xs if x["should"] == "reject"]
            un = [x for x in xs if x["should"] == "accept" and x["verdict"] == "unsure"]
            md.append(f"| {NAMES[c]} | {len(xs)} | {sum(x['verdict'] == 'match' for x in le)}/{len(le)} | "
                      f"{sum(x['verdict'] == 'match' for x in at)}/{len(at)} | {len(un)} |")
        md.append("")
        md.append("By answer style (real users):")
        for st in ("exact", "paraphrase", "terse", "local", "forgot", "typos", "wrong_day"):
            for c in ("C1", "C2", "C4", "PC-C1", "PC-C2", "PC-C4"):
                xs = [x for x in ans if x["condition"] == c and x["style"] == st and x["should"] == "accept"
                      and not x["answer"].lower().startswith("sorry")]
                if xs:
                    md.append(f"- {st:10s} {NAMES[c]}: {sum(x['verdict'] == 'match' for x in xs)}/{len(xs)} accepted")
        md.append("")

    # ---------------- Part B
    sumB = []
    for c in ORDER_B:
        rs = sorted([r for r in B if r["condition"] == c], key=lambda r: (r["day"], r["id"]))
        for day in sorted({r["day"] for r in rs}):
            d = [r for r in rs if r["day"] == day]
            lg = [r for r in d if r["truth"] == "allow"]
            at = [r for r in d if r["truth"] == "deny"]
            sumB.append(dict(condition=c, day=day, legit_admitted=sum(r["decision"] == "allow" for r in lg),
                             legit=len(lg), attacks_admitted=sum(r["decision"] == "allow" for r in at), attacks=len(at),
                             memory_question_asked=sum("last_task" in [e["fact"] for e in r["twin_log"]] for r in d),
                             twin_items_stored=sum(bool(r["twin_stored"]) for r in d),
                             poisoned=sum(bool(r["twin_stored"]) for r in at)))
    if sumB:
        with open(os.path.join(outdir, "summary_B.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(sumB[0]))
            w.writeheader()
            w.writerows(sumB)
        md += ["## Part B: the twin grows over eight days (3 users, attacks on days 31, 34, 37)", "",
               "| Judge | Legitimate logins admitted | Attacks admitted | Memory question used | Twin entries stored | "
               "Twin poisoned by an attacker |", "|---|---|---|---|---|---|"]
        for c in ORDER_B:
            xs = [s for s in sumB if s["condition"] == c]
            if xs:
                md.append(f"| {NAMES[c]} | {sum(s['legit_admitted'] for s in xs)}/{sum(s['legit'] for s in xs)} | "
                          f"{sum(s['attacks_admitted'] for s in xs)}/{sum(s['attacks'] for s in xs)} | "
                          f"{sum(s['memory_question_asked'] for s in xs)} | {sum(s['twin_items_stored'] for s in xs)} | "
                          f"{sum(s['poisoned'] for s in xs)} |")
        md.append("")
        md.append("Day by day (legitimate admitted / attacks admitted):")
        for c in ORDER_B:
            xs = [s for s in sumB if s["condition"] == c]
            if xs:
                md.append(f"- {NAMES[c]}: " + ", ".join(
                    f"day {s['day']}: {s['legit_admitted']}/{s['legit']}" + (f", atk {s['attacks_admitted']}/{s['attacks']}" if s["attacks"] else "")
                    for s in xs))
        md.append("")
    meta_p = os.path.join(outdir, "run_meta.json")
    if os.path.exists(meta_p):
        meta = json.load(open(meta_p))
        md += ["## Run", "", f"- Local models: {meta.get('slm_models')}", f"- Global models: {meta.get('llm_models')}",
               f"- API calls: {meta.get('llm_calls')}, cache hits: {meta.get('llm_cache_hits')}, degraded steps: "
               f"{meta.get('degraded_llm_steps')}, substitutions: {meta.get('substitutions')}",
               f"- Wall clock: {meta.get('wall_clock_min')} min, finished {meta.get('finished')}", ""]
    open(os.path.join(outdir, "summary.md"), "w", encoding="utf-8").write("\n".join(md))
    print("\n".join(md))
    charts(outdir, sumA, sumB, sumC)
    print(f"\nSaved in {outdir}")


def charts(outdir, sumA, sumB, sumC=None):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib not installed: charts skipped)")
        return
    for sumA, fname, ttl in ((sumA, "twin_partA.png", "Part A: twin-based personal challenge (28 attempts)"),
                             (sumC, "twin_partC.png", "Part C: fresh held-out set (30 attempts)")):
      if sumA:
        fig, ax = plt.subplots(figsize=(9, 4.2), dpi=200)
        x = range(len(sumA))
        lg = [100 * s["legit_admitted"] / s["legit"] for s in sumA]
        at = [100 * s["attacks_admitted"] / s["attacks"] for s in sumA]
        ax.bar([i - 0.2 for i in x], lg, 0.4, color="#1F6F54", label="Legitimate users admitted (%)")
        ax.bar([i + 0.2 for i in x], at, 0.4, color="#B23A3A", label="Attacks admitted (%)")
        for i in x:
            ax.text(i - 0.2, lg[i] + 1.5, f"{sumA[i]['legit_admitted']}/{sumA[i]['legit']}", ha="center", fontsize=8)
            ax.text(i + 0.2, at[i] + 1.5, f"{sumA[i]['attacks_admitted']}/{sumA[i]['attacks']}", ha="center", fontsize=8)
        ax.set_xticks(list(x))
        ax.set_xticklabels([s["name"] for s in sumA], fontsize=8)
        ax.set_ylim(0, 110)
        ax.spines[["top", "right"]].set_visible(False)
        ax.legend(frameon=False, fontsize=8, loc="upper center", ncol=2)
        ax.set_title(ttl, fontsize=10, loc="left")
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, fname))
        plt.close(fig)
    if sumB:
        fig, ax = plt.subplots(figsize=(9, 3.8), dpi=200)
        for c, col in (("B-rule", "#6E7F77"), ("B-model", "#3E5C76"), ("B-hybrid", "#1F6F54")):
            xs = [s for s in sumB if s["condition"] == c]
            if xs:
                ax.plot([s["day"] for s in xs], [s["legit_admitted"] for s in xs], marker="o", color=col,
                        label=f"{NAMES[c]}: legitimate admitted (of 3)")
                ax.plot([s["day"] for s in xs if s["attacks"]], [s["attacks_admitted"] for s in xs if s["attacks"]],
                        marker="x", ls="--", color=col, label=f"{NAMES[c]}: attacks admitted (of 3)")
        ax.set_ylim(-0.2, 3.4)
        ax.set_xlabel("day")
        ax.spines[["top", "right"]].set_visible(False)
        ax.legend(frameon=False, fontsize=7)
        ax.set_title("Part B: the twin grows from an empty memory", fontsize=10, loc="left")
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, "twin_partB.png"))
        plt.close(fig)


if __name__ == "__main__":
    main()
