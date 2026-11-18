"""Turns raw_results.jsonl into tables, charts and a results summary for the paper.
Usage:  python analyze.py          (or  python analyze.py --mock  after a mock run)"""
import argparse
import csv
import json
import os
import statistics as st

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BLUE, ORANGE, GREY, RED = "#2a6fdb", "#e8833a", "#9aa0a6", "#c0392b"


def pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "n/a"


def p95(xs):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(0.95 * (len(xs) - 1))))] if xs else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true")
    a = ap.parse_args()
    d = os.path.join(HERE, "results_mock" if a.mock else "results")
    rows = [json.loads(l) for l in open(os.path.join(d, "raw_results.jsonl"), encoding="utf-8")]
    metas = json.load(open(os.path.join(d, "run_meta.json"), encoding="utf-8"))
    metas = metas if isinstance(metas, list) else [metas]
    charts = os.path.join(d, "charts")
    os.makedirs(charts, exist_ok=True)

    # keep the latest row per (system, id)
    latest = {}
    for r in rows:
        latest[(r["system"], r["id"])] = r
    rows = list(latest.values())
    by = {s: {r["id"]: r for r in rows if r["system"] == s} for s in ("Baseline-ZTA", "RAZTA", "RAZTA-noguard")}

    # ---------------- access decisions (all scenarios with allow/deny truth, plus session start)
    def access_metrics(sysrows):
        legit = [r for r in sysrows.values() if r["truth"] in ("allow", "continue", "terminate")
                 and r["category"] != "prompt_injection" and r["category"] not in ("credential_theft", "enumeration_probe")
                 and not (r["category"] == "noncompliant_device")]
        attacks = [r for r in sysrows.values() if r["truth"] == "deny"]
        fr = sum(r["decision"] == "deny" for r in legit)
        fa = sum(r["decision"] == "allow" for r in attacks)
        correct = len(legit) - fr + len(attacks) - fa
        return dict(n=len(legit) + len(attacks), legit=len(legit), attacks=len(attacks), false_rejects=fr,
                    false_accepts=fa, correct=correct)

    m = {s: access_metrics(by[s]) for s in ("Baseline-ZTA", "RAZTA")}

    # ---------------- sessions
    def sess(sysrows):
        rs = [r for r in sysrows.values() if r["category"] == "session"]
        hij = [r for r in rs if r["truth"] == "terminate"]
        ben = [r for r in rs if r["truth"] == "continue"]
        return dict(hijacks=len(hij), hijacks_stopped=sum(r.get("session_outcome") == "terminate" for r in hij),
                    benign=len(ben), benign_kept=sum(r.get("session_outcome") == "continue" for r in ben),
                    stepups=sum(r.get("stepups", 0) or 0 for r in rs))

    sm = {s: sess(by[s]) for s in ("Baseline-ZTA", "RAZTA")}

    # ---------------- injection
    inj_ids = sorted(i for i, r in by["RAZTA"].items() if r["category"] == "prompt_injection")
    inj = {}
    for s in ("RAZTA", "RAZTA-noguard", "Baseline-ZTA"):
        rs = [by[s][i] for i in inj_ids if i in by[s]]
        inj[s] = dict(n=len(rs), succeeded=sum(r["decision"] == "allow" for r in rs),
                      flagged=sum(bool(r.get("injection_flagged")) for r in rs),
                      override=sum(bool(r.get("override_applied")) for r in rs))

    # ---------------- enumeration
    enum = [r for r in by["RAZTA"].values() if r["category"] == "enumeration_probe"]
    enum_uniform = len({r.get("actor_message") for r in enum}) == 1 if enum else None
    enum_llm = sum(r.get("llm_calls_made", 0) or 0 for r in enum)

    # ---------------- latency and model behaviour
    rz = [r for r in by["RAZTA"].values() if r["category"] != "enumeration_probe"]
    lat = [r["latency_s"] for r in rz]
    slm_t = [r["slm_s"] for r in rz]
    llm_t = [r["llm_s"] for r in rz]
    base_lat = [r["latency_s"] for r in by["Baseline-ZTA"].values()]
    otp = [v for r in by["RAZTA"].values() if r.get("otp_parse_ok") for v in json.loads(r["otp_parse_ok"]) if v is not None]
    tpl = [r["template_valid"] for r in by["RAZTA"].values() if "template_valid" in r]
    degraded = sum(bool(r.get("degraded")) for r in by["RAZTA"].values())

    # ---------------- per-scenario CSV
    with open(os.path.join(d, "results_table.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "category", "truth", "note", "baseline_decision", "baseline_reason", "razta_decision",
                    "razta_session_outcome", "razta_T", "razta_band", "policy", "mfa_factors", "razta_reason",
                    "razta_latency_s", "slm_s", "llm_s", "llm_sources", "noguard_decision"])
        for i in sorted(by["RAZTA"]):
            b, r, n = by["Baseline-ZTA"].get(i, {}), by["RAZTA"][i], by["RAZTA-noguard"].get(i, {})
            w.writerow([i, r["category"], r["truth"], r["note"], b.get("decision"), b.get("reason"), r["decision"],
                        r.get("session_outcome"), r.get("T"), r.get("band"), r.get("policy"), r.get("mfa"),
                        r.get("reason"), r["latency_s"], round(r["slm_s"], 2), round(r["llm_s"], 2),
                        r.get("llm_sources"), n.get("decision")])

    # ---------------- charts
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    fig, ax = plt.subplots(figsize=(6.5, 3.6))
    labels = ["Accuracy", "False-accept rate", "False-reject rate"]
    vals = {s: [100 * m[s]["correct"] / m[s]["n"], 100 * m[s]["false_accepts"] / max(1, m[s]["attacks"]),
                100 * m[s]["false_rejects"] / max(1, m[s]["legit"])] for s in m}
    x = range(len(labels))
    for k, (s, c) in enumerate((("Baseline-ZTA", GREY), ("RAZTA", BLUE))):
        bars = ax.bar([i + (k - 0.5) * 0.38 for i in x], vals[s], 0.36, label=s, color=c)
        ax.bar_label(bars, fmt="%.0f%%", fontsize=8)
    ax.set_xticks(list(x), labels)
    ax.set_ylabel("%")
    ax.set_ylim(0, 110)
    ax.legend(frameon=False)
    ax.set_title("Access decisions: classical ZTA vs RAZTA")
    fig.tight_layout()
    fig.savefig(os.path.join(charts, "fig1_decision_quality.png"), dpi=300)
    plt.close(fig)

    cats = ["legit_routine", "legit_unusual", "credential_theft", "noncompliant_device", "enumeration_probe",
            "prompt_injection", "session"]

    def correct(r):
        if r["category"] == "session":
            return (r.get("session_outcome") or "continue") == r["truth"]
        return r["decision"] == r["truth"]

    fig, ax = plt.subplots(figsize=(7.5, 3.6))
    for k, (s, c) in enumerate((("Baseline-ZTA", GREY), ("RAZTA", BLUE))):
        ys = []
        for ccat in cats:
            rs = [r for r in by[s].values() if r["category"] == ccat]
            ys.append(100 * sum(correct(r) for r in rs) / len(rs) if rs else 0)
        bars = ax.bar([i + (k - 0.5) * 0.38 for i in range(len(cats))], ys, 0.36, label=s, color=c)
        ax.bar_label(bars, fmt="%.0f", fontsize=7)
    ax.set_xticks(range(len(cats)), [c.replace("_", "\n") for c in cats], fontsize=8)
    ax.set_ylabel("% scenarios handled correctly")
    ax.set_ylim(0, 115)
    ax.legend(frameon=False, loc="lower right")
    ax.set_title("Correct outcomes by scenario category")
    fig.tight_layout()
    fig.savefig(os.path.join(charts, "fig2_by_category.png"), dpi=300)
    plt.close(fig)

    ids = sorted(r["id"] for r in rz)
    fig, ax = plt.subplots(figsize=(8, 3.6))
    s_ = [by["RAZTA"][i]["slm_s"] for i in ids]
    l_ = [by["RAZTA"][i]["llm_s"] for i in ids]
    o_ = [max(0, by["RAZTA"][i]["latency_s"] - s_[k] - l_[k]) for k, i in enumerate(ids)]
    ax.bar(ids, s_, color=BLUE, label="Local SLMs (CPU, Ollama)")
    ax.bar(ids, l_, bottom=s_, color=ORANGE, label="Global LLMs (OpenRouter)")
    ax.bar(ids, o_, bottom=[a + b for a, b in zip(s_, l_)], color=GREY, label="Rules / orchestration")
    ax.set_ylabel("seconds per decision")
    ax.set_title("RAZTA decision latency by tier")
    ax.legend(frameon=False, fontsize=8)
    plt.xticks(fontsize=7)
    fig.tight_layout()
    fig.savefig(os.path.join(charts, "fig3_latency_breakdown.png"), dpi=300)
    plt.close(fig)

    if inj_ids:
        fig, ax = plt.subplots(figsize=(5.5, 3.4))
        names = ["RAZTA (guards on)", "RAZTA (guards off)"]
        succ = [100 * inj[s]["succeeded"] / max(1, inj[s]["n"]) for s in ("RAZTA", "RAZTA-noguard")]
        bars = ax.bar(names, succ, color=[BLUE, RED], width=0.5)
        ax.bar_label(bars, fmt="%.0f%%")
        ax.set_ylim(0, 110)
        ax.set_ylabel("injection attacks that gained access (%)")
        ax.set_title("Reflexive guards vs prompt injection")
        fig.tight_layout()
        fig.savefig(os.path.join(charts, "fig4_injection_ablation.png"), dpi=300)
        plt.close(fig)

    # ---------------- summary
    last = metas[-1]
    calls = sum(x.get("llm_calls", 0) for x in metas)
    hits = sum(x.get("llm_cache_hits", 0) for x in metas)
    subs = {}
    for x in metas:
        subs.update(x.get("slm_substitutions", {}))
    L = []
    L.append("# RAZTA pilot experiment: results summary\n")
    if a.mock:
        L.append("> **MOCK RUN. These numbers come from fake model replies and must not be reported.**\n")
    L.append(f"Run finished {last['finished']}. Scenarios: {len(by['RAZTA'])} "
             f"(plus {inj['RAZTA-noguard']['n']} ablation runs).\n")
    dec_n = sum(1 for r in by["RAZTA"].values() if r["category"] != "enumeration_probe")
    if degraded:
        L.append(f"> **WARNING: {degraded} of {dec_n} RAZTA decisions had at least one global-LLM step that fell back "
                 f"to its deterministic rule (degraded mode). Results for those decisions show RAZTA running "
                 f"without its global tier. Do not attribute them to the LLM agents. See cache/llm_errors.log.**\n")
    ng_deg = sum(bool(r.get("degraded")) for r in by["RAZTA-noguard"].values())
    if ng_deg:
        L.append(f"> **The guards-off ablation is inconclusive: {ng_deg} of its runs had no LLM reply, so the "
                 f"injected text never reached a large model.**\n")
    L.append("## Models actually used\n")
    L.append("| Agent | Tier | Model |\n|---|---|---|")
    for role, mdl in last["slm_models"].items():
        L.append(f"| {role} | local SLM (CPU) | {subs.get(mdl, mdl)}{' (substituted for ' + mdl + ')' if mdl in subs else ''} |")
    for role, mdl in last["llm_models"].items():
        L.append(f"| {role} | global LLM (OpenRouter) | {mdl} |")
    L.append("\n## Table 1. Access decisions\n")
    L.append("| Metric | Classical ZTA | RAZTA |\n|---|---|---|")
    for key, lab in (("correct", "Correct decisions"), ("false_accepts", "False accepts (attacks allowed)"),
                     ("false_rejects", "False rejects (legitimate users denied)")):
        den = {"correct": "n", "false_accepts": "attacks", "false_rejects": "legit"}[key]
        L.append(f"| {lab} | {m['Baseline-ZTA'][key]}/{m['Baseline-ZTA'][den]} ({pct(m['Baseline-ZTA'][key], m['Baseline-ZTA'][den])}) "
                 f"| {m['RAZTA'][key]}/{m['RAZTA'][den]} ({pct(m['RAZTA'][key], m['RAZTA'][den])}) |")
    L.append("\n## Table 2. Live sessions (continuous monitoring)\n")
    L.append("| Metric | Classical ZTA | RAZTA |\n|---|---|---|")
    L.append(f"| Hijacked sessions terminated | {sm['Baseline-ZTA']['hijacks_stopped']}/{sm['Baseline-ZTA']['hijacks']} | "
             f"{sm['RAZTA']['hijacks_stopped']}/{sm['RAZTA']['hijacks']} |")
    L.append(f"| Benign sessions left running | {sm['Baseline-ZTA']['benign_kept']}/{sm['Baseline-ZTA']['benign']} | "
             f"{sm['RAZTA']['benign_kept']}/{sm['RAZTA']['benign']} |")
    L.append(f"| Step-up challenges issued | 0 | {sm['RAZTA']['stepups']} |")
    L.append("\n## Table 3. Prompt-injection ablation (reflexive guards on vs off)\n")
    L.append("| Configuration | Attacks that gained access | Injections flagged | LLM trust overrides applied |\n|---|---|---|---|")
    for s, lab in (("RAZTA", "RAZTA, guards on"), ("RAZTA-noguard", "RAZTA, guards off")):
        L.append(f"| {lab} | {inj[s]['succeeded']}/{inj[s]['n']} | {inj[s]['flagged']}/{inj[s]['n']} | {inj[s]['override']} |")
    L.append(f"\nClassical ZTA is not exposed to this attack (it has no language model), "
             f"but it allowed {inj['Baseline-ZTA']['succeeded']}/{inj['Baseline-ZTA']['n']} of these attackers through its fixed password + SMS OTP rule.\n")
    L.append("## Table 4. Enumeration resistance\n")
    L.append(f"- Probes: {len(enum)}; all denied: {all(r['decision'] == 'deny' for r in enum)}; "
             f"identical message to the actor: {enum_uniform}; LLM calls spent on probes: {enum_llm}.\n")
    L.append("## Table 5. Cost and latency\n")
    L.append("| Metric | Value |\n|---|---|")
    L.append(f"| Classical ZTA decision time (mean) | {1000 * st.mean(base_lat):.3f} ms |")
    if lat:
        L.append(f"| RAZTA decision time, mean / median / p95 | {st.mean(lat):.1f} s / {st.median(lat):.1f} s / {p95(lat):.1f} s |")
        L.append(f"| of which local SLM time (mean) | {st.mean(slm_t):.1f} s |")
        L.append(f"| of which global LLM time (mean) | {st.mean(llm_t):.1f} s |")
    L.append(f"| LLM API calls / cache hits (all runs) | {calls} / {hits} |")
    L.append(f"| RAZTA decisions made with a degraded (rule-only) LLM step | {degraded} |")
    if otp:
        L.append(f"| Enforcement SLM: OTP replies parsed correctly | {sum(otp)}/{len(otp)} ({pct(sum(otp), len(otp))}) |")
    if tpl:
        L.append(f"| Verification SLM: challenge template inside whitelist | {sum(tpl)}/{len(tpl)} ({pct(sum(tpl), len(tpl))}) |")
    L.append("\n## Limitations to state in the paper\n")
    L.append("- Synthetic test bed of 24 scenarios on one consumer laptop (16 GB RAM); a pilot, not a statistically powered evaluation.")
    L.append("- Free-tier LLMs vary in availability and rate limits; the models in the table above are the ones actually used.")
    L.append("- Latency on a consumer laptop and free shared API endpoints overstates production latency; the tier split (Figure 3) is the transferable result.")
    L.append("- The human-review step is a deterministic stand-in; session re-scoring uses the rule formula plus an LLM check on trigger events.")
    L.append("- Scenarios were designed by the authors and target RAZTA's stated features; public datasets (LANL, CERT) are future work.")
    L.append("\nFigures: charts/fig1_decision_quality.png, fig2_by_category.png, fig3_latency_breakdown.png, fig4_injection_ablation.png")
    L.append("Per-scenario detail: results_table.csv")
    open(os.path.join(d, "summary.md"), "w", encoding="utf-8").write("\n".join(L))
    print("\n".join(L))
    print(f"\nSaved to {d}")


if __name__ == "__main__":
    main()
