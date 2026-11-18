"""Runs every scenario through (1) the classical ZTA baseline, (2) RAZTA, and
(3) RAZTA with its reflexive guards switched off (ablation, injection scenarios only).

Usage:
    python run_experiment.py            real run (Ollama + OpenRouter)
    python run_experiment.py --mock     dry run with fake model replies (tests the plumbing only)
    python run_experiment.py --only A1 C1
    python run_experiment.py --fresh    delete previous results and start again
The run saves after every scenario, so if it stops you can simply run it again to resume."""
import argparse
import json
import os
import time

import config
from agents import Orchestrator
from baseline import baseline_decide
from llm_clients import STATS, OllamaClient, OpenRouterClient
from scenarios import SCENARIOS

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--skip-ablation", action="store_true")
    ap.add_argument("--max-llm-calls", type=int, default=None,
                    help="raise this (e.g. 400) after adding credit to OpenRouter")
    a = ap.parse_args()
    if a.max_llm_calls:
        config.MAX_LLM_CALLS = a.max_llm_calls

    outdir = os.path.join(HERE, "results_mock" if a.mock else "results")
    os.makedirs(outdir, exist_ok=True)
    raw_path = os.path.join(outdir, "raw_results.jsonl")
    if a.fresh and os.path.exists(raw_path):
        os.remove(raw_path)
    done = set()
    if os.path.exists(raw_path):
        with open(raw_path, encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                done.add((r["system"], r["id"]))

    slm = OllamaClient(mock=a.mock)
    llm = OpenRouterClient(mock=a.mock)
    print("Global LLMs chosen:", json.dumps(llm.models, indent=2))
    if not a.mock:
        for role, m in config.SLM.items():
            print(f"Local SLM {role:22s} -> {slm.resolve(m)}")

    razta = Orchestrator(slm, llm, guard=True)
    ablation = Orchestrator(slm, llm, guard=False)
    todo = [s for s in SCENARIOS if not a.only or s["id"] in a.only]
    t_start = time.time()
    with open(raw_path, "a", encoding="utf-8") as out:
        for i, sc in enumerate(todo, 1):
            runs = [("Baseline-ZTA", None), ("RAZTA", razta)]
            if sc["category"] == "prompt_injection" and not a.skip_ablation:
                runs.append(("RAZTA-noguard", ablation))
            for system, orch in runs:
                if (system, sc["id"]) in done:
                    continue
                print(f"[{i}/{len(todo)}] {sc['id']:3s} {sc['category']:18s} {system:14s} ...", end=" ", flush=True)
                calls_before = STATS.llm_calls
                if orch is None:
                    r = baseline_decide(sc)
                else:
                    r = orch.handle(sc)
                    r["llm_calls_made"] = STATS.llm_calls - calls_before
                    r["degraded"] = any(s.endswith(":degraded") for s in r["llm_sources"])
                    r["llm_sources"] = "|".join(r["llm_sources"])
                row = dict(system=system, id=sc["id"], category=sc["category"], truth=sc["truth"],
                           note=sc["note"], **{k: v for k, v in r.items() if not isinstance(v, (list, dict)) or k == "breakdown"})
                if "otp_parse_ok" in r:
                    row["otp_parse_ok"] = json.dumps(r["otp_parse_ok"])
                out.write(json.dumps(row, default=str) + "\n")
                out.flush()
                print(f"{row['decision']:5s} {row.get('session_outcome') or '':9s} "
                      f"band={row.get('band')} T={row.get('T')} {row.get('latency_s', 0):.2f}s  ({row.get('reason', '')})")

    meta = dict(mock=a.mock, llm_models=STATS.llm_models, slm_models=config.SLM, slm_substitutions=STATS.substitutions,
                slm_calls=STATS.slm_calls, llm_calls=STATS.llm_calls, llm_cache_hits=STATS.llm_cache_hits,
                llm_failures=STATS.llm_failures, degraded_llm_steps=STATS.degraded,
                wall_clock_min=round((time.time() - t_start) / 60, 1), finished=time.strftime("%Y-%m-%d %H:%M"))
    meta_path = os.path.join(outdir, "run_meta.json")
    prev = []
    if os.path.exists(meta_path):
        try:
            prev = json.load(open(meta_path, encoding="utf-8"))
        except Exception:
            prev = []
    prev = prev if isinstance(prev, list) else [prev]
    json.dump(prev + [meta], open(meta_path, "w", encoding="utf-8"), indent=2)
    print("\nDone. LLM calls this run:", STATS.llm_calls, "| cache hits:", STATS.llm_cache_hits,
          "| degraded steps:", STATS.degraded, "| SLM substitutions:", STATS.substitutions)
    print(f"Now run:  python analyze.py{' --mock' if a.mock else ''}")


if __name__ == "__main__":
    main()
