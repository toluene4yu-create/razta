"""Increment 6: do the language models help on AMBIGUOUS requests?

Runs the 16 ambiguous cases (ambiguous.py) through six configurations:
  RBA                    conventional risk-based authentication baseline (no models, ignores the reason)
  RAZTA-rules            RAZTA with every model replaced by its rule stand-in; reason ignored
  RAZTA-rules+regex      as above, plus a regular expression that finds ticket ids / keywords in the reason,
                         checked against the records by code (strongest no-model control)
  RAZTA-models           full RAZTA with the local and global models; reason ignored
  RAZTA-models+tighten   full RAZTA + justification agent; the reason can only make things stricter
  RAZTA-models+bounded   full RAZTA + justification agent; a code-verified record may relax ONE band
All RAZTA configurations use the identity twin (Stage 1c).

Usage:
    python run_ambiguous.py --rules-only     no Ollama / API needed (takes seconds)
    python run_ambiguous.py                  everything (Ollama running + OPENROUTER_API_KEY set)
    python run_ambiguous.py --mock           plumbing test with fake model replies
    python run_ambiguous.py --fresh          start again
Saves after every case, so if it stops just run it again to resume."""
import argparse
import json
import os
import time

import config
import ambiguous  # noqa: F401  (extends the test bed: users, devices, logs, records)
from agents import Orchestrator
from ambiguous import AMBIG, ON_CALL, TICKETS, TRAVEL
from baseline_rba import rba_decide
from llm_clients import STATS, OllamaClient, OpenRouterClient, RuleLLM, RuleSLM

HERE = os.path.dirname(os.path.abspath(__file__))
RECORDS = dict(oncall=ON_CALL, tickets=TICKETS, travel=TRAVEL)
RULE_CONFIGS = [("RAZTA-rules", "off"), ("RAZTA-rules+regex", "regex")]
MODEL_CONFIGS = [("RAZTA-models", "off"), ("RAZTA-models+tighten", "llm_tighten"), ("RAZTA-models+bounded", "llm_bounded")]
KEEP = ("decision", "reason", "band", "T", "policy", "mfa", "injection_flagged", "review", "arbitration",
        "provisional", "just_claim", "just_ref", "just_verification", "just_flags", "just_assessment",
        "just_plausibility", "just_adjust", "just_injection", "latency_s", "slm_s", "llm_s", "llm_sources",
        "gate_reason", "ev_note")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--rules-only", action="store_true")
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()

    outdir = os.path.join(HERE, "results_ambiguous_mock" if a.mock else "results_ambiguous")
    os.makedirs(outdir, exist_ok=True)
    raw_path = os.path.join(outdir, "raw.jsonl")
    if a.fresh and os.path.exists(raw_path):
        os.remove(raw_path)
    done = set()
    if os.path.exists(raw_path):
        for line in open(raw_path, encoding="utf-8"):
            r = json.loads(line)
            done.add((r["system"], r["id"]))

    configs = [("RBA", None, None)] + [(n, "rules", j) for n, j in RULE_CONFIGS]
    slm = llm = None
    if not a.rules_only:
        slm = OllamaClient(mock=a.mock, memo=True)
        llm = OpenRouterClient(mock=a.mock)
        print("Global LLMs:", json.dumps(llm.models, indent=2))
        configs += [(n, "models", j) for n, j in MODEL_CONFIGS]

    todo = [s for s in AMBIG if not a.only or s["id"] in a.only]
    t0 = time.time()
    with open(raw_path, "a", encoding="utf-8") as out:
        for i, sc in enumerate(todo, 1):
            for system, kind, just in configs:
                if (system, sc["id"]) in done:
                    continue
                print(f"[{i}/{len(todo)}] {sc['id']} {system:22s} ...", end=" ", flush=True)
                calls0 = STATS.llm_calls
                if kind is None:
                    r = rba_decide(sc)
                    r["mfa"] = "+".join(r.pop("factors", []) or [])
                else:
                    s_, l_ = (RuleSLM(), RuleLLM()) if kind == "rules" else (slm, llm)
                    orch = Orchestrator(s_, l_, guard=True, use_twin=True, justify=just, records=RECORDS)   # fresh state per case
                    r = orch.handle(sc)
                    r["llm_sources"] = "|".join(r["llm_sources"])
                    r["llm_calls_made"] = STATS.llm_calls - calls0
                row = dict(system=system, id=sc["id"], pair=sc["pair"], design_truth=sc["design_truth"],
                           **{k: r.get(k) for k in KEEP + ("risk", "llm_calls_made") if k in r})
                if isinstance(r.get("breakdown"), dict):
                    row["breakdown"] = r["breakdown"]
                out.write(json.dumps(row, default=str) + "\n")
                out.flush()
                print(f"{row['decision']:5s} band={row.get('band')} T={row.get('T')} mfa={row.get('mfa')} "
                      f"reason-check={row.get('just_verification')}/{row.get('just_adjust')}  ({row.get('reason')})")
    meta = dict(mock=a.mock, rules_only=a.rules_only, llm_models=STATS.llm_models, slm_models=config.SLM,
                slm_calls=STATS.slm_calls, llm_calls=STATS.llm_calls, llm_cache_hits=STATS.llm_cache_hits,
                llm_failures=STATS.llm_failures, degraded=STATS.degraded,
                wall_clock_min=round((time.time() - t0) / 60, 1), finished=time.strftime("%Y-%m-%d %H:%M"))
    with open(os.path.join(outdir, "run_meta.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps(meta) + "\n")
    print(f"\nDone. LLM calls: {STATS.llm_calls}, cache hits: {STATS.llm_cache_hits}, degraded: {STATS.degraded}")
    print(f"Now run:  python analyze_ambiguous.py{' --mock' if a.mock else ''}")


if __name__ == "__main__":
    main()
