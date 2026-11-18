"""Resilience / chaos experiment for RAZTA.

Runs all 24 scenarios through RAZTA under normal operation and under injected faults:
agent crashes, an orchestrator stop, inter-agent message delays, and outages of the
supporting services (local model server, global model API, access-log store,
threat-intelligence feed, policy store). Every fault is injected by this script; the
RAZTA code itself is unchanged between conditions.

Usage (PowerShell, inside the razta folder, Ollama running, API key set):
    python chaos.py              real run  (about 1-3 hours; resumes if stopped)
    python chaos.py --mock       dry run with fake model replies (checks the plumbing only)
    python chaos.py --only N0 D2 run selected conditions
    python chaos.py --fresh      delete previous chaos results first
Then:
    python analyze_chaos.py
"""
import argparse
import json
import os
import time

import agents
import config
from agents import Orchestrator
from llm_clients import STATS, OllamaClient, OpenRouterClient
from scenarios import SCENARIOS

HERE = os.path.dirname(os.path.abspath(__file__))

# Identifiers of the global models used in the reported run (Table 5 of the paper). Pinning them
# lets the global tier answer from the same cache as the reported run where inputs are identical.
REPORTED_LLMS = {
    "orchestrator": "deepseek/deepseek-v4.1-flash-1017",
    "risk_engine": "moonshotai/kimi-k2.7-code",
    "policy_mfa": "z-ai/glm-5.3-flashx",
    "trust_monitor": "moonshotai/kimi-k2.7-code",
    "justification": "deepseek/deepseek-v4.1-flash-1017",
}

#  id      kind        target / value               policy           description
CONDITIONS = [
    ("N0", "none", None, "conservative", "Normal operation (no fault)"),
    ("A1", "crash", "identity_gate", "conservative", "Identity Gate agent crashes"),
    ("A2", "crash", "context_retrieval", "conservative", "Context and Log Retrieval agent crashes"),
    ("A3", "crash", "device_trust", "conservative", "Device and Endpoint Trust agent crashes"),
    ("A4", "crash", "risk_engine", "conservative", "Risk and Trust Engine agent crashes"),
    ("A5", "crash", "policy_mfa", "conservative", "Policy and Adaptive MFA agent crashes"),
    ("A6", "crash", "entity_verification", "conservative", "Entity Verification agent crashes"),
    ("A7", "crash", "policy_enforcement", "conservative", "Policy Enforcement agent crashes"),
    ("A8", "crash", "trust_monitor", "conservative", "Continuous Trust Monitor crashes during the session"),
    ("O1", "orch_stop", "before_policy", "conservative", "Orchestrator stops mid-decision (after scoring, before policy)"),
    ("D1", "delay", 2.0, "conservative", "2 s delay on every inter-agent message"),
    ("D2", "delay", 5.0, "conservative", "5 s delay on every inter-agent message"),
    ("D3", "delay", 10.0, "conservative", "10 s delay on every inter-agent message"),
    ("D4", "delay", 20.0, "conservative", "20 s delay on every inter-agent message"),
    ("D5", "delay", 30.0, "conservative", "30 s delay on every inter-agent message"),
    ("S1", "slm_down", None, "conservative", "Local model server (Ollama) unreachable"),
    ("S2", "llm_down", None, "conservative", "Global model API (OpenRouter) unreachable"),
    ("S3", "store_down", "LOGS", "conservative", "Access-log store unreachable"),
    ("S4", "store_down", "THREAT_INTEL", "conservative", "Threat-intelligence feed unreachable"),
    ("S5", "store_down", "POLICIES", "conservative", "Signed policy store unreachable"),
    ("A2s", "crash", "context_retrieval", "strict", "Context agent crashes (strict policy)"),
    ("A3s", "crash", "device_trust", "strict", "Device agent crashes (strict policy)"),
    ("S3s", "store_down", "LOGS", "strict", "Access-log store unreachable (strict policy)"),
    ("S4s", "store_down", "THREAT_INTEL", "strict", "Threat-intelligence feed unreachable (strict policy)"),
]


class Unreachable:
    """Stands in for a data store that cannot be reached: any read raises ConnectionError."""
    def __init__(self, name):
        self.name = name

    def _fail(self, *a, **k):
        raise ConnectionError(f"{self.name} store unreachable")

    __iter__ = __getitem__ = __contains__ = __len__ = get = items = keys = values = _fail


class DownSLM:
    """Local model server unreachable: every call returns the same error the client returns
    when Ollama refuses the connection."""
    calls = 0

    def chat_json(self, model, system, user, mock_fn=None):
        DownSLM.calls += 1
        return None, "ERROR: connection refused (Ollama unreachable)", 0.0


class DownLLM:
    """Global model API unreachable (the cache is not consulted)."""
    def __init__(self, models):
        self.models = models

    def chat_json(self, role, system, user, mock_fn=None):
        STATS.degraded += 1
        return None, "ERROR: connection refused (OpenRouter unreachable)", 0.0, "degraded"


def crasher(agent):
    def boom(*a, **k):
        raise RuntimeError(f"{agent} process crashed")
    return boom


CRASH_METHODS = {
    "identity_gate": ("ig", "run"), "context_retrieval": ("clr", "run"), "device_trust": ("det", "run"),
    "risk_engine": ("rte", "score"), "policy_mfa": ("pc", "select"), "entity_verification": ("ev", "run"),
    "policy_enforcement": ("pe", "enforce"), "trust_monitor": ("catm", "watch"),
}


def build(cond, slm, llm):
    cid, kind, target, policy, _ = cond
    s = DownSLM() if kind == "slm_down" else slm
    l = DownLLM(llm.models) if kind == "llm_down" else llm
    orch = Orchestrator(s, l, guard=True, fault_policy=policy)
    if kind == "crash":
        attr, meth = CRASH_METHODS[target]
        setattr(getattr(orch, attr), meth, crasher(target))
    if kind == "orch_stop":
        orch.fail_point = target
    return orch


def apply_env(cond):
    """Faults that live outside the orchestrator object. Returns an undo function."""
    _, kind, target, _, _ = cond
    saved = {}
    if kind == "delay":
        agents.Clock.msg_delay_s = float(target)
    if kind == "store_down":
        saved[target] = getattr(agents, target)
        setattr(agents, target, Unreachable(target.lower()))

    def undo():
        agents.Clock.msg_delay_s = 0.0
        for k, v in saved.items():
            setattr(agents, k, v)
    return undo


def warm_up(slm):
    print("Warming up local models (so model loading is not counted as a fault)...")
    for role, m in config.SLM.items():
        t0 = time.time()
        slm.chat_json(m, "Reply with JSON {\"ok\": true}.", "{}", mock_fn=lambda: {"ok": True})
        print(f"  {role:22s} {slm.resolve(m):16s} {time.time() - t0:6.1f}s")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--max-llm-calls", type=int, default=300)
    a = ap.parse_args()
    config.MAX_LLM_CALLS = a.max_llm_calls
    if not a.mock:
        config.LLM_OVERRIDE = dict(REPORTED_LLMS)

    outdir = os.path.join(HERE, "results_chaos_mock" if a.mock else "results_chaos")
    os.makedirs(outdir, exist_ok=True)
    raw_path = os.path.join(outdir, "raw.jsonl")
    if a.fresh and os.path.exists(raw_path):
        os.remove(raw_path)
    done = set()
    if os.path.exists(raw_path):
        for line in open(raw_path, encoding="utf-8"):
            r = json.loads(line)
            done.add((r["condition"], r["id"]))

    slm = OllamaClient(mock=a.mock, memo=True)     # identical inputs -> identical local replies across conditions
    llm = OpenRouterClient(mock=a.mock)
    print("Global LLMs:", json.dumps(llm.models, indent=2))
    if not a.mock:
        warm_up(slm)

    conds = [c for c in CONDITIONS if not a.only or c[0] in a.only]
    t_start = time.time()
    with open(raw_path, "a", encoding="utf-8") as out:
        for cond in conds:
            cid, kind, target, policy, desc = cond
            todo = [sc for sc in SCENARIOS if (cid, sc["id"]) not in done]
            if not todo:
                continue
            print(f"\n=== {cid}: {desc} [{policy}] ===")
            orch = build(cond, slm, llm)
            for sc in todo:
                undo = apply_env(cond)
                calls0 = STATS.llm_calls
                try:
                    r = orch.handle(sc)
                    crashed = False
                except Exception as e:                       # should never happen: counted as an unhandled crash
                    r = dict(decision="error", reason=f"UNHANDLED {type(e).__name__}: {e}", llm_sources=[])
                    crashed = True
                finally:
                    undo()
                row = dict(condition=cid, kind=kind, target=str(target), policy=policy, description=desc,
                           id=sc["id"], category=sc["category"], truth=sc["truth"],
                           decision=r.get("decision"), session_outcome=r.get("session_outcome"),
                           band=r.get("band"), T=r.get("T"), reason=r.get("reason"),
                           fault=r.get("fault"), fail_closed=bool(r.get("fail_closed")),
                           session_fault=bool(r.get("session_fault")),
                           degraded_inputs="|".join(r.get("degraded_inputs", [])),
                           llm_degraded=any(str(s).endswith(":degraded") for s in r.get("llm_sources", [])),
                           llm_sources="|".join(r.get("llm_sources", [])),
                           llm_calls_made=STATS.llm_calls - calls0,
                           latency_s=r.get("latency_s"), unhandled=crashed, mock=a.mock)
                out.write(json.dumps(row, default=str) + "\n")
                out.flush()
                print(f"  {sc['id']:3s} {row['decision']:5s} {row['session_outcome'] or '':9s} band={row['band']} "
                      f"T={row['T']} {row['latency_s'] or 0:7.2f}s  {row['reason']}")
    meta = dict(mock=a.mock, llm_models=llm.models, slm_calls=STATS.slm_calls, llm_calls=STATS.llm_calls,
                llm_cache_hits=STATS.llm_cache_hits, degraded_llm_steps=STATS.degraded,
                deadline_s=config.DECISION_DEADLINE_S, wall_clock_min=round((time.time() - t_start) / 60, 1),
                finished=time.strftime("%Y-%m-%d %H:%M"))
    json.dump(meta, open(os.path.join(outdir, "run_meta.json"), "w"), indent=2)
    print(f"\nDone in {meta['wall_clock_min']} min. LLM calls: {STATS.llm_calls}, cache hits: {STATS.llm_cache_hits}")
    print(f"Now run:  python analyze_chaos.py{' --mock' if a.mock else ''}")


if __name__ == "__main__":
    main()
