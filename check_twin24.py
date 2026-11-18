"""Checks that switching the identity twin on does not change the structural outcome of the
original 24 scenarios. Uses the rule stand-ins for every model, so it needs no Ollama or API.
Usage:  python check_twin24.py"""
import csv
import os

from agents import Orchestrator
from llm_clients import RuleLLM, RuleSLM
from scenarios import SCENARIOS

rows, same = [], 0
for sc in SCENARIOS:
    out = {}
    for twin in (False, True):
        r = Orchestrator(RuleSLM(), RuleLLM(), guard=True, use_twin=twin).handle(sc)
        out[twin] = r
    a, b = out[False], out[True]
    sa = (a["decision"], a.get("session_outcome"))
    sb = (b["decision"], b.get("session_outcome"))
    same += sa == sb
    rows.append([sc["id"], sc["truth"], a["band"], a["T"], sa[0], sa[1], b["band"], b["T"], sb[0], sb[1],
                 (b.get("twin") or {}).get("sessions")])
    print(f"{sc['id']:3s} no-twin: {a['band']}/{a['T']} {sa}   twin: {b['band']}/{b['T']} {sb}")
os.makedirs("results_ambiguous", exist_ok=True)
with open("results_ambiguous/twin_check_24.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["id", "truth", "band_no_twin", "T_no_twin", "decision_no_twin", "session_no_twin",
                "band_twin", "T_twin", "decision_twin", "session_twin", "twin_sessions"])
    w.writerows(rows)
print(f"\nSame outcome with and without the twin: {same}/24  (saved results_ambiguous/twin_check_24.csv)")
