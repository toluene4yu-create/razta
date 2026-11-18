"""Runs the risk-based authentication (RBA) baseline on all 24 scenarios.
Deterministic: no models or API key needed.  Usage:  python run_rba.py"""
import csv
import os

from baseline_rba import rba_decide
from scenarios import SCENARIOS

os.makedirs("results", exist_ok=True)
rows, correct = [], 0
for sc in SCENARIOS:
    r = rba_decide(sc)
    ok = (r["session_outcome"] == sc["truth"]) if sc["category"] == "session" else r["decision"] == sc["truth"]
    login_ok = r["decision"] == ("allow" if sc["category"] == "session" else sc["truth"])
    correct += login_ok
    rows.append([sc["id"], sc["category"], sc["truth"], r["decision"], r["session_outcome"], r["risk"], r["reason"], ok])
    print(f"{sc['id']:3s} expected={sc['truth']:9s} rba={r['decision']:5s} {r['session_outcome'] or '':9s} {r['reason']}")
with open("results/rba_results.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["id", "category", "truth", "decision", "session_outcome", "risk", "reason", "correct"])
    w.writerows(rows)
print(f"\nCorrect access decisions (sessions judged at login): {correct}/24. Saved results/rba_results.csv")
