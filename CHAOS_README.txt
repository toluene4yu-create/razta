RAZTA RESILIENCE (CHAOS) EXPERIMENT - HOW TO RUN
================================================
What changed in the code
  agents.py  - any agent crash, unreachable store or missed deadline now ends in a refusal
               (fail closed) instead of a Python error; advisory inputs (context, device,
               threat intel) can degrade to worst-case values ("conservative" policy);
               a lost session monitor suspends the session; a 180 s decision deadline;
               a simulated clock so message delays can be tested without real waiting.
               Normal behaviour is unchanged: the 24-scenario dry run gives identical results.
  config.py  - DECISION_DEADLINE_S = 180 and FAULT_POLICY = "conservative" added at the end.
  chaos.py, analyze_chaos.py - new: the fault-injection harness and its analysis.

Steps (PowerShell, inside this razta folder)
  1. Make sure Ollama is running (ollama list should show the five models).
  2. Set the key for this window:   $env:OPENROUTER_API_KEY="your key"
  3. Optional 5-second check:        python chaos.py --mock --fresh
                                     python analyze_chaos.py --mock
  4. Real run (about 1 hour; leave the laptop plugged in, close other apps):
                                     python chaos.py --fresh
     If it stops for any reason, run   python chaos.py   again - it resumes.
  5. Summarise:                      python analyze_chaos.py
  6. Send back the whole results_chaos folder (raw.jsonl, summary.csv, summary.md,
     run_meta.json, chaos_overview.png) and a screenshot of the console summary.

Conditions (each runs all 24 scenarios)
  N0 normal | A1-A8 one agent crashes | O1 orchestrator stops mid-decision
  D1-D5 2/5/10/20/30 s delay per inter-agent message | S1 Ollama down | S2 OpenRouter down
  S3 log store down | S4 threat-intel feed down | S5 policy store down
  A2s A3s S3s S4s the same faults under the "strict" policy (any fault -> refuse)
