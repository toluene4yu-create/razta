# RAZTA pilot experiment (CPU-only, free API)

This folder runs the RAZTA experiment end to end. It runs 24 labelled access scenarios through three systems:

1. **Classical ZTA**, a NIST SP 800-207 style baseline with static rules, fixed password + SMS OTP, and no session monitoring.
2. **RAZTA**: 5 local agents on small models (Ollama, your CPU) and 4 global agents on large models (OpenRouter free API).
3. **RAZTA with its reflexive guards switched off**, run on the 3 prompt-injection scenarios only (ablation).

It produces the tables, figures and a results summary for the paper.

## Which agent uses which model

| Agent | Tier | Model |
|---|---|---|
| Identity Gate | local | llama3.2:1b |
| Context & Log Retrieval | local | mistral:7b |
| Device & Endpoint Trust | local | ministral-3:3b |
| Entity Verification | local | gemma2:2b |
| Policy Enforcement | local | llama3.2:3b |
| Orchestrator, Risk & Trust Engine, Policy + MFA, Trust Monitor | global | OpenRouter free models, chosen automatically (DeepSeek / Kimi / GLM / Qwen first) |

## Steps (Windows)

1. Install Python 3.12 from python.org and tick **"Add python.exe to PATH"**.
2. Install Ollama from ollama.com/download/windows.
3. In PowerShell, download the models:
   `ollama pull llama3.2:1b`, `ollama pull llama3.2:3b`, `ollama pull gemma2:2b`, `ollama pull ministral-3:3b`, `ollama pull mistral:7b`
4. Unzip this folder to `Documents\razta`.
5. Open the folder in File Explorer, click the address bar, type `powershell` and press Enter. A PowerShell window opens already inside the folder.
6. Install the two Python packages:
   `pip install -r requirements.txt`
7. Give PowerShell your OpenRouter key. Do this again each time you open a new PowerShell window:
   `$env:OPENROUTER_API_KEY="sk-or-...your key..."`
8. Check everything:
   `python check_setup.py`
9. Optional: run a 10-second plumbing test with fake replies:
   `python run_experiment.py --mock`
10. Run the real experiment:
    `python run_experiment.py`
    If it stops for any reason, run the same command again. It resumes where it stopped.
11. Make the tables and figures:
    `python analyze.py`
    Your results are in `results\summary.md`, `results\results_table.csv` and `results\charts\*.png`.

## Free-tier facts that affect the results

- Without credit, OpenRouter allows about 50 free requests a day and 20 a minute. The full run needs about 22 distinct LLM requests. Replies are cached in `cache\`, so re-runs cost nothing.
- If the daily limit runs out mid-run, RAZTA continues in **degraded mode**: the LLM step falls back to its deterministic rule. This is counted and reported in the summary. It is RAZTA's designed connectivity-loss behaviour, but say so in the paper.
- The free models change often. The summary records the exact models that were used. Report those, not the names in the planning table.

## Files

`config.py` holds all settings and thresholds. `scenarios.py` holds the test bed. `agents.py` implements the 9 agents (Algorithms 1–9). `baseline.py` is the classical ZTA. `run_experiment.py` runs everything. `analyze.py` writes the results.

## Live demo for screen-sharing

Double-click `start_demo.bat`, or run `python demo_server.py`. Your browser opens at http://localhost:8765.

- **Replay recorded run** (default) replays the real experiment from `results\`. It is fast, needs no models, and is the safest choice for a demo.
- **Live models** runs the real agents. Ollama must be running and your key must be set. Each request takes about 40 s.
- **Simulated** uses fake model replies. Use it for rehearsal only, never for reporting.
- The **Reflexive guards** switch reruns a request with the guards off (the ablation).
- **Build a custom request** lets you combine any user, resource, location, device, attacker and injection.
- The **Experiment results** tab shows the summary tables and the four figures.

Press Ctrl+C in the PowerShell window to stop the demo.

---------------------------------------------------------------------------
INCREMENT 6 - IDENTITY TWIN + AMBIGUOUS-CASE EXPERIMENT
---------------------------------------------------------------------------
New files: twin.py, ambiguous.py, run_ambiguous.py, analyze_ambiguous.py,
check_twin24.py, labels.csv, LABELLING_RULE.txt
(agents.py, llm_clients.py and config.py were updated; the original 24-scenario
experiment is unchanged because the twin and the reason-checker are OFF by default.)

STEP 0  Labels first. Send labels.csv + LABELLING_RULE.txt to your supervisor or a
        colleague. They fill in allow/deny and send it back. Put their labels.csv in
        this folder (replace the blank one).

STEP 1  Open PowerShell in this folder:
            cd C:\Users\tolua\razta-exp\razta
            .\.venv\Scripts\Activate.ps1          (only if you used a venv before)

STEP 2  Quick checks (seconds, no internet, no Ollama):
            python check_twin24.py              -> should end "24/24"
            python run_ambiguous.py --rules-only

STEP 3  Full run (Ollama open, API key set, close other apps; about 20-30 minutes):
            $env:OPENROUTER_API_KEY = "sk-or-...your key..."
            python run_ambiguous.py
        If it stops, run the same command again - it resumes.

STEP 4  Results:
            python analyze_ambiguous.py
        Send me results_ambiguous\summary.md (and the whole results_ambiguous folder).

DEMO (updated): python demo_server.py  -> the left list now ends with the 16 ambiguous
cases (H01-H16). Pick the "RAZTA setup (H cases)" at the top to switch between
"Models + reason check", "Rules only (no AI)" etc. and click the same case again to compare.
The Experiment results tab now also shows the ambiguous-case results.

LOGIN PORTAL (supervisor's request): the demo console is now a resource protected by RAZTA.
  python demo_server.py          -> opens http://localhost:8765/login
  Sign in as adaeze.o, bello.m, chidi.n, funmi.a, emeka.k or grace.i, password Razta2026!
  RAZTA decides which factors to ask for; answer them on the simulated devices on the right
  (authenticator app, SMS/USSD phone, security key, fingerprint, agent). If allowed you reach
  the console; the green bar at the top shows the session and lets you test the session monitor.
  Untick devices, pick "Moscow" or "internet-cafe PC" under Context to play an attacker.
  python demo_server.py --open   -> the old behaviour, no login.
  Note: 5 failed sign-ins lock that user until you restart the server.
