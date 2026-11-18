"""Checks that everything is ready and times each small model on your CPU.
Usage:  python check_setup.py"""
import os
import sys
import time

print("Python", sys.version.split()[0])
try:
    import matplotlib  # noqa: F401
    import requests
except ImportError as e:
    sys.exit(f"Missing package: {e.name}. Run:  pip install -r requirements.txt")

import config
from llm_clients import OllamaClient

ok = True
# 1. Ollama and the five small models
try:
    slm = OllamaClient()
    print("Ollama: running. Installed models:", ", ".join(sorted(slm.installed)) or "none")
except SystemExit as e:
    print("PROBLEM:", e)
    sys.exit(1)

total = 0.0
for role, model in config.SLM.items():
    try:
        real = slm.resolve(model)
    except SystemExit as e:
        print(f"PROBLEM: {e}")
        ok = False
        continue
    sub = "" if real == model else f"  (not installed, will use {real} instead)"
    print(f"Timing {role:22s} {real:16s} ...", end=" ", flush=True)
    out, raw, dt = slm.chat_json(model, "Return JSON {\"ok\": true}.", "ping")
    total += dt
    print(f"{dt:6.1f} s  reply={'OK' if out is not None else 'NO JSON: ' + raw[:60]}{sub}")
    if dt > 120:
        print(f"   NOTE: {real} is very slow on this CPU. In config.py you can change it to \"llama3.2:3b\".")

# 2. OpenRouter key and free models
key = os.environ.get("OPENROUTER_API_KEY", "").strip()
if not key:
    print("PROBLEM: OPENROUTER_API_KEY not set in this PowerShell window (README step 7).")
    ok = False
else:
    try:
        r = requests.get(f"{config.OPENROUTER_URL}/key", headers={"Authorization": f"Bearer {key}"}, timeout=30)
        if r.status_code != 200:
            print("PROBLEM: OpenRouter rejected the key:", r.status_code, r.text[:120])
            ok = False
        else:
            info = r.json().get("data", {})
            print("OpenRouter key: valid.", "Free-tier key (about 50 free requests/day)." if info.get("is_free_tier") else "")
            from llm_clients import OpenRouterClient
            llm = OpenRouterClient()
            print("Free models available today:", ", ".join(getattr(llm, "free_models", [])))
            for role, m in llm.models.items():
                print(f"Global {role:14s} -> {m}")
    except Exception as e:
        print("PROBLEM reaching OpenRouter:", e)
        ok = False

print()
if ok:
    est = total * 24 * 1.3 / 60 + 3
    print(f"ALL GOOD. Rough estimate for the full experiment on this PC: {est:.0f} minutes.")
    print("Next:  python run_experiment.py")
else:
    print("Fix the PROBLEM lines above, then run this check again.")
