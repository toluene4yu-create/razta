"""Picks the global models and sends ONE test request to each, printing exactly what comes back.
Usage:  python test_llms.py"""
import os
import time

import requests

import config
from llm_clients import OpenRouterClient

key = os.environ.get("OPENROUTER_API_KEY", "").strip()
llm = OpenRouterClient()
print("Chosen global models:")
for role, m in llm.models.items():
    print(f"  {role:14s} -> {m}")
good = 0
models = sorted(set(llm.models.values()))
for m in models:
    body = {"model": m, "temperature": 0, "max_tokens": config.LLM_MAX_TOKENS, "reasoning": {"effort": "low"},
            "messages": [{"role": "system", "content": "Reply with one JSON object only."},
                         {"role": "user", "content": "Return {\"threat_level\": 0.2, \"confidence\": 0.9}"}]}
    t0 = time.time()
    try:
        r = requests.post(f"{config.OPENROUTER_URL}/chat/completions", json=body, timeout=config.LLM_TIMEOUT_S,
                          headers={"Authorization": f"Bearer {key}"})
        msg = ((r.json().get("choices") or [{}])[0].get("message") or {}) if r.status_code == 200 else {}
        content = (msg.get("content") or msg.get("reasoning") or "")[:200]
        print(f"\n{m}  HTTP {r.status_code}  {time.time() - t0:.1f}s\ncontent: {content!r}")
        if r.status_code != 200:
            print("body:", r.text[:300])
        elif "{" in content:
            good += 1
    except Exception as e:
        print(f"\n{m}  FAILED after {time.time() - t0:.1f}s: {e}")
print(f"\n{good}/{len(models)} models OK." + ("  ALL GOOD - start the run." if good == len(models) else "  Send this output to Claude."))
