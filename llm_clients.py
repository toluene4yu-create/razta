"""Clients for the local SLMs (Ollama) and global LLMs (OpenRouter), with a disk cache,
a call budget, and a mock mode for testing the pipeline without any model."""
import hashlib
import json
import os
import re
import time

import requests

import config

CACHE_FILE = os.path.join(os.path.dirname(__file__), "cache", "llm_cache.json")


def extract_json(text):
    """Pull the first JSON object out of a model reply. Returns dict or None."""
    if not text:
        return None
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        obj = json.loads(text[start:end + 1])
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


class Cache:
    def __init__(self):
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        try:
            with open(CACHE_FILE, encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, json.JSONDecodeError):
            self.data = {}

    @staticmethod
    def key(model, system, user):
        return hashlib.sha256(f"{model}\n{system}\n{user}".encode()).hexdigest()

    def get(self, k):
        return self.data.get(k)

    def put(self, k, v):
        self.data[k] = v
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        os.replace(tmp, CACHE_FILE)


class Stats:
    def __init__(self):
        self.slm_calls = 0
        self.llm_calls = 0
        self.llm_cache_hits = 0
        self.llm_failures = 0
        self.degraded = 0
        self.substitutions = {}
        self.llm_models = {}


STATS = Stats()


class OllamaClient:
    def __init__(self, mock=False, memo=False):
        self.mock = mock
        self.memo = {} if memo else None     # reuse identical SLM calls within one run (same input -> same output)
        self.installed = set()
        if not mock:
            try:
                r = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=10)
                self.installed = {m["name"] for m in r.json().get("models", [])}
            except Exception as e:
                raise SystemExit(f"Cannot reach Ollama at {config.OLLAMA_URL}. Is Ollama running? ({e})")

    def resolve(self, model):
        if self.mock:
            return model
        names = self.installed | {n.split(":")[0] + ":latest" for n in self.installed}
        m = model
        seen = set()
        while m not in names and m not in seen:
            seen.add(m)
            m = config.SLM_FALLBACK.get(m, m)
        if m not in names:
            raise SystemExit(f"Model {model} (and its fallbacks) not installed. Run: ollama pull {model}")
        if m != model:
            STATS.substitutions[model] = m
        return m

    def chat_json(self, model, system, user, mock_fn=None):
        """Returns (dict_or_None, raw_text, seconds)."""
        STATS.slm_calls += 1
        t0 = time.perf_counter()
        if self.mock:
            out = mock_fn() if mock_fn else {}
            return out, json.dumps(out), time.perf_counter() - t0
        model = self.resolve(model)
        mk = (model, system, user)
        if self.memo is not None and mk in self.memo:
            out, raw = self.memo[mk]
            return out, raw, 0.0
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "format": "json",
            "stream": False,
            "keep_alive": "10m",
            "options": {"temperature": 0, "num_predict": config.SLM_MAX_TOKENS, "seed": config.RANDOM_SEED},
        }
        try:
            r = requests.post(f"{config.OLLAMA_URL}/api/chat", json=body, timeout=config.SLM_TIMEOUT_S)
            raw = r.json().get("message", {}).get("content", "")
            if extract_json(raw) is None:   # some models return nothing in JSON mode: retry in plain mode
                body.pop("format", None)
                body["messages"][0]["content"] += " Output only the JSON object, nothing else."
                r = requests.post(f"{config.OLLAMA_URL}/api/chat", json=body, timeout=config.SLM_TIMEOUT_S)
                raw = r.json().get("message", {}).get("content", "")
        except Exception as e:
            raw = f"ERROR: {e}"
        if self.memo is not None and extract_json(raw) is not None:
            self.memo[mk] = (extract_json(raw), raw)
        return extract_json(raw), raw, time.perf_counter() - t0


class BudgetExhausted(Exception):
    pass


class OpenRouterClient:
    def __init__(self, mock=False):
        self.mock = mock
        self.cache = Cache()
        self.last_call = 0.0
        self.exhausted = False
        self.key = os.environ.get("OPENROUTER_API_KEY", "").strip()
        self.models = {}
        if not mock:
            if not self.key:
                raise SystemExit("OPENROUTER_API_KEY is not set. See README step 7.")
            self.models = self._pick_models()
        else:
            self.models = {role: f"mock/{role}" for role in config.LLM_PREFS}
        STATS.llm_models = dict(self.models)

    def _pick_models(self):
        r = requests.get(f"{config.OPENROUTER_URL}/models", timeout=30)
        free = []
        for m in r.json().get("data", []):
            p = m.get("pricing", {})
            if m["id"].endswith(":free") or (str(p.get("prompt")) in ("0", "0.0") and str(p.get("completion")) in ("0", "0.0")):
                free.append(m["id"])
        self.free_models = sorted(free)
        if not free:
            raise SystemExit("OpenRouter returned no free models right now.")
        if getattr(config, "USE_PAID_MODELS", False):
            return self._pick_paid(r.json().get("data", []))
        chosen = {}
        for role, prefs in config.LLM_PREFS.items():
            if role in config.LLM_OVERRIDE:
                chosen[role] = config.LLM_OVERRIDE[role]
                continue
            pick = next((f for kw in list(prefs) + config.LLM_FALLBACK_KEYWORDS for f in free
                         if kw in f.lower()), free[0])
            chosen[role] = pick
        return chosen

    def _pick_paid(self, data):
        """Cheapest-tier paid open-weight models from the planned families (DeepSeek, Kimi, GLM, Qwen)."""
        bad = ("vl", "vision", "image", "audio", "embed", "guard", "coder", "math", "distill", "free", "omni")
        ok = []
        for m in data:
            mid = m["id"].lower()
            p = m.get("pricing", {})
            try:
                pin, pout = float(p.get("prompt", 0)) * 1e6, float(p.get("completion", 0)) * 1e6
            except (TypeError, ValueError):
                continue
            if pin <= 0 or pin > config.MAX_PRICE_IN or pout > config.MAX_PRICE_OUT or any(b in mid for b in bad):
                continue
            ok.append(m["id"])
        self.free_models = ok
        chosen = {}
        for role, prefs in config.PAID_PREFS.items():
            if role in config.LLM_OVERRIDE:
                chosen[role] = config.LLM_OVERRIDE[role]
                continue
            pick = next((f for kw in prefs for f in ok if f.lower().startswith(kw)), None)
            if pick is None:
                raise SystemExit(f"No affordable model found for {role}; set LLM_OVERRIDE in config.py")
            chosen[role] = pick
        return chosen

    def chat_json(self, role, system, user, mock_fn=None):
        """Returns (dict_or_None, raw_text, seconds, source) where source is
        'llm', 'cache', 'mock' or 'degraded' (budget/rate limit/failure)."""
        model = self.models[role]
        k = Cache.key(model, system, user)
        t0 = time.perf_counter()
        hit = self.cache.get(k)
        if hit is not None:
            STATS.llm_cache_hits += 1
            return extract_json(hit), hit, time.perf_counter() - t0, "cache"
        if self.mock:
            out = mock_fn() if mock_fn else {}
            raw = json.dumps(out)
            return out, raw, time.perf_counter() - t0, "mock"
        if self.exhausted or STATS.llm_calls >= config.MAX_LLM_CALLS:
            STATS.degraded += 1
            with open(os.path.join(os.path.dirname(CACHE_FILE), "llm_errors.log"), "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%H:%M:%S')} {role} {model}: skipped, call budget used up\n")
            return None, "", time.perf_counter() - t0, "degraded"
        wait = config.SECONDS_BETWEEN_LLM_CALLS - (time.time() - self.last_call)
        if wait > 0:
            time.sleep(wait)
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system + " Reply with one JSON object only."},
                         {"role": "user", "content": user}],
            "temperature": 0,
            "max_tokens": config.LLM_MAX_TOKENS,
            "reasoning": {"effort": "low"},
        }
        headers = {"Authorization": f"Bearer {self.key}", "X-Title": "RAZTA experiment"}
        raw = ""
        for attempt in range(3):
            self.last_call = time.time()
            STATS.llm_calls += 1
            try:
                r = requests.post(f"{config.OPENROUTER_URL}/chat/completions", json=body,
                                  headers=headers, timeout=config.LLM_TIMEOUT_S)
                if r.status_code == 429:
                    msg = r.text.lower()
                    if "per-day" in msg or "per day" in msg or "daily" in msg or "free-models-per-day" in msg:
                        self.exhausted = True
                        break
                    time.sleep(20 * (attempt + 1))
                    continue
                if r.status_code >= 400:
                    raw = f"HTTP {r.status_code}: {r.text[:200]}"
                    time.sleep(5)
                    continue
                choices = r.json().get("choices") or [{}]
                msg = choices[0].get("message") or {}
                raw = msg.get("content") or msg.get("reasoning") or ""
                if extract_json(raw) is not None:
                    self.cache.put(k, raw)
                    return extract_json(raw), raw, time.perf_counter() - t0, "llm"
            except Exception as e:
                raw = f"ERROR: {e}"
                time.sleep(5)
        STATS.llm_failures += 1
        STATS.degraded += 1
        why = "daily free limit reached" if self.exhausted else raw[:400].replace("\n", " ")
        with open(os.path.join(os.path.dirname(CACHE_FILE), "llm_errors.log"), "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {role} {model}: {why or 'empty reply / no JSON'}\n")
        return None, raw, time.perf_counter() - t0, "degraded"


class RuleSLM:
    """'Models off' condition: every local-model step uses its deterministic rule stand-in."""
    def chat_json(self, model, system, user, mock_fn=None):
        out = mock_fn() if mock_fn else {}
        return out, json.dumps(out), 0.0


class RuleLLM:
    """'Models off' condition for the global tier (never reads the cache, never calls the API)."""
    models = {}

    def chat_json(self, role, system, user, mock_fn=None):
        out = mock_fn() if mock_fn else {}
        return out, json.dumps(out), 0.0, "rule"
