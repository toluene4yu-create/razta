"""RAZTA experiment configuration. Edit values here, not in the other files."""

# ---------- Local tier: small language models served by Ollama on your CPU ----------
OLLAMA_URL = "http://localhost:11434"
SLM = {
    "identity_gate":       "llama3.2:1b",
    "context_retrieval":   "mistral:7b",
    "device_trust":        "ministral-3:3b",
    "entity_verification": "gemma2:2b",
    "policy_enforcement":  "llama3.2:3b",
    "twin_question":       "gemma2:2b",     # Increment 7, Stage 4: words the personal question
    "twin_judge":          "mistral:7b",    # Increment 7, Stage 5: judges the answer (stays local: twin data never leaves)
}
# If a model is not installed, use this substitute instead (the substitution is recorded).
SLM_FALLBACK = {
    "ministral-3:3b": "llama3.2:3b",
    "mistral:7b": "llama3.2:3b",
    "gemma2:2b": "llama3.2:1b",
    "llama3.2:3b": "llama3.2:1b",
}
SLM_TIMEOUT_S = 300          # CPUs are slow; give each call up to 5 minutes
SLM_MAX_TOKENS = 120

# ---------- Global tier: large language models via OpenRouter free API ----------
OPENROUTER_URL = "https://openrouter.ai/api/v1"
# The script looks at OpenRouter's live list of free models and picks the first match
# for each keyword, in order. Free models change often, so this is keyword-based.
LLM_PREFS = {
    "orchestrator":  ["deepseek", "qwen", "glm", "kimi"],
    "risk_engine":   ["kimi", "moonshot", "glm", "qwen", "deepseek"],
    "policy_mfa":    ["glm", "z-ai", "qwen", "deepseek"],
    "trust_monitor": ["kimi", "moonshot", "glm", "deepseek", "qwen"],
    "justification": ["deepseek", "glm", "qwen", "kimi"],
}
# If none of the preferred families is free today, try these large open models next.
LLM_FALLBACK_KEYWORDS = ["gpt-oss-120b", "llama-3.3-70b", "llama-4", "nemotron", "mistral-small",
                         "gemma-3-27b", "hermes", "gpt-oss"]
# You can force exact model IDs here instead, e.g. "deepseek/deepseek-chat-v3.1:free"
LLM_OVERRIDE = {}
# The free endpoints were unreliable (upstream rate limits / provider errors), so with credit on the
# account we use low-cost PAID endpoints of the planned open-weight families. A full run costs well under $1.
USE_PAID_MODELS = True
PAID_PREFS = {   # matched against model IDs in OpenRouter's list (newest first)
    "orchestrator":  ["deepseek/deepseek-v4", "deepseek/deepseek-chat", "deepseek/", "qwen/"],
    "risk_engine":   ["moonshotai/kimi-k2", "moonshotai/", "z-ai/glm", "qwen/"],
    "policy_mfa":    ["z-ai/glm", "qwen/qwen3", "deepseek/"],
    "trust_monitor": ["moonshotai/kimi-k2", "moonshotai/", "z-ai/glm", "qwen/"],
    "justification": ["deepseek/deepseek-v4", "deepseek/deepseek-chat", "deepseek/", "z-ai/glm"],   # Increment 6
}
MAX_PRICE_IN = 1.50    # US$ per million input tokens
MAX_PRICE_OUT = 5.00   # US$ per million output tokens
LLM_TIMEOUT_S = 240
LLM_MAX_TOKENS = 3000
SECONDS_BETWEEN_LLM_CALLS = 3.5   # free tier allows about 20 requests per minute
MAX_LLM_CALLS = 400               # safety cap on API calls per run

# ---------- RAZTA parameters (from the redesign document; illustrative, tunable) ----------
WEIGHTS = {"I": 0.30, "D": 0.25, "B": 0.20, "P": 0.15, "S": 0.10}
THETA_HI = 0.80     # T >= this -> LOW risk band
THETA_LO = 0.50     # T <  this -> HIGH risk band
THETA_G = 0.50      # identity-gate claim-shape threshold
THETA_C = 0.70      # confidence below this -> escalate / arbitrate
DELTA = 0.10        # tolerated trust drop during a session
MVM_EXPIRY_S = 120
LOCKOUT_FAILURES = 5
ACCESS_TTL_MIN = 15

RANDOM_SEED = 42

# ---------- Resilience (chaos experiment) ----------
DECISION_DEADLINE_S = 180      # a decision not reached within this time is refused (fail closed)
OTP_RULE_FIRST = False        # Increment 7 fix for the A6 error: read USSD/SMS codes with a parser first,
                              # and ask the model only if the parser fails (the twin experiment sets True)
FAULT_POLICY = "conservative"  # "conservative": advisory inputs (context, device, threat intel) degrade to
                               # worst-case values; "strict": any fault refuses the request
