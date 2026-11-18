# RAZTA pilot experiment: results summary

Run finished 2026-10-23 16:37. Scenarios: 24 (plus 3 ablation runs).

## Models actually used

| Agent | Tier | Model |
|---|---|---|
| identity_gate | local SLM (CPU) | llama3.2:1b |
| context_retrieval | local SLM (CPU) | mistral:7b |
| device_trust | local SLM (CPU) | ministral-3:3b |
| entity_verification | local SLM (CPU) | gemma2:2b |
| policy_enforcement | local SLM (CPU) | llama3.2:3b |
| orchestrator | global LLM (OpenRouter) | deepseek/deepseek-v4.1-flash-1017 |
| risk_engine | global LLM (OpenRouter) | moonshotai/kimi-k2.7-code |
| policy_mfa | global LLM (OpenRouter) | z-ai/glm-5.3-flashx |
| trust_monitor | global LLM (OpenRouter) | moonshotai/kimi-k2.7-code |

## Table 1. Access decisions

| Metric | Classical ZTA | RAZTA |
|---|---|---|
| Correct decisions | 16/24 (66.7%) | 23/24 (95.8%) |
| False accepts (attacks allowed) | 6/10 (60.0%) | 0/10 (0.0%) |
| False rejects (legitimate users denied) | 2/14 (14.3%) | 1/14 (7.1%) |

## Table 2. Live sessions (continuous monitoring)

| Metric | Classical ZTA | RAZTA |
|---|---|---|
| Hijacked sessions terminated | 0/2 | 2/2 |
| Benign sessions left running | 2/2 | 2/2 |
| Step-up challenges issued | 0 | 2 |

## Table 3. Prompt-injection ablation (reflexive guards on vs off)

| Configuration | Attacks that gained access | Injections flagged | LLM trust overrides applied |
|---|---|---|---|
| RAZTA, guards on | 0/3 | 3/3 | 0 |
| RAZTA, guards off | 0/3 | 0/3 | 2 |

Classical ZTA is not exposed to this attack (it has no language model), but it allowed 3/3 of these attackers through its fixed password + SMS OTP rule.

## Table 4. Enumeration resistance

- Probes: 2; all denied: True; identical message to the actor: True; LLM calls spent on probes: 0.

## Table 5. Cost and latency

| Metric | Value |
|---|---|
| Classical ZTA decision time (mean) | 0.022 ms |
| RAZTA decision time, mean / median / p95 | 44.3 s / 37.8 s / 62.5 s |
| of which local SLM time (mean) | 39.5 s |
| of which global LLM time (mean) | 4.7 s |
| LLM API calls / cache hits (all runs) | 23 / 23 |
| RAZTA decisions made with a degraded (rule-only) LLM step | 0 |
| Enforcement SLM: OTP replies parsed correctly | 1/2 (50.0%) |
| Verification SLM: challenge template inside whitelist | 19/19 (100.0%) |

## Limitations to state in the paper

- Synthetic test bed of 24 scenarios on one consumer laptop (16 GB RAM); a pilot, not a statistically powered evaluation.
- Free-tier LLMs vary in availability and rate limits; the models in the table above are the ones actually used.
- Latency on a consumer laptop and free shared API endpoints overstates production latency; the tier split (Figure 3) is the transferable result.
- The human-review step is a deterministic stand-in; session re-scoring uses the rule formula plus an LLM check on trigger events.
- Scenarios were designed by the authors and target RAZTA's stated features; public datasets (LANL, CERT) are future work.

Figures: charts/fig1_decision_quality.png, fig2_by_category.png, fig3_latency_breakdown.png, fig4_injection_ablation.png
Per-scenario detail: results_table.csv