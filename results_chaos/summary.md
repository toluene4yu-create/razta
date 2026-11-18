| Cond. | Fault | Correct | Legit. admitted | Attacks admitted | Hijacks ended | Benign kept | Refused, verification incomplete | Degraded | Mean time (s) |
|---|---|---|---|---|---|---|---|---|---|
| N0 | Normal operation (no fault) | 23/24 | 13/14 (92.9%) | 0/10 | 2/2 | 2/2 | 0/24 | 0 | 14.8 |
| A1 | Identity Gate agent crashes | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 24/24 | 0 | 0.0 |
| A2 | Context and Log Retrieval agent crashes | 24/24 | 14/14 (100.0%) | 0/10 | 2/2 | 2/2 | 0/24 | 22 | 2.6 |
| A3 | Device and Endpoint Trust agent crashes | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 0/24 | 22 | 1.8 |
| A4 | Risk and Trust Engine agent crashes | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 22/24 | 0 | 0.0 |
| A5 | Policy and Adaptive MFA agent crashes | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 19/24 | 0 | 0.0 |
| A6 | Entity Verification agent crashes | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 19/24 | 0 | 0.0 |
| A7 | Policy Enforcement agent crashes | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 19/24 | 0 | 0.0 |
| A8 | Continuous Trust Monitor crashes during the session | 21/24 | 13/14 (92.9%) | 0/10 | 2/2 | 0/2 | 0/24 | 0 | 0.2 |
| O1 | Orchestrator stops mid-decision (after scoring, before policy) | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 19/24 | 0 | 0.0 |
| D1 | 2 s delay on every inter-agent message | 24/24 | 14/14 (100.0%) | 0/10 | 2/2 | 2/2 | 0/24 | 0 | 15.8 |
| D2 | 5 s delay on every inter-agent message | 23/24 | 13/14 (92.9%) | 0/10 | 2/2 | 2/2 | 0/24 | 0 | 39.1 |
| D3 | 10 s delay on every inter-agent message | 24/24 | 14/14 (100.0%) | 0/10 | 2/2 | 2/2 | 0/24 | 0 | 77.9 |
| D4 | 20 s delay on every inter-agent message | 23/24 | 13/14 (92.9%) | 0/10 | 2/2 | 2/2 | 0/24 | 0 | 155.7 |
| D5 | 30 s delay on every inter-agent message | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 19/24 | 0 | 175.9 |
| S1 | Local model server (Ollama) unreachable | 23/24 | 13/14 (92.9%) | 0/10 | 2/2 | 2/2 | 0/24 | 0 | 2.6 |
| S2 | Global model API (OpenRouter) unreachable | 23/24 | 13/14 (92.9%) | 0/10 | 2/2 | 2/2 | 0/24 | 22 | 0.2 |
| S3 | Access-log store unreachable | 23/24 | 13/14 (92.9%) | 0/10 | 2/2 | 2/2 | 0/24 | 22 | 0.2 |
| S4 | Threat-intelligence feed unreachable | 24/24 | 14/14 (100.0%) | 0/10 | 2/2 | 2/2 | 0/24 | 22 | 3.2 |
| S5 | Signed policy store unreachable | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 19/24 | 0 | 0.0 |
| A2s | Context agent crashes (strict policy) | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 22/24 | 0 | 0.0 |
| A3s | Device agent crashes (strict policy) | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 22/24 | 0 | 0.0 |
| S3s | Access-log store unreachable (strict policy) | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 22/24 | 0 | 0.0 |
| S4s | Threat-intelligence feed unreachable (strict policy) | 10/24 | 0/14 (0.0%) | 0/10 | 0/2 | 0/2 | 22/24 | 0 | 0.0 |

Unhandled crashes across all conditions: 0. Attacks admitted across all fault conditions: 0.