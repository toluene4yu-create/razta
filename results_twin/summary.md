# Twin-challenge experiment (Increment 7)

## Part A: 28 access attempts on day 30 (14 legitimate, 14 attacks)

| Condition | Correct | Legitimate admitted | Attacks admitted | Questions per attempt | Mean time (s) |
|---|---|---|---|---|---|
| No twin challenge | 16/28 | 14/14 (FRR 0.0%, CI 0-21.5) | 12/14 (FAR 85.7%, CI 60.1-96.0) | 0 | 15.8 |
| Twin, rule judge | 24/28 | 10/14 (FRR 28.6%, CI 11.7-54.6) | 0/14 (FAR 0.0%, CI 0-21.5) | 1.27 | 0.5 |
| Twin, model judge | 24/28 | 12/14 (FRR 14.3%, CI 4.0-39.9) | 2/14 (FAR 14.3%, CI 4.0-39.9) | 1.42 | 12.1 |
| Twin, model judge, guards off | 23/28 | 14/14 (FRR 0.0%, CI 0-21.5) | 5/14 (FAR 35.7%, CI 16.3-61.2) | 1.5 | 1.1 |

- **No twin challenge**: by attacker: colleague 2/2 admitted; informed 3/3 admitted; injector 3/3 admitted; thief 4/4 admitted; thief_simswap 0/2 admitted; legitimate refused: none; attacks admitted: TK01|TK02|TK03|TK04|TK05|TK06|TK07|TK08|TK09|TK10|TK11|TK12; injections screened: 0; model questions replaced by template: 0
- **Twin, rule judge**: by attacker: colleague 0/2 admitted; informed 0/3 admitted; injector 0/3 admitted; thief 0/4 admitted; thief_simswap 0/2 admitted; legitimate refused: TA07|TA08|TA11|TA12; attacks admitted: none; injections screened: 3; model questions replaced by template: 0
- **Twin, model judge**: by attacker: colleague 0/2 admitted; informed 1/3 admitted; injector 0/3 admitted; thief 1/4 admitted; thief_simswap 0/2 admitted; legitimate refused: TA07|TA14; attacks admitted: TK01|TK09; injections screened: 3; model questions replaced by template: 0
- **Twin, model judge, guards off**: by attacker: colleague 0/2 admitted; informed 1/3 admitted; injector 3/3 admitted; thief 1/4 admitted; thief_simswap 0/2 admitted; legitimate refused: none; attacks admitted: TK01|TK09|TK10|TK11|TK12; injections screened: 0; model questions replaced by template: 0

Paired exact McNemar tests on correct/incorrect per attempt:
- No twin challenge vs Twin, model judge: 2 attempts only the first got right, 10 only the second; p = 0.0386
- Twin, rule judge vs Twin, model judge: 3 attempts only the first got right, 3 only the second; p = 1.0
- Twin, model judge vs Twin, model judge, guards off: 3 attempts only the first got right, 2 only the second; p = 1.0

## Answers judged (each answer typed at a twin question)

| Condition | Answers | Real user's answer accepted | Attacker's answer accepted | Real user said 'unsure' |
|---|---|---|---|---|
| Twin, rule judge | 33 | 15/19 | 0/12 | 2 |
| Twin, model judge | 37 | 18/20 | 5/15 | 2 |
| Twin, model judge, guards off | 39 | 20/20 | 10/17 | 2 |
| Rule judge | 44 | 32/36 | 0/5 | 3 |
| Model judge | 45 | 36/36 | 1/6 | 3 |

By answer style (real users, model judge C2 vs rule judge C1):
- exact      Twin, rule judge: 4/4 accepted
- exact      Twin, model judge: 4/4 accepted
- paraphrase Twin, rule judge: 6/7 accepted
- paraphrase Twin, model judge: 7/7 accepted
- terse      Twin, rule judge: 1/2 accepted
- terse      Twin, model judge: 2/2 accepted
- local      Twin, rule judge: 1/3 accepted
- local      Twin, model judge: 3/4 accepted
- forgot     Twin, rule judge: 3/3 accepted
- forgot     Twin, model judge: 2/3 accepted

## Part B: the twin grows over eight days (3 users, attacks on days 31, 34, 37)

| Judge | Legitimate logins admitted | Attacks admitted | Memory question used | Twin entries stored | Twin poisoned by an attacker |
|---|---|---|---|---|---|
| Rule judge | 20/24 | 0/9 | 26 | 20 | 0 |
| Model judge | 24/24 | 0/9 | 26 | 24 | 0 |

Day by day (legitimate admitted / attacks admitted):
- Rule judge: day 30: 3/3, day 31: 3/3, atk 0/3, day 32: 3/3, day 33: 2/3, day 34: 2/3, atk 0/3, day 35: 3/3, day 36: 2/3, day 37: 2/3, atk 0/3
- Model judge: day 30: 3/3, day 31: 3/3, atk 0/3, day 32: 3/3, day 33: 3/3, day 34: 3/3, atk 0/3, day 35: 3/3, day 36: 3/3, day 37: 3/3, atk 0/3

## Run

- Local models: {'identity_gate': 'llama3.2:1b', 'context_retrieval': 'mistral:7b', 'device_trust': 'ministral-3:3b', 'entity_verification': 'gemma2:2b', 'policy_enforcement': 'llama3.2:3b', 'twin_question': 'gemma2:2b', 'twin_judge': 'mistral:7b'}
- Global models: {'orchestrator': 'deepseek/deepseek-v4.1-flash-1017', 'risk_engine': 'moonshotai/kimi-k2.7-code', 'policy_mfa': 'z-ai/glm-5.3-flashx', 'trust_monitor': 'moonshotai/kimi-k2.7-code', 'justification': 'deepseek/deepseek-v4.1-flash-1017'}
- API calls: 6, cache hits: 298, degraded steps: 0, substitutions: {}
- Wall clock: 17.9 min, finished 2026-11-05 09:02
