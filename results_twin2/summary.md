# Twin-challenge experiment (Increment 7)

## Part A: 28 access attempts on day 30 (14 legitimate, 14 attacks)

| Condition | Correct | Legitimate admitted | Attacks admitted | Questions per attempt | Mean time (s) |
|---|---|---|---|---|---|
| No twin challenge | 16/28 | 14/14 (FRR 0.0%, CI 0-21.5) | 12/14 (FAR 85.7%, CI 60.1-96.0) | 0 | 12.1 |
| Twin, rule judge | 24/28 | 10/14 (FRR 28.6%, CI 11.7-54.6) | 0/14 (FAR 0.0%, CI 0-21.5) | 1.27 | 0.2 |
| Twin, model judge | 26/28 | 14/14 (FRR 0.0%, CI 0-21.5) | 2/14 (FAR 14.3%, CI 4.0-39.9) | 1.42 | 8.3 |
| Twin, model judge, guards off | 23/28 | 14/14 (FRR 0.0%, CI 0-21.5) | 5/14 (FAR 35.7%, CI 16.3-61.2) | 1.5 | 0.8 |
| Twin, hybrid judge | 28/28 | 14/14 (FRR 0.0%, CI 0-21.5) | 0/14 (FAR 0.0%, CI 0-21.5) | 1.35 | 0.0 |

- **No twin challenge**: by attacker: colleague 2/2 admitted; informed 3/3 admitted; injector 3/3 admitted; thief 4/4 admitted; thief_simswap 0/2 admitted; legitimate refused: none; attacks admitted: TK01|TK02|TK03|TK04|TK05|TK06|TK07|TK08|TK09|TK10|TK11|TK12; injections screened: 0; model questions replaced by template: 0
- **Twin, rule judge**: by attacker: colleague 0/2 admitted; informed 0/3 admitted; injector 0/3 admitted; thief 0/4 admitted; thief_simswap 0/2 admitted; legitimate refused: TA07|TA08|TA11|TA12; attacks admitted: none; injections screened: 3; model questions replaced by template: 0
- **Twin, model judge**: by attacker: colleague 0/2 admitted; informed 1/3 admitted; injector 0/3 admitted; thief 1/4 admitted; thief_simswap 0/2 admitted; legitimate refused: none; attacks admitted: TK01|TK09; injections screened: 3; model questions replaced by template: 0
- **Twin, model judge, guards off**: by attacker: colleague 0/2 admitted; informed 1/3 admitted; injector 3/3 admitted; thief 1/4 admitted; thief_simswap 0/2 admitted; legitimate refused: none; attacks admitted: TK01|TK09|TK10|TK11|TK12; injections screened: 0; model questions replaced by template: 0
- **Twin, hybrid judge**: by attacker: colleague 0/2 admitted; informed 0/3 admitted; injector 0/3 admitted; thief 0/4 admitted; thief_simswap 0/2 admitted; legitimate refused: none; attacks admitted: none; injections screened: 3; model questions replaced by template: 0

Paired exact McNemar tests on correct/incorrect per attempt:
- No twin challenge vs Twin, model judge: 0 attempts only the first got right, 10 only the second; p = 0.002
- Twin, rule judge vs Twin, model judge: 2 attempts only the first got right, 4 only the second; p = 0.6875
- Twin, model judge vs Twin, model judge, guards off: 3 attempts only the first got right, 0 only the second; p = 0.25
- Twin, model judge vs Twin, hybrid judge: 0 attempts only the first got right, 2 only the second; p = 0.5
- Twin, rule judge vs Twin, hybrid judge: 0 attempts only the first got right, 4 only the second; p = 0.125

## Part C: FRESH held-out set, 30 attempts (15 legitimate, 15 attacks)

| Condition | Correct | Legitimate admitted | Attacks admitted | Questions per attempt | Mean time (s) |
|---|---|---|---|---|---|
| Fresh set, rule judge | 22/30 | 7/15 (FRR 53.3%, CI 30.1-75.2) | 0/15 (FAR 0.0%, CI 0-20.4) | 1.14 | 0.7 |
| Fresh set, model judge | 23/30 | 14/15 (FRR 6.7%, CI 1.2-29.8) | 6/15 (FAR 40.0%, CI 19.8-64.3) | 1.31 | 2.8 |
| Fresh set, hybrid judge | 26/30 | 13/15 (FRR 13.3%, CI 3.7-37.9) | 2/15 (FAR 13.3%, CI 3.7-37.9) | 1.24 | 0.0 |

- **Fresh set, rule judge**: by attacker: colleague 0/2 admitted; informed 0/4 admitted; injector 0/3 admitted; thief 0/6 admitted; legitimate refused: PC02|PC03|PC06|PC07|PC08|PC09|PC13|PC15; attacks admitted: none; injections screened: 2; model questions replaced by template: 0
- **Fresh set, model judge**: by attacker: colleague 1/2 admitted; informed 1/4 admitted; injector 1/3 admitted; thief 3/6 admitted; legitimate refused: PC13; attacks admitted: PK01|PK04|PK05|PK09|PK13|PK14; injections screened: 2; model questions replaced by template: 0
- **Fresh set, hybrid judge**: by attacker: colleague 1/2 admitted; informed 0/4 admitted; injector 0/3 admitted; thief 1/6 admitted; legitimate refused: PC09|PC13; attacks admitted: PK01|PK05; injections screened: 2; model questions replaced by template: 0

Paired exact McNemar tests on correct/incorrect per attempt:
- Fresh set, rule judge vs Fresh set, model judge: 6 attempts only the first got right, 7 only the second; p = 1.0
- Fresh set, model judge vs Fresh set, hybrid judge: 1 attempts only the first got right, 4 only the second; p = 0.375
- Fresh set, rule judge vs Fresh set, hybrid judge: 2 attempts only the first got right, 6 only the second; p = 0.2891

## Answers judged (each answer typed at a twin question)

| Condition | Answers | Real user's answer accepted | Attacker's answer accepted | Real user said 'unsure' |
|---|---|---|---|---|
| Twin, rule judge | 33 | 15/19 | 0/12 | 2 |
| Twin, model judge | 37 | 20/20 | 5/15 | 2 |
| Twin, model judge, guards off | 39 | 20/20 | 10/17 | 2 |
| Twin, hybrid judge | 35 | 20/20 | 1/13 | 2 |
| Fresh set, rule judge | 33 | 9/18 | 0/15 | 1 |
| Fresh set, model judge | 38 | 18/20 | 9/18 | 1 |
| Fresh set, hybrid judge | 36 | 17/20 | 3/16 | 1 |
| Rule judge | 44 | 32/36 | 0/5 | 3 |
| Model judge | 45 | 36/36 | 1/6 | 3 |
| Hybrid judge | 44 | 36/36 | 0/5 | 3 |

By answer style (real users):
- exact      Twin, rule judge: 4/4 accepted
- exact      Twin, model judge: 4/4 accepted
- exact      Twin, hybrid judge: 4/4 accepted
- paraphrase Twin, rule judge: 6/7 accepted
- paraphrase Twin, model judge: 7/7 accepted
- paraphrase Twin, hybrid judge: 7/7 accepted
- paraphrase Fresh set, rule judge: 1/3 accepted
- paraphrase Fresh set, model judge: 3/3 accepted
- paraphrase Fresh set, hybrid judge: 2/3 accepted
- terse      Twin, rule judge: 1/2 accepted
- terse      Twin, model judge: 2/2 accepted
- terse      Twin, hybrid judge: 2/2 accepted
- terse      Fresh set, rule judge: 3/5 accepted
- terse      Fresh set, model judge: 5/5 accepted
- terse      Fresh set, hybrid judge: 5/5 accepted
- local      Twin, rule judge: 1/3 accepted
- local      Twin, model judge: 4/4 accepted
- local      Twin, hybrid judge: 4/4 accepted
- local      Fresh set, rule judge: 1/3 accepted
- local      Fresh set, model judge: 4/4 accepted
- local      Fresh set, hybrid judge: 4/4 accepted
- forgot     Twin, rule judge: 3/3 accepted
- forgot     Twin, model judge: 3/3 accepted
- forgot     Twin, hybrid judge: 3/3 accepted
- forgot     Fresh set, rule judge: 1/2 accepted
- forgot     Fresh set, model judge: 1/2 accepted
- forgot     Fresh set, hybrid judge: 1/2 accepted
- typos      Fresh set, rule judge: 1/1 accepted
- typos      Fresh set, model judge: 1/1 accepted
- typos      Fresh set, hybrid judge: 1/1 accepted
- wrong_day  Fresh set, rule judge: 0/1 accepted
- wrong_day  Fresh set, model judge: 0/1 accepted
- wrong_day  Fresh set, hybrid judge: 0/1 accepted

## Part B: the twin grows over eight days (3 users, attacks on days 31, 34, 37)

| Judge | Legitimate logins admitted | Attacks admitted | Memory question used | Twin entries stored | Twin poisoned by an attacker |
|---|---|---|---|---|---|
| Rule judge | 20/24 | 0/9 | 26 | 20 | 0 |
| Model judge | 24/24 | 0/9 | 26 | 24 | 0 |
| Hybrid judge | 24/24 | 0/9 | 26 | 24 | 0 |

Day by day (legitimate admitted / attacks admitted):
- Rule judge: day 30: 3/3, day 31: 3/3, atk 0/3, day 32: 3/3, day 33: 2/3, day 34: 2/3, atk 0/3, day 35: 3/3, day 36: 2/3, day 37: 2/3, atk 0/3
- Model judge: day 30: 3/3, day 31: 3/3, atk 0/3, day 32: 3/3, day 33: 3/3, day 34: 3/3, atk 0/3, day 35: 3/3, day 36: 3/3, day 37: 3/3, atk 0/3
- Hybrid judge: day 30: 3/3, day 31: 3/3, atk 0/3, day 32: 3/3, day 33: 3/3, day 34: 3/3, atk 0/3, day 35: 3/3, day 36: 3/3, day 37: 3/3, atk 0/3

## Run

- Local models: {'identity_gate': 'llama3.2:1b', 'context_retrieval': 'mistral:7b', 'device_trust': 'ministral-3:3b', 'entity_verification': 'gemma2:2b', 'policy_enforcement': 'llama3.2:3b', 'twin_question': 'gemma2:2b', 'twin_judge': 'mistral:7b'}
- Global models: {'orchestrator': 'deepseek/deepseek-v4.1-flash-1017', 'risk_engine': 'moonshotai/kimi-k2.7-code', 'policy_mfa': 'z-ai/glm-5.3-flashx', 'trust_monitor': 'moonshotai/kimi-k2.7-code', 'justification': 'deepseek/deepseek-v4.1-flash-1017'}
- API calls: 2, cache hits: 551, degraded steps: 0, substitutions: {}
- Wall clock: 16.0 min, finished 2026-11-05 09:34
