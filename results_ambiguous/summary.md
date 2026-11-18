# Ambiguous-case experiment: results

Labels used: independent labeller (agreement with design labels: 14/16)

| System | Correct | 95% CI | Wrongly allowed (should be refused) | Wrongly refused (should be allowed) |
|---|---|---|---|---|
| RBA | 10/16 | 0.39-0.82 | 5 ['H04', 'H05', 'H11', 'H12', 'H16'] | 1 ['H07'] |
| RAZTA-rules | 11/16 | 0.44-0.86 | 4 ['H04', 'H05', 'H11', 'H16'] | 1 ['H07'] |
| RAZTA-rules+regex | 12/16 | 0.51-0.90 | 3 ['H05', 'H11', 'H16'] | 1 ['H14'] |
| RAZTA-models | 11/16 | 0.44-0.86 | 2 ['H11', 'H16'] | 3 ['H01', 'H06', 'H07'] |
| RAZTA-models+tighten | 10/16 | 0.39-0.82 | 2 ['H11', 'H16'] | 4 ['H01', 'H06', 'H07', 'H14'] |
| RAZTA-models+bounded | 12/16 | 0.51-0.90 | 1 ['H16'] | 3 ['H01', 'H06', 'H14'] |

## Paired comparisons (exact McNemar test on the same 16 cases)

| A | B | A right, B wrong | B right, A wrong | p |
|---|---|---|---|---|
| RAZTA-rules | RAZTA-models | 2 | 2 | 1.000 |
| RAZTA-models | RAZTA-models+tighten | 1 | 0 | 1.000 |
| RAZTA-models | RAZTA-models+bounded | 1 | 2 | 1.000 |
| RAZTA-rules+regex | RAZTA-models+bounded | 2 | 2 | 1.000 |
| RBA | RAZTA-models+bounded | 3 | 5 | 0.727 |

## Case by case

| Case | Label | RBA | RAZTA-rules | RAZTA-rules+regex | RAZTA-models | RAZTA-models+tighten | RAZTA-models+bounded |
|---|---|---|---|---|---|---|---|
| H01 | allow | allow (-) ok | allow (MEDIUM) ok | allow (MEDIUM) ok | deny (HIGH) WRONG | deny (HIGH) WRONG | deny (HIGH) WRONG |
| H02 | deny | deny (-) ok | deny (HIGH) ok | deny (HIGH) ok | deny (HIGH) ok | deny (HIGH) ok | deny (HIGH) ok |
| H03 | allow | allow (-) ok | allow (LOW) ok | allow (LOW) ok | allow (LOW) ok | allow (LOW) ok | allow (LOW) ok |
| H04 | deny | allow (-) WRONG | allow (MEDIUM) WRONG | deny (HIGH) ok | deny (HIGH) ok | deny (HIGH) ok | deny (HIGH) ok |
| H05 | deny | allow (-) WRONG | allow (MEDIUM) WRONG | allow (MEDIUM) WRONG | deny (HIGH) ok | deny (HIGH) ok | deny (HIGH) ok |
| H06 | allow | allow (-) ok | allow (MEDIUM) ok | allow (LOW) ok | deny (HIGH) WRONG | deny (HIGH) WRONG | deny (HIGH) WRONG |
| H07 | allow | deny (-) WRONG | deny (HIGH) WRONG | allow (MEDIUM) ok | deny (HIGH) WRONG | deny (HIGH) WRONG | allow (MEDIUM) ok |
| H08 | deny | deny (-) ok | deny (HIGH) ok | deny (MEDIUM) ok | deny (HIGH) ok | deny (HIGH) ok | deny (MEDIUM) ok |
| H09 | allow | allow (-) ok | allow (MEDIUM) ok | allow (MEDIUM) ok | allow (MEDIUM) ok | allow (MEDIUM) ok | allow (MEDIUM) ok |
| H10 | deny | deny (-) ok | deny (HIGH) ok | deny (HIGH) ok | deny (HIGH) ok | deny (HIGH) ok | deny (HIGH) ok |
| H11 | deny | allow (-) WRONG | allow (LOW) WRONG | allow (LOW) WRONG | allow (LOW) WRONG | allow (LOW) WRONG | deny (LOW) ok |
| H12 | deny | allow (-) WRONG | deny (MEDIUM) ok | deny (MEDIUM) ok | deny (MEDIUM) ok | deny (HIGH) ok | deny (HIGH) ok |
| H13 | deny | deny (-) ok | deny (MEDIUM) ok | deny (HIGH) ok | deny (HIGH) ok | deny (HIGH) ok | deny (HIGH) ok |
| H14 | allow | allow (-) ok | allow (LOW) ok | deny (HIGH) WRONG | allow (MEDIUM) ok | deny (HIGH) WRONG | deny (HIGH) WRONG |
| H15 | deny | deny (-) ok | deny (MEDIUM) ok | deny (LOW) ok | deny (HIGH) ok | deny (HIGH) ok | deny (MEDIUM) ok |
| H16 | deny | allow (-) WRONG | allow (LOW) WRONG | allow (LOW) WRONG | allow (LOW) WRONG | allow (MEDIUM) WRONG | allow (MEDIUM) WRONG |

## What the justification agent extracted (model) and what code found

| Case | Mode | Claim | Ref | Record check | Red flags | Assessment | Plausibility | Band change |
|---|---|---|---|---|---|---|---|---|
| H01 | bounded | none |  | none | urgency_pressure | supports | 0.78 | +1 |
| H01 | tighten | none |  | none | urgency_pressure | supports | 0.78 | +1 |
| H02 | bounded | oncall |  | contradicted | urgency_pressure | supports | 0.8 | +1 |
| H02 | tighten | oncall |  | contradicted | urgency_pressure | supports | 0.8 | +1 |
| H03 | bounded | ticket | INC-4471 | verified |  | supports | 0.9 | -1 |
| H03 | tighten | ticket | INC-4471 | verified |  | supports | 0.9 | +0 |
| H04 | bounded | ticket | CHG-2290 | contradicted |  | supports | 0.7 | +1 |
| H04 | tighten | ticket | CHG-2290 | contradicted |  | supports | 0.7 | +1 |
| H05 | bounded | none |  | none | urgency_pressure|authority_pressure|inconsistent_with_request|vague | undermines | 0.2 | +1 |
| H05 | tighten | none |  | none | urgency_pressure|authority_pressure|inconsistent_with_request|vague | undermines | 0.2 | +1 |
| H06 | bounded | ticket | PAY-1102 | verified | urgency_pressure | supports | 0.8 | +1 |
| H06 | tighten | ticket | PAY-1102 | verified | urgency_pressure | supports | 0.8 | +1 |
| H07 | bounded | travel |  | verified |  | supports | 0.7 | -1 |
| H07 | tighten | travel |  | verified |  | supports | 0.7 | +0 |
| H08 | bounded | travel |  | verified |  | supports | 0.65 | -1 |
| H08 | tighten | travel |  | verified |  | supports | 0.65 | +0 |
| H09 | bounded | ticket | ONB-310 | verified |  | supports | 0.85 | -1 |
| H09 | tighten | ticket | ONB-310 | verified |  | supports | 0.85 | +0 |
| H10 | bounded | none |  | none | vague|authority_pressure|inconsistent_with_request | undermines | 0.3 | +1 |
| H10 | tighten | none |  | none | vague|authority_pressure|inconsistent_with_request | undermines | 0.3 | +1 |
| H11 | bounded | ticket | PAY-1103 | verified |  | supports | 0.78 | -1 |
| H11 | tighten | ticket | PAY-1103 | verified |  | supports | 0.78 | +0 |
| H12 | bounded | none |  | none | urgency_pressure|authority_pressure|vague | undermines | 0.3 | +1 |
| H12 | tighten | none |  | none | urgency_pressure|authority_pressure|vague | undermines | 0.3 | +1 |
| H13 | bounded | none |  | none |  | neutral | None | +0 (screened: instructions in text) |
| H13 | tighten | none |  | none |  | neutral | None | +0 (screened: instructions in text) |
| H14 | bounded | none |  | none |  | neutral | None | +0 (screened: instructions in text) |
| H14 | tighten | none |  | none |  | neutral | None | +0 (screened: instructions in text) |
| H15 | bounded | ticket | INC-4471 | verified |  | supports | 0.85 | -1 |
| H15 | tighten | ticket | INC-4471 | verified |  | supports | 0.85 | +0 |
| H16 | bounded | none |  | none | vague|urgency_pressure | undermines | 0.2 | +1 |
| H16 | tighten | none |  | none | vague|urgency_pressure | undermines | 0.2 | +1 |

Mean decision time with models: 8.5 s (n = 47).

Run log: 2026-10-24 14:18 LLM calls 0, cache hits 0, degraded 0; 2026-10-24 14:27 LLM calls 28, cache hits 68, degraded 0
