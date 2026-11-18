RAZTA TWIN-CHALLENGE EXPERIMENT (Increment 7) - HOW TO RUN
==========================================================
The idea being tested
  RAZTA keeps an identity digital twin of each person. After every granted session it asks
  "what did you work on?" and stores the answer. At the next login, once the normal factors pass,
  it asks a personal question built from the twin (the stored answer, which system they opened
  last, when they last signed in). A small LOCAL model words the question and judges the answer,
  so the twin never leaves the laptop. Code makes the final decision.

What changed in the code
  twin_challenge.py   NEW  question planning, question wording (Stage 4), answer judging (Stage 5),
                           twin memory and the "what did you work on?" store (Twin Builder, Stage 1c)
  personas.py         NEW  the synthetic people: work diaries, natural answers (incl. Pidgin, Yoruba,
                           Hausa) and what each kind of attacker could guess
  twin_experiment.py  NEW  runs the experiment;   analyze_twin.py  NEW  summarises it
  agents.py           the twin factor added to the factor ladder (always last), new signed message
                      types TWINQ / TWINV / TWINU, and the A6 fix (USSD code read by a parser first)
  config.py           two local model roles added: twin_question = gemma2:2b, twin_judge = mistral:7b;
                      OTP_RULE_FIRST setting
  scenarios.py        the factor "twin_challenge" added to the factor list
  Your earlier experiments are unchanged: with the twin challenge off (the default), the original
  24 scenarios and the chaos run behave exactly as before.

Steps (PowerShell, inside this razta folder)
  1. Ollama running (ollama list shows the five models; no new model is needed).
  2. $env:OPENROUTER_API_KEY="your key"
  3. Plumbing check (5 seconds, fake model replies - its numbers mean NOTHING):
        python twin_experiment.py --mock --fresh
        python analyze_twin.py --mock
  4. Real run (about 1.5-2.5 hours; laptop plugged in, other apps closed):
        python twin_experiment.py --fresh
     If it stops, run   python twin_experiment.py   again - it resumes.
  5. Summarise:   python analyze_twin.py
  6. Send back the whole results_twin folder (raw.jsonl, summary.md, summary_A.csv, summary_B.csv,
     answers.csv, run_meta.json, twin_partA.png, twin_partB.png) and a screenshot of the console.

Part A - 28 attempts on day 30, four conditions
  14 real users answering in different ways (close wording, paraphrase, one word, Pidgin/Yoruba/Hausa,
  "I can't remember" then a second question). 14 attacks: a thief with the stolen laptop and phone,
  a colleague on the shared computer, an attacker who studied the victim's social media, an attacker
  who types instructions into the answer box, and the two SIM-swap attacks from the paper (C1, C4).
    C0  no twin challenge (the factor ladder from the paper)
    C1  twin challenge, rule judge (keywords and numbers, no model)
    C2  twin challenge, model judge, guards on
    C3  twin challenge, model judge, twin guards off (no answer screening, no leak check)
Part B - the twin grows
  Three users sign in once a day for eight days starting with an EMPTY twin memory; on days 31, 34
  and 37 an attacker with their stolen devices tries first. Run with the rule judge and the model judge.

RUN 2 (after run 1, 5 Nov 2026) - two fixes and a fresh test set
=================================================================
Fix 1  The guarded judge only accepted the model's verdict in exact lowercase, so "Match" counted as a
       fail. Verdicts are now read regardless of case and punctuation. (A programming slip in run 1.)
Fix 2  New "hybrid" judge (condition C4 / B-hybrid / Part C C4): the model's "match" on the memory
       question also needs at least one SPECIFIC word in common with what the twin stored (generic work
       words such as "records", "files", "reports", "working" do not count). The rule still accepts an
       answer it matches. This was designed AFTER seeing run 1, which is why Part C exists.
Part C A FRESH held-out set of 30 attempts written before any run of the fixes: different stored answers
       (each user's day-32 entry), fully written answers including full Hausa and Yoruba, typos, a
       paraphrase with no word in common, a real user who mixes up days, an insider who overheard part
       of the day's work, an informed attacker who knows the user's office city, an instruction written
       in Pidgin that the screening patterns do not catch, and an attacker who says "I don't know"
       to get the replacement question. Run with the rule, model and hybrid judges.
Results go to results_twin2 (run 1 stays untouched in results_twin).

Steps (PowerShell in C:\Users\tolua\razta-exp\razta, Ollama running)
  $env:OPENROUTER_API_KEY="your key"
  python twin_experiment.py --mock --fresh     (5-second check; numbers mean nothing)
  python twin_experiment.py --fresh            (real run, about 30-60 minutes)
  python analyze_twin.py

TEST APP (login portal) - the personal question is now part of the sign-in
==========================================================================
  python demo_server.py      then sign in at http://localhost:8765/login
  - After the usual factors, RAZTA asks a personal question built from the user's identity twin.
  - After a granted sign-in it asks "what did you work on?" and stores the answer for next time.
  - The right-hand panel has "Your memory (what the real user knows)". Untick "with me" to play an
    attacker who has the stolen devices but not the memories.
  - Engines: "Rules only" uses the rule judge; "Simulated" and "Live models" use the hybrid judge.
  - The twin memory is saved in twin_memory.json in this folder. Delete that file to start afresh.
