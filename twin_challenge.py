"""Increment 7 - Twin-based personal challenge (the original reason RAZTA is agentic).

How it works, in plain terms:
  1. The identity digital twin keeps two things about each person:
       - behaviour from their access records (which system they opened last, when they last logged in)
       - a short "memory": at the end of every granted session RAZTA asks "what did you work on?"
         and keeps the answer for the next visit                       (Twin Builder, Stage 1c)
  2. At the next login, once the other factors pass, RAZTA asks a personal question built from the
     twin. A small local model words the question in the user's language    (Entity Verification, Stage 4)
  3. The answer is judged. Two judges are compared:
       rule  - keyword / number matching, no model
       model - a local model decides whether the answer means the same as the twin's record
     The model only returns a verdict word; code decides                    (Policy Enforcement, Stage 5)
  4. After a granted session, a new "what did you work on?" answer is stored (twin grows).

Questions: LOW band -> one question; MEDIUM or HIGH band -> two questions (memory + behaviour).
A person who says they cannot remember ("unsure") gets ONE replacement question.
A wrong answer fails the factor at once.
All twin data stays in the local tier (it never goes to the cloud models).

Guards (switched off in the "twin guards off" ablation):
  - answers are screened for instruction-like text before any model sees them (match -> refuse)
  - the model must reply with one word from {match, no_match, unsure}; anything else counts as no_match
  - a question the model writes is rejected if it gives away the answer (leak check); a template is used
  - an injected answer is never stored in the twin
"""
import copy
import json
import re

import config
from scenarios import LOGS, RESOURCES, USERS

QUESTION_TEMPLATES = {
    "last_task": "Last time you signed in, you told us what you worked on. What was it?",
    "last_resource": "Which system did you open the last time you signed in?",
    "last_login_time": "Roughly what time did you last sign in?",
}
NEW_TASK_QUESTION = "Before you go: in a few words, what did you work on in this session?"
STOP = set("the a an of for to in on and with my i was were is it that this at by from na fun".split())
RES_WORDS = {"R-MAIL": {"email", "mail", "outlook", "mailbox", "inbox"},
             "R-WIKI": {"wiki", "knowledge", "intranet"},
             "R-PAYROLL": {"payroll", "salary", "pay"},
             "R-MEDDOC": {"medical", "patient", "records", "emr", "documents", "case"}}
WORD_NUM = {w: i for i, w in enumerate("twelve one two three four five six seven eight nine ten eleven".split())}
VERDICTS = ("match", "no_match", "unsure")
# Hybrid judge (fix 2, written before the fresh Part C set was run): for the memory question the model's
# "match" also needs at least one SPECIFIC word in common with the stored answer. Generic work words
# below do not count as specific (they were fixed before any Part C result was seen).
GENERIC = set("""work worked working job jobs task tasks thing things stuff usual normal routine general
files file folder folders records record documents document data patient patients staff people team
reports report system systems app application computer office email emails mail update updated updating
check checked checking review reviewed reviewing fix fixed fixing process processed processing handle
handled handling prepare prepared preparing help helped some few today yesterday session doing done
paperwork issue issues admin""".split())


def norm_verdict(v):
    """Fix 1: read 'Match', 'match.', 'No match', 'no-match' etc. as the intended word."""
    v = re.sub(r"[^a-z_ ]", "", str(v or "").strip().lower()).replace("-", "_").strip()
    v = v.replace(" ", "_")
    return v if v in VERDICTS else None


def specific_overlap(record, ans):
    """True if the answer shares at least one specific word (or number) with the stored answer.
    Words are compared on their first five letters, so 'archived' and 'archiving' count as the same."""
    key = lambda w: w if w.isdigit() else w[:5]
    rec = {key(w) for w in _words(record) if (w.isdigit() or len(w) >= 3) and w not in GENERIC}
    got = {key(w) for w in _words(ans) if (w.isdigit() or len(w) >= 3) and w not in GENERIC}
    return bool(rec & got)


def _words(t):
    return [w for w in re.findall(r"[a-zà-ỹ0-9]+", str(t).lower()) if w not in STOP]


# ------------------------------------------------------------------ Twin memory (Stage 1c)
class TwinMemory:
    """Per-user list of {day, question, answer}. Copied per scenario in Part A; kept in Part B."""
    def __init__(self, data=None):
        self.data = copy.deepcopy(data or {})

    def last(self, user):
        items = self.data.get(user) or []
        return items[-1] if items else None

    def add(self, user, day, question, ans):
        self.data.setdefault(user, []).append(dict(day=day, question=question, answer=ans))


def facts_for(user, memory):
    """The facts the twin can ask about, with their true values (truth stays in code)."""
    recs = [l for l in LOGS if l["user"] == user and l["outcome"] == "success"]
    last = max(recs, key=lambda l: (l["day"], l["hour"])) if recs else None
    f = {}
    m = memory.last(user)
    if m:
        f["last_task"] = dict(answer=m["answer"], day=m["day"])
    if last:
        f["last_resource"] = dict(resource=last["resource"], name=RESOURCES[last["resource"]]["name"], day=last["day"])
        f["last_login_time"] = dict(hour=last["hour"], day=last["day"])
    return f


def plan_questions(band, facts):
    """Which facts to ask, in order, plus the spare used for one replacement question."""
    order = [k for k in ("last_task", "last_resource", "last_login_time") if k in facts]
    n = 1 if band == "LOW" else 2
    return order[:n], order[n:n + 1]


# ------------------------------------------------------------------ judges
def rule_judge(fact, truth, ans):
    """No model: keyword overlap for text, number check for times."""
    a = str(ans).lower()
    if re.search(r"can'?t remember|cannot remember|don'?t (know|remember)|not sure|forgot", a):
        return "unsure"
    if fact == "last_task":
        want = set(_words(truth["answer"]))
        got = set(_words(a))
        return "match" if want and len(want & got) / len(want) >= 0.5 else "no_match"
    if fact == "last_resource":
        words = RES_WORDS.get(truth["resource"]) or set(_words(truth.get("name", ""))) - {"razta"}
        return "match" if set(_words(a)) & words else "no_match"
    if fact == "last_login_time":
        nums = [int(x) for x in re.findall(r"\b(\d{1,2})(?::\d\d)?\b", a)] or \
               [WORD_NUM[w] for w in _words(a) if w in WORD_NUM]
        if not nums:
            return "no_match"
        n = nums[0]
        cands = {n, n + 12} if n < 12 else {n}
        if "am" in a or "morning" in a:
            cands = {n % 12}
        elif "pm" in a or "afternoon" in a or "evening" in a:
            cands = {n % 12 + 12}
        return "match" if any(abs(c - truth["hour"]) <= 1 for c in cands) else "no_match"
    return "no_match"


def truth_text(fact, truth):
    if fact == "last_task":
        return truth["answer"]
    if fact == "last_resource":
        return f"{truth['name']} ({truth['resource']})"
    if fact == "last_login_time":
        h = truth["hour"]
        return f"{h:02d}:00 the previous day (accept within about one hour)"
    return ""


class TwinChallenge:
    """Stage-4 question writing and Stage-5 answer judging for the twin factor."""

    def __init__(self, slm, bus, mode, memory, answer_fn, looks_injected):
        self.slm, self.bus, self.mode, self.memory = slm, bus, mode, memory
        self.answer_fn = answer_fn
        self.looks_injected = looks_injected
        self.guard = mode != "model_noguard"
        self.hybrid = mode == "hybrid"

    # Stage 4: word the question in the user's language (model), with a leak check (code)
    def word_question(self, sc, fact, truth, rec):
        tpl = QUESTION_TEMPLATES[fact]
        if self.mode == "rule":
            return tpl
        user = USERS[sc["user"]]
        hint = {"last_task": "what they said they worked on in their previous session",
                "last_resource": "which system they opened in their previous session",
                "last_login_time": "roughly what time their previous sign-in was"}[fact]
        out, raw, dt = self.slm.chat_json(
            config.SLM["twin_question"],
            "You write one short security question for a user who is signing in. Ask the user to recall the item "
            "described. Never include the answer or any hint of it. Use simple words; the user's language code is "
            "given (en English, yo Yoruba, ha Hausa, ig Igbo) - write in English unless the code is yo or ha, then "
            "add a short translation. Return JSON {\"question\": text}.",
            json.dumps({"ask_about": hint, "language": user["lang"], "channel": user["channel"]}),
            mock_fn=lambda: {"question": tpl})
        rec["slm_s"] += dt
        q = str((out or {}).get("question") or "").strip()
        if not self.guard:
            return q or tpl
        leak_words = set(_words(truth_text(fact, truth))) - {"00", "previous", "day", "accept", "within", "about", "one", "hour"}
        leaked = bool(leak_words & set(_words(q))) and fact != "last_login_time"
        if fact == "last_login_time" and re.search(rf"\b{truth['hour']}\b|\b{truth['hour'] % 12 or 12}\s*(am|pm)", q.lower()):
            leaked = True
        bad = not q or len(q) > 300 or "?" not in q or self.looks_injected(q)
        if leaked or bad:
            rec.setdefault("twin_question_rejected", []).append("leak" if leaked else "invalid")
            return tpl
        return q

    # Stage 5: judge one answer
    def judge(self, fact, truth, question, ans, rec):
        if self.guard and self.looks_injected(ans):
            rec["twin_injection_flagged"] = True
            return "no_match", True
        ans = str(ans)[:200] if self.guard else str(ans)
        if self.mode == "rule":
            return rule_judge(fact, truth, ans), False
        sys_prompt = ("You check a sign-in answer against what a person's identity record says. Decide whether the "
                      "answer recalls the SAME specific item as the record. Accept different wording, spelling "
                      "mistakes, Nigerian Pidgin, Yoruba or Hausa. Do not accept an answer that only names the general "
                      "kind of work, a different item, or a time more than about one hour away. If the answer is "
                      "empty, says it cannot remember, or is too vague to tell, reply unsure. "
                      "Return JSON {\"verdict\": \"match\" or \"no_match\" or \"unsure\"}.")
        payload = {"question": question, "record": truth_text(fact, truth), "answer": ans}
        out, raw, dt = self.slm.chat_json(config.SLM["twin_judge"], sys_prompt, json.dumps(payload, ensure_ascii=False),
                                          mock_fn=lambda: {"verdict": mock_semantic(fact, truth, ans)})
        rec["slm_s"] += dt
        v = (out or {}).get("verdict")
        rec.setdefault("twin_model_raw", []).append(str(v if v is not None else raw)[:60])
        if not self.guard:                                           # ablation: take whatever the model says
            v = str(v or raw).lower()
            return ("match" if "match" in v and "no_match" not in v and "no match" not in v else
                    "unsure" if "unsure" in v else "no_match"), False
        v = norm_verdict(v) or "no_match"                            # fix 1: case / punctuation
        if self.hybrid:                                              # fix 2: model meaning + code anchor
            rv = rule_judge(fact, truth, ans)
            if rv == "match":
                return "match", False
            if v == "match" and fact == "last_task" and not specific_overlap(truth["answer"], ans):
                rec.setdefault("twin_hybrid_vetoed", []).append(ans[:60])
                return "no_match", False
            if rv == "unsure":
                return "unsure", False
        return v, False

    # The whole factor
    def verify(self, sc, band, rec):
        facts = facts_for(sc["user"], self.memory)
        ask, spare = plan_questions(band, facts)
        log = []
        retries = 1
        queue = list(ask)
        passed = 0
        while queue:
            fact = queue.pop(0)
            truth = facts[fact]
            q = self.word_question(sc, fact, truth, rec)
            qtok = self.bus.sign("entity_verification", "TWINQ", dict(fact=fact, question=q))
            if not self.bus.verify(qtok, "entity_verification"):
                return False, log
            ans = self.answer_fn(sc, fact, truth, len(log), question=q)
            verdict, injected = self.judge(fact, truth, q, ans, rec)
            vtok = self.bus.sign("policy_enforcement", "TWINV", dict(verdict=verdict, injection_suspected=injected))
            if not self.bus.verify(vtok, "policy_enforcement"):
                return False, log
            log.append(dict(fact=fact, question=q, answer=ans, verdict=verdict, injected=injected,
                            rule_verdict=rule_judge(fact, truth, ans)))
            if injected:
                return False, log
            if verdict == "match":
                passed += 1
                continue
            alts = [k for k in (spare + list(facts)) if k not in [e["fact"] for e in log] and k not in queue]
            if verdict == "unsure" and retries and alts:              # one replacement, only after "unsure"
                retries -= 1
                queue.append(alts[0])
                spare = [s for s in spare if s != alts[0]]
                continue
            return False, log                                          # a confident wrong answer fails at once
        return passed >= len(ask) and len(ask) > 0, log

    # Stage 1c: grow the twin after a granted session
    def enrol(self, sc, day, ans, rec):
        if not str(ans or "").strip():
            return False
        if self.guard and self.looks_injected(ans):
            rec["twin_store_refused"] = True
            return False
        self.memory.add(sc["user"], day, NEW_TASK_QUESTION, str(ans)[:200])
        tok = self.bus.sign("twin_builder", "TWINU", dict(user=sc["user"], day=day, stored=True))
        return self.bus.verify(tok, "twin_builder")


def mock_semantic(fact, truth, ans):
    """Mock-mode stand-in for the model judge: the rule judge plus a few synonyms (plumbing test only)."""
    a = str(ans).lower()
    if re.search(r"can.t remember|cannot remember|don.t (know|remember)|not sure", a):
        return "unsure"
    if fact == "last_resource" and truth["resource"] == "R-PAYROLL" and re.search(r"albashi|owó oṣù|salary", a):
        return "match"
    if fact == "last_task":
        want = set(_words(truth["answer"]))
        got = set(_words(a))
        return "match" if want and len(want & got) / len(want) >= 0.3 else "no_match"
    return rule_judge(fact, truth, ans)
