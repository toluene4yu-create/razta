"""RAZTA login portal: the demo dashboard becomes a protected resource (R-DEMO).

A person signs in with a username and password, chooses (or accepts) their context, and the access
request runs through RAZTA. RAZTA chooses the authentication factors; the person answers each one on
simulated authenticators (phone app, SIM phone, hardware key, fingerprint, agent). If RAZTA allows the
request, a short-lived session token opens the dashboard; the session can later be stepped up or revoked
by the continuous trust monitor.

Everything here is a demonstration: the users, passwords, phones and keys are simulated."""
import hashlib
import hmac
import json
import os
import queue
import random
import secrets
import struct
import threading
import time

from agents import Orchestrator, PolicyMFA, TrustMonitor
from ambiguous import ON_CALL, TICKETS, TRAVEL
from llm_clients import RuleLLM, RuleSLM
from scenarios import LOGS, POLICIES, RESOURCES, USERS, endpoint
from twin_challenge import NEW_TASK_QUESTION, TwinMemory, facts_for

# ------------------------------------------------------------------ identity twin memory (Increment 7)
# The twin keeps what each person said they worked on, and their past portal logins, in a file next to
# this script, so the personal question at the next login is built from the previous visit.
MEMORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "twin_memory.json")


def _load_memory():
    try:
        data = json.load(open(MEMORY_FILE, encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    logins = data.pop("_logins", [])
    return TwinMemory(data), logins


MEMORY, PORTAL_LOGINS = _load_memory()


def save_memory():
    data = dict(MEMORY.data)
    data["_logins"] = PORTAL_LOGINS[-500:]
    tmp = MEMORY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, MEMORY_FILE)


def today():
    return int(time.time() // 86400)


def memory_card(user):
    """What the REAL user would remember (shown in the right-hand panel so a tester can play them)."""
    activate()
    try:
        f = facts_for(user, MEMORY)
    finally:
        deactivate()
    out = {}
    if "last_task" in f:
        out["last_task"] = f["last_task"]["answer"]
    if "last_resource" in f:
        out["last_resource"] = f["last_resource"]["name"]
    if "last_login_time" in f:
        out["last_login_time"] = f"{f['last_login_time']['hour']:02d}:00"
    return out

DEMO_PASSWORD = "Razta2026!"
PORTAL_USERS = ["adaeze.o", "bello.m", "chidi.n", "funmi.a", "emeka.k", "grace.i"]
RESOURCE = "R-DEMO"
RESOURCES[RESOURCE] = dict(name="RAZTA research demo console", S=0.75, tags=["sensitive"], min_factors=2,
                           scope="read")
TICKETS.setdefault("RES-701", dict(assignee="adaeze.o", system=RESOURCE, status="open",
                                   title="Supervisor review of the RAZTA demo"))
RECORDS = dict(oncall=ON_CALL, tickets=TICKETS, travel=TRAVEL)

_SALT = b"razta-demo-salt"
PW_HASH = {u: hashlib.pbkdf2_hmac("sha256", DEMO_PASSWORD.encode(), _SALT + u.encode(), 100_000) for u in USERS}
TOTP_SECRET = {u: hashlib.sha256(b"totp" + u.encode()).digest()[:20] for u in USERS}

LOCATIONS = {   # key -> (label, city, country, asn)
    "home": ("Your usual city", None, "NG", "AS37148"),
    "ng_other": ("Another Nigerian city", None, "NG", "AS29465"),
    "accra": ("Accra, Ghana", "Accra", "GH", "AS30986"),
    "nairobi": ("Nairobi, Kenya", "Nairobi", "KE", "AS33771"),
    "moscow": ("Moscow, Russia (flagged network)", "Moscow", "RU", "AS9999"),
}
DEVICE_CHOICES = {
    "own": "This computer (your enrolled work laptop)",
    "new": "A new company laptop (compliant, not yet enrolled)",
    "cafe": "An internet-cafe PC (unmanaged, no attestation)",
    "old": "An old PC (Windows 8.1, no EDR, no encryption)",
}


# ------------------------------------------------------------------ extra access history for the new resource
def _demo_logs():
    rng = random.Random(7)
    out = []
    for u in PORTAL_USERS:
        p = USERS[u]
        for d in range(20, 30):
            out.append(dict(user=u, day=d, hour=rng.randint(p["hours"][0], p["hours"][1] - 1), location=p["home"],
                            country=p["country"], device=p["device"], resource=RESOURCE, outcome="success", note=""))
    return out


DEMO_LOGS = _demo_logs()


def activate():
    if not any(l.get("resource") == RESOURCE for l in LOGS):
        LOGS.extend(DEMO_LOGS)
        LOGS.extend(PORTAL_LOGINS)


def deactivate():
    ids = {id(l) for l in DEMO_LOGS} | {id(l) for l in PORTAL_LOGINS}
    LOGS[:] = [l for l in LOGS if id(l) not in ids]


# ------------------------------------------------------------------ simulated authenticators
def totp(user, t=None, step=30):
    counter = int((t or time.time()) // step)
    h = hmac.new(TOTP_SECRET[user], struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


def totp_ok(user, code):
    code = "".join(ch for ch in str(code) if ch.isdigit())
    now = time.time()
    return any(hmac.compare_digest(code, totp(user, now + k * 30)) for k in (-1, 0, 1))


def password_ok(user, pw):
    if user not in PW_HASH:
        return False
    return hmac.compare_digest(PW_HASH[user], hashlib.pbkdf2_hmac("sha256", str(pw).encode(), _SALT + user.encode(), 100_000))


# ------------------------------------------------------------------ state
PRE_TOKENS = {}       # pre-authentication tokens handed out with the login page
JOBS = {}             # rid -> {"answers": Queue, "user":..}
GRANTS = {}           # one-time grant -> session token
SESSIONS = {}         # session token -> session record
ORCH = {}             # engine -> Orchestrator (kept so lockout counters persist)
LOCK = threading.Lock()


def new_pre_token():
    t = secrets.token_urlsafe(16)
    PRE_TOKENS[t] = time.time() + 1800
    return t


def pre_ok(t):
    return bool(t) and PRE_TOKENS.get(t, 0) > time.time()


def session(token):
    s = SESSIONS.get(token or "")
    if s and s["expires"] < time.time():
        SESSIONS.pop(token, None)
        return None
    return s


def orchestrator(engine, clients):
    if engine not in ORCH:
        slm, llm = (RuleSLM(), RuleLLM()) if engine == "rules" else clients(engine)
        ORCH[engine] = Orchestrator(slm, llm, guard=True, use_twin=True, justify="llm_bounded" if engine != "rules"
                                    else "regex", records=RECORDS,
                                    twin_challenge="rule" if engine == "rules" else "hybrid", memory=MEMORY)
    return ORCH[engine]


def build_request(form, pre_token_valid):
    user = form.get("username", "").strip()
    u = USERS.get(user, USERS["adaeze.o"])
    loc = LOCATIONS.get(form.get("where", "home"), LOCATIONS["home"])
    city = loc[1] or (u["home"] if form.get("where", "home") == "home" else ("Abuja" if u["home"] != "Abuja" else "Lagos"))
    dev_key = form.get("device", "own")
    ep = {"own": endpoint(u["device"]),
          "new": endpoint("NEW-" + user[:6].upper(), owner_device=False, patch_days=3),
          "cafe": endpoint("CAFE-PC", owner_device=False, patch_days=60, edr=False, attest=False),
          "old": endpoint("OLD-PC", owner_device=False, os="Windows 8.1 build 9600", patch_days=900, edr=False,
                          enc=False)}.get(dev_key, endpoint(u["device"]))
    try:
        hour = int(form.get("hour"))
    except (TypeError, ValueError):
        hour = time.localtime().tm_hour
    reason = (form.get("reason") or "").strip()
    return dict(id="LOGIN", category="portal", truth=None, user=user, claim=user, resource=RESOURCE, hour=hour % 24,
                location=city, country=loc[2], asn=loc[3], endpoint=ep, caps=[], token="valid" if pre_token_valid else "none",
                inject=[], session=None, justification=reason or None, note="live login through the portal",
                device_key=dev_key)


def make_ask(rid, put, form, sc):
    """Returns the function the enforcement agent calls for each factor."""
    user = sc["user"]
    answers = JOBS[rid]["answers"]

    def ask(factor, info):
        if factor == "password":
            return password_ok(user, form.get("password", ""))
        if factor == "device_cert":
            ok = sc["device_key"] == "own"
            put(dict(type="challenge", factor=factor, auto=True, ok=ok,
                     text="Device certificate " + ("found on this enrolled computer" if ok else "not present on this device")))
            return ok
        put(dict(type="challenge", factor=factor, code=info.get("code"), user=user))
        try:
            got = answers.get(timeout=120)
        except queue.Empty:
            return None
        if got.get("factor") != factor:
            return None
        val = got.get("value")
        if factor == "totp_app":
            return totp_ok(user, val)
        if factor in ("otp_sms", "otp_ussd"):
            return val or None
        return val == "ok"          # hw_key, biometric, agent_verify: the simulated device confirmed

    def wait_text(factor, question):
        put(dict(type="challenge", factor=factor, question=question, user=user))
        try:
            got = answers.get(timeout=180)
        except queue.Empty:
            return ""
        if got.get("factor") != factor:
            return ""
        return str(got.get("value") or "")[:300]

    def twin_answer(sc_, fact, truth, idx, question=None):      # the person types the answer
        return wait_text("twin_challenge", question or "")

    def twin_enrol(sc_, day):                                  # after a granted login: grow the twin
        v = wait_text("twin_enrol", NEW_TASK_QUESTION)
        return "" if v.strip().lower() in ("", "no") else v
    ask.twin_answer, ask.twin_enrol = twin_answer, twin_enrol
    return ask


def run_login(rid, form, engine, clients, put):
    activate()
    try:
        sc = build_request(form, pre_ok(form.get("pre")))
        put(dict(type="request", user=sc["user"], where=f"{sc['location']}, {sc['country']}", hour=sc["hour"],
                 device=DEVICE_CHOICES.get(sc["device_key"]), engine=engine, reason=sc["justification"]))
        orch = orchestrator(engine, clients)
        t0 = time.perf_counter()
        orch.emit = lambda agent, state, msg="", **data: put(dict(type="agent", agent=agent, state=state, msg=msg,
                                                                 data=data, t=round(time.perf_counter() - t0, 1)))
        orch.pe.emit = orch.catm.emit = orch.emit
        orch.pe.ask = make_ask(rid, put, form, sc)
        orch.tc.answer_fn, orch.enrol_fn, orch.day = orch.pe.ask.twin_answer, orch.pe.ask.twin_enrol, today()
        try:
            r = orch.handle(sc)
        finally:
            orch.pe.ask = None
            orch.enrol_fn = None
        if r["decision"] == "allow":                               # the twin remembers this visit
            PORTAL_LOGINS.append(dict(user=sc["user"], day=today(), hour=sc["hour"], location=sc["location"],
                                      country=sc["country"], device=sc["endpoint"]["device_id"], resource=RESOURCE,
                                      outcome="success", note=""))
        save_memory()
        record = dict(decision=r["decision"], reason=r.get("reason"), T=r.get("T"), band=r.get("band"),
                      breakdown=r.get("breakdown"), policy=r.get("policy"), mfa=r.get("mfa"),
                      justification=r.get("just_verification"), latency=r.get("latency_s"),
                      provisional=r.get("provisional"),
                      twin=[dict(question=e["question"], answer=e["answer"], verdict=e["verdict"])
                            for e in r.get("twin_log", [])], twin_stored=r.get("twin_stored"))
        if r["decision"] == "allow":
            pol = next((p for p in POLICIES if p["id"] == r.get("policy")), {"max_ttl": 15})
            ttl = min(pol["max_ttl"], 15)
            tok = secrets.token_urlsafe(24)
            SESSIONS[tok] = dict(user=sc["user"], T=r["T"], band=r["band"], mfa=r.get("mfa"), policy=r.get("policy"),
                                 ttl=ttl, expires=time.time() + ttl * 60, sc=sc, engine=engine, started=time.time())
            grant = secrets.token_urlsafe(16)
            GRANTS[grant] = tok
            record["grant"] = grant
            record["ttl"] = ttl
        put(dict(type="result", data=record))
    finally:
        deactivate()


DRIFTS = {
    "network": "Switched network (Wi-Fi to mobile data, same country)",
    "burst": "Sudden burst of requests (6x usual rate)",
    "country": "Same token now used from Moscow on a flagged network",
    "device": "Same token now used from a different device",
    "priv": "Attempt to reach admin functions (privilege escalation)",
}


def drift(token, kind, engine, clients):
    s = session(token)
    if not s:
        return dict(action="revoke", why="session already ended")
    sc = dict(s["sc"])
    dev0 = sc["endpoint"]["device_id"]
    ev = dict(minute=round((time.time() - s["started"]) / 60, 1), asn=sc["asn"], country=sc["country"], device=dev0,
              rate=1.0, priv=False)
    if kind == "network":
        ev["asn"] = "AS29465" if sc["asn"] != "AS29465" else "AS37148"
    elif kind == "burst":
        ev["rate"] = 6.0
    elif kind == "country":
        ev.update(asn="AS9999", country="RU")
    elif kind == "device":
        ev["device"] = "HX-UNKNOWN"
    elif kind == "priv":
        ev["priv"] = True
    sc["session"] = dict(tel=[ev], hijacker_caps=[])
    slm, llm = (RuleSLM(), RuleLLM()) if engine == "rules" else clients(engine)
    rec = dict(llm_s=0.0, llm_sources=[])
    mon = TrustMonitor(llm, None).watch(sc, dict(T=s["T"]), dict(device=dev0), lambda caps: True, rec)
    act = mon["actions"][0] if mon["actions"] else "continue"
    if act == "revoke":
        SESSIONS.pop(token, None)
    elif act == "stepup":
        s["needs_stepup"] = True
    return dict(action=act, event=DRIFTS.get(kind, kind))


def run_stepup(rid, token, engine, clients, put, form):
    """Re-challenge the signed-in user with HIGH-band factors (Stage 6 step-up)."""
    activate()
    try:
        s = SESSIONS.get(token)
        if not s:
            put(dict(type="result", data=dict(decision="deny", reason="session ended")))
            return
        sc = s["sc"]
        orch = orchestrator(engine, clients)
        res = dict(RESOURCES[RESOURCE], resource=RESOURCE)
        ch = USERS[sc["user"]]["channel"]
        hp = dict(policy=dict(id="STEP-UP", min_device=0.0, max_ttl=5), map=PolicyMFA.build_map("HIGH", res, ch))
        put(dict(type="agent", agent="catm", state="warn", msg="trust fell during the session: step-up with HIGH-band factors",
                 data=dict(mfa=hp["map"])))
        rec = dict(slm_s=0.0, llm_s=0.0, llm_sources=[])
        orch.pe.emit = lambda agent, state, msg="", **data: put(dict(type="agent", agent=agent, state=state, msg=msg, data=data))
        orch.pe.ask = make_ask(rid, put, form, sc)
        try:
            m = orch.ev.run(hp, sc, rec)
            ok = False
            if m is not None:
                o = orch.pe.enforce(m["payload"], hp, dict(s_dev=1.0), res, sc, rec, caps=[])
                ok = o["payload"]["decision"] == "allow"
        finally:
            orch.pe.ask = None
        if ok:
            s.pop("needs_stepup", None)
            s["expires"] = time.time() + 5 * 60
            s["mfa"] = "+".join(hp["map"])
            s["band"] = str(s["band"]).split(" ")[0] + " + step-up"
            grant = secrets.token_urlsafe(16)
            GRANTS[grant] = token
            put(dict(type="result", data=dict(decision="allow", reason="step-up passed", grant=grant, ttl=5,
                                              mfa="+".join(hp["map"]), T=s["T"], band="HIGH (step-up)")))
        else:
            SESSIONS.pop(token, None)
            put(dict(type="result", data=dict(decision="deny", reason="step-up failed: session revoked")))
    finally:
        deactivate()
