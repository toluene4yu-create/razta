"""RAZTA live demo: a small local web page for screen-sharing.
Click a scenario (or build your own request) and watch the agents decide, live.

Usage:   python demo_server.py           then the browser opens http://localhost:8765
Modes in the page:
  Live      - real models (Ollama + OpenRouter), about 40 s per request
  Replay    - replays the recorded experiment run from results/ (fast, no models needed)
  Simulated - fake model replies, instant (for rehearsing only)
The 16 ambiguous cases (H01-H16) use the identity twin and the reason check, and can be run in
five RAZTA configurations chosen in the page; their baseline is risk-based authentication."""
import csv
import json
import os
import sys
from http.cookies import SimpleCookie
import queue
import secrets
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import config
from agents import Orchestrator
import ambiguous
import portal
from ambiguous import AMBIG, ON_CALL, TICKETS, TRAVEL
from baseline import FIXED_MFA, baseline_decide
from baseline_rba import rba_decide
from llm_clients import OllamaClient, OpenRouterClient, RuleLLM, RuleSLM
from scenarios import (ATTACKER_SIMSWAP, DEVICES, INJECT_OS, RESOURCES, SCENARIOS, USERS, S, endpoint,
                       legit_caps)

ambiguous.deactivate()          # the original 24 scenarios run in their own world; switched per request
HERE = os.path.dirname(os.path.abspath(__file__))
OPEN_MODE = "--open" in sys.argv     # python demo_server.py --open  -> no login required (old behaviour)
RECORDS = dict(oncall=ON_CALL, tickets=TICKETS, travel=TRAVEL)
CONFIGS = {   # page option -> (uses models?, reason-check mode, recorded system name)
    "bounded": (True, "llm_bounded", "RAZTA-models+bounded"),
    "tighten": (True, "llm_tighten", "RAZTA-models+tighten"),
    "models": (True, "off", "RAZTA-models"),
    "regex": (False, "regex", "RAZTA-rules+regex"),
    "rules": (False, "off", "RAZTA-rules"),
}
AMBIG_TITLES = {
    "H01": "On-call doctor, 2am, new phone", "H02": "Fraudster claims to be on call",
    "H03": "Engineer fixing a real outage", "H04": "Contractor's ticket is for another system",
    "H05": "Thief with unlocked phone: 'MD says urgent'", "H06": "Payroll officer, payroll ticket, own phone",
    "H07": "Doctor at approved conference, Nairobi", "H08": "Phisher in Nairobi who knew of the trip",
    "H09": "New hire (provisional twin)", "H10": "Fraudster on the new hire's account",
    "H11": "Feature-phone clerk, reason in Hausa", "H12": "Fraudster, Hausa 'manager says now'",
    "H13": "Reason contains instructions to the AI", "H14": "On-call doctor writes 'override'",
    "H15": "Phisher quotes a real outage ticket", "H16": "Engineer, vague reason, no ticket",
}
AMBIG_ACTORS = {
    "H01": "Account owner", "H02": "Fraudster (SIM swap)", "H03": "Account owner", "H04": "Account owner, outside his task",
    "H05": "Thief (stolen phone)", "H06": "Account owner", "H07": "Account owner", "H08": "Phisher (password + app code)",
    "H09": "Account owner", "H10": "Fraudster (SIM swap)", "H11": "Account owner", "H12": "Fraudster (SIM swap)",
    "H13": "Attacker (SIM swap)", "H14": "Account owner", "H15": "Phisher (password + app code)", "H16": "Account owner",
}
PORT = 8765
RUN_LOCK = threading.Lock()
CLIENTS = {}

TITLES = {
    "A1": "Routine email access", "A2": "Routine medical-records access", "A3": "Routine wiki access",
    "A4": "Routine payroll access", "A5": "Routine medical-records access", "A6": "USSD-only user, payroll",
    "B1": "Travelling user, late night in Accra", "B2": "New company laptop", "B3": "Evening login from Abuja",
    "B4": "Device one patch cycle behind", "C1": "SIM-swap attacker, payroll", "C2": "SIM-swap attacker, email",
    "C3": "Stolen password from Moscow", "C4": "SIM-swap vs USSD-only user", "D1": "Unsupported OS, medical records",
    "E1": "SQL-injection username probe", "E2": "Forged token probe", "F1": "Poisoned access-log note",
    "F2": "Poisoned OS build string", "F3": "Poisoned threat-intel feed", "G1": "Stable benign session",
    "G2": "Benign network switch mid-session", "G3": "Session token stolen, used abroad",
    "G4": "Session token stolen, privilege escalation",
}
GROUPS = [("legit_routine", "Legitimate, routine"), ("legit_unusual", "Legitimate, unusual"),
          ("credential_theft", "Credential theft"), ("noncompliant_device", "Device posture"),
          ("enumeration_probe", "Enumeration probes"), ("prompt_injection", "Prompt injection"),
          ("session", "Live sessions (continuous monitoring)"), ("ambiguous", "Ambiguous look-alike pairs (twin + reason check)")]


def labels():
    """Colleague's labels from labels.csv when filled in, else the design labels."""
    lab = {}
    path = os.path.join(HERE, "labels.csv")
    if os.path.exists(path):
        for r in csv.DictReader(open(path, encoding="utf-8-sig")):
            col = next((k for k in r if k and k.startswith("labeller_label")), None)
            v = (r.get(col) or "").strip().lower() if col else ""
            if v in ("allow", "deny"):
                lab[r["id"]] = v
    full = len(lab) >= len(AMBIG)
    return (lab if full else {s["id"]: s["design_truth"] for s in AMBIG}), ("colleague's label" if full else "design label")


for _s in AMBIG:
    _s["category"] = "ambiguous"
ALL = SCENARIOS + AMBIG


def clients(mode):
    if mode not in CLIENTS:
        mock = mode == "simulated"
        CLIENTS[mode] = (OllamaClient(mock=mock), OpenRouterClient(mock=mock))
    return CLIENTS[mode]


def describe(sc):
    if sc["id"] in AMBIG_TITLES:
        lab, src = labels()
        ep = sc["endpoint"]
        own = ep["device_id"] in DEVICES and DEVICES[ep["device_id"]]["owner"] == sc["user"]
        dev = ("own enrolled device" if own else "unenrolled device") + f" · {ep['os'][:40]}"
        return dict(id=sc["id"], title=AMBIG_TITLES[sc["id"]], category="ambiguous", truth=lab[sc["id"]],
                    label_source=src, note="", story=sc["story"], justification=sc["justification"], pair=sc["pair"],
                    claim=sc["claim"], resource=sc["resource"], resource_name=RESOURCES[sc["resource"]]["name"],
                    S=RESOURCES[sc["resource"]]["S"], where=f"{sc['location']}, {sc['country']} ({sc['asn']})",
                    hour=f"{sc['hour']:02d}:{40 if sc['hour'] < 5 else 30}", device=dev,
                    actor=AMBIG_ACTORS[sc["id"]] + " · holds: " + ", ".join(sc["caps"]), inject=[], session=False)
    ep = sc["endpoint"]
    own = ep["device_id"] in DEVICES and DEVICES[ep["device_id"]]["owner"] == sc["user"]
    if sc["caps"] == []:
        actor = "Probe / unknown"
    elif set(sc["caps"]) == set(USERS.get(sc["user"], {}).get("enrolled", [])):
        actor = "Legitimate user"
    else:
        actor = "Attacker holding: " + ", ".join(sc["caps"])
    dev = ("own enrolled device" if own else "unenrolled device") + \
          f" · {ep['os'][:40]} · patched {ep['patch_days']} d ago" + ("" if ep["edr"] else " · no EDR") + \
          ("" if ep["enc"] else " · no encryption") + ("" if ep["attest"] else " · no attestation")
    return dict(id=sc["id"], title=TITLES.get(sc["id"], "Custom request"), category=sc["category"],
                truth=sc["truth"], note=sc["note"], claim=sc["claim"], resource=sc["resource"],
                resource_name=RESOURCES[sc["resource"]]["name"], S=RESOURCES[sc["resource"]]["S"],
                where=f"{sc['location']}, {sc['country']} ({sc['asn']})", hour=f"{sc['hour']:02d}:00",
                device=dev, actor=actor, inject=sc["inject"], session=bool(sc.get("session")))


def custom_scenario(p):
    user = p.get("user", "adaeze.o")
    u = USERS[user]
    res = p.get("resource", "R-MAIL")
    loc = {"home": (u["home"], "NG", "AS37148"), "ng_other": ("Abuja" if u["home"] != "Abuja" else "Lagos", "NG", "AS29465"),
           "accra": ("Accra", "GH", "AS30986"), "moscow": ("Moscow", "RU", "AS9999")}[p.get("where", "home")]
    hour = int(p.get("hour", 10))
    dev = {"own": endpoint(u["device"]),
           "new": endpoint("NEW1", owner_device=False, patch_days=3),
           "old": endpoint("OLD1", owner_device=False, os="Windows 8.1 build 9600", patch_days=900, edr=False, enc=False),
           "unmanaged": endpoint("UNM1", owner_device=False, patch_days=40, edr=False, attest=False)}[p.get("device", "own")]
    actor = p.get("actor", "legit")
    caps = legit_caps(user) if actor == "legit" else ATTACKER_SIMSWAP if actor == "simswap" else ["password"]
    inject = [p["inject"]] if p.get("inject") not in (None, "", "none") else []
    if "os" in inject:
        dev = dict(dev, os=INJECT_OS)
    session = None
    if p.get("session") in ("benign", "hijack"):
        d0 = dev["device_id"]
        tel = [dict(minute=5, asn=loc[2], country=loc[1], device=d0, rate=1.0, priv=False)]
        if p["session"] == "benign":
            tel += [dict(minute=10, asn=loc[2], country=loc[1], device=d0, rate=1.1, priv=False),
                    dict(minute=15, asn=loc[2], country=loc[1], device=d0, rate=0.9, priv=False)]
        else:
            tel += [dict(minute=10, asn="AS9999", country="RU", device="HX9", rate=6.0, priv=False),
                    dict(minute=15, asn="AS9999", country="RU", device="HX9", rate=9.0, priv=True)]
        session = dict(tel=tel, hijacker_caps=["password"])
    truth = ("terminate" if p.get("session") == "hijack" else "continue") if session else \
            ("allow" if actor == "legit" else "deny")
    cat = "session" if session else "prompt_injection" if inject else "custom"
    return S("X", cat, truth, user, res, hour, loc[0], loc[1], loc[2], dev, caps, inject=inject, session=session,
             note="custom request built in the demo")


def latest_rows(folder="results", name="raw_results.jsonl"):
    path = os.path.join(HERE, folder, name)
    rows = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            r = json.loads(line)
            rows[(r["system"], r["id"])] = r
    return rows


def replay_events(sc, guard, put, cfg="bounded"):
    amb = sc.get("category") == "ambiguous"
    if amb:
        r = latest_rows("results_ambiguous", "raw.jsonl").get((CONFIGS[cfg][2], sc["id"]))
    else:
        r = latest_rows().get(("RAZTA" if guard else "RAZTA-noguard", sc["id"]))
    if r is None:
        put(dict(type="error", msg="No recorded result for this scenario/configuration. Use Live mode."))
        return None
    pause = lambda: time.sleep(0.55)  # noqa: E731
    if r.get("gate_reason"):
        put(dict(type="agent", agent="gate", state="fail", msg=f"uniform deny ({r['gate_reason']})"))
        return r
    put(dict(type="agent", agent="gate", state="done", msg="claim accepted")); pause()
    put(dict(type="agent", agent="clr", state="done", msg="access history summarised")); pause()
    if amb:
        put(dict(type="agent", agent="twin", state="warn" if r.get("provisional") else "done",
                 msg="identity twin compared with this request" + (" · PROVISIONAL (< 25 sessions): LOW band not allowed"
                                                                    if r.get("provisional") else ""))); pause()
    put(dict(type="agent", agent="det", state="done", msg="endpoint posture scored")); pause()
    put(dict(type="agent", agent="pc", state="done", msg=f"resource sensitivity S = {RESOURCES[sc['resource']]['S']}")); pause()
    bd = r.get("breakdown") or {}
    if r.get("T") is not None:
        put(dict(type="agent", agent="rte", state="done",
                 msg=f"trust T = {r['T']} -> " + (f"final band {r['band']} (after the checks below)" if amb else f"band {r['band']}"),
                 data=dict(T=r["T"], band=r["band"], breakdown=bd))); pause()
    if amb and r.get("just_claim") is not None:
        if r.get("just_injection"):
            put(dict(type="agent", agent="jc", state="warn", msg="instructions found in the stated reason: screened out, band forced HIGH"))
        else:
            adj = int(r.get("just_adjust") or 0)
            put(dict(type="agent", agent="jc", state="warn" if adj > 0 else "done",
                     msg=f"claim: {r['just_claim']}{' ' + r['just_ref'] if r.get('just_ref') else ''} · record: "
                         f"{r['just_verification']} · red flags: {(r.get('just_flags') or 'none').replace('|', ', ')} · "
                         f"band {['relaxed', 'unchanged', 'tightened'][adj + 1]}"))
        pause()
    if r.get("arbitration") in (1, "1"):
        put(dict(type="agent", agent="orch", state="warn", msg="arbitration: model chose the STRICTER band")); pause()
    if r.get("injection_flagged") and not amb:
        put(dict(type="agent", agent="orch", state="warn", msg="injection quarantined: band forced to HIGH")); pause()
    if r.get("review"):
        put(dict(type="agent", agent="orch", state="done" if r["review"] == "approved" else "fail",
                 msg=f"human review {r['review']}")); pause()
    if r.get("policy"):
        put(dict(type="agent", agent="pc", state="done", msg=f"policy {r['policy']}, MFA = {r['mfa']}",
                 data=dict(policy=r["policy"], mfa=(r.get("mfa") or "").split("+")))); pause()
        put(dict(type="agent", agent="ev", state="done", msg="verification model built")); pause()
        ok = r["decision"] == "allow"
        put(dict(type="agent", agent="pe", state="done" if ok else "fail", msg=r.get("reason", ""))); pause()
    for k, act in enumerate((r.get("monitor_actions") or "").split("|") if r.get("monitor_actions") else []):
        put(dict(type="agent", agent="catm", state="tick", msg=f"tick {k + 1}: {act}", data=dict(action=act,
                 minute=sc["session"]["tel"][k]["minute"] if sc.get("session") else 0))); pause()
    if r.get("session_outcome"):
        put(dict(type="agent", agent="catm", state="fail" if r["session_outcome"] == "terminate" else "done",
                 msg="session TERMINATED" if r["session_outcome"] == "terminate" else "session ran to completion"))
    return r


def run_request(sc, mode, guard, put, cfg="bounded"):
    amb = sc.get("category") == "ambiguous"
    (ambiguous.activate if amb else ambiguous.deactivate)()
    put(dict(type="request", data=describe(sc), mode=mode, guard=guard, cfg=cfg if amb else None))
    if amb:
        b = rba_decide(sc)
        put(dict(type="baseline", data=dict(decision=b["decision"], reason=b["reason"], mfa=b.get("factors"),
                                            session_outcome=None, label="Risk-based authentication (no AI)")))
        if CONFIGS[cfg][1] == "off":
            put(dict(type="agent", agent="jc", state="idle", msg="reason NOT read in this configuration"))
    else:
        b = baseline_decide(sc)
        put(dict(type="baseline", data=dict(decision=b["decision"], reason=b["reason"], mfa=FIXED_MFA,
                                            session_outcome=b["session_outcome"], label="Classical ZTA (NIST 800-207 rules)")))
    t0 = time.perf_counter()
    if mode == "replay":
        r = replay_events(sc, guard, put, cfg)
        if r is None:
            return
    else:
        uses_models, just, _ = CONFIGS[cfg] if amb else (True, "off", None)
        slm, llm = clients(mode) if uses_models else (RuleSLM(), RuleLLM())
        orch = Orchestrator(slm, llm, guard=guard, use_twin=amb, justify=just if amb else "off", records=RECORDS)

        def emit(agent, state, msg="", **data):
            put(dict(type="agent", agent=agent, state=state, msg=msg, data=data,
                     t=round(time.perf_counter() - t0, 1)))
            if mode == "simulated" or (amb and not uses_models):
                time.sleep(0.35)   # slow the instant fake or rule replies down so the flow is watchable
        orch.emit = emit
        orch.pe.emit = orch.catm.emit = emit
        r = orch.handle(sc)
    put(dict(type="result", data=dict(decision=r["decision"], reason=r.get("reason"), T=r.get("T"), band=r.get("band"),
                                      policy=r.get("policy"), mfa=r.get("mfa"), session_outcome=r.get("session_outcome"),
                                      latency=r.get("latency_s"), slm_s=round(r.get("slm_s", 0), 1),
                                      llm_s=round(r.get("llm_s", 0), 1), recorded=mode == "replay",
                                      injection_flagged=r.get("injection_flagged"),
                                      override=r.get("override_applied"))))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _cookie(self, name):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return c[name].value if name in c else None

    def _sess(self):
        s = portal.session(self._cookie("razta_sess"))
        return s if s and not s.get("needs_stepup") else None

    def _redirect(self, where, cookies=()):
        self.send_response(302)
        self.send_header("Location", where)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return {}

    def _stream(self, job):
        """Run job(put) in a worker thread and stream its events to the browser (Server-Sent Events)."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        qu = queue.Queue()

        def worker():
            if not RUN_LOCK.acquire(blocking=False):
                qu.put(dict(type="error", msg="Another request is still running. Wait for it to finish."))
                qu.put(None)
                return
            try:
                job(qu.put)
            except SystemExit as e:
                qu.put(dict(type="error", msg=str(e)))
            except Exception as e:
                traceback.print_exc()
                qu.put(dict(type="error", msg=f"{type(e).__name__}: {e}"))
            finally:
                RUN_LOCK.release()
                qu.put(None)
        threading.Thread(target=worker, daemon=True).start()
        try:
            while True:
                ev = qu.get()
                if ev is None:
                    self.wfile.write(b"data: {\"type\": \"end\"}\n\n")
                    self.wfile.flush()
                    break
                self.wfile.write(f"data: {json.dumps(ev, default=str)}\n\n".encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def do_POST(self):
        u = urlparse(self.path)
        body = self._json_body()
        if u.path == "/api/portal/login":
            rid = secrets.token_urlsafe(8)
            body["pre"] = self._cookie("razta_pre")
            portal.JOBS[rid] = dict(kind="login", form=body, answers=queue.Queue(),
                                    engine=body.get("engine") if body.get("engine") in ("live", "simulated", "rules") else "simulated")
            return self._send(200, json.dumps(dict(rid=rid)), "application/json")
        if u.path == "/api/portal/stepup":
            tok = self._cookie("razta_sess")
            s = portal.SESSIONS.get(tok or "")
            if not s:
                return self._send(401, json.dumps(dict(error="no session")), "application/json")
            rid = secrets.token_urlsafe(8)
            portal.JOBS[rid] = dict(kind="stepup", form=dict(body, username=s["user"]), token=tok, answers=queue.Queue(),
                                    engine=s["engine"])
            return self._send(200, json.dumps(dict(rid=rid)), "application/json")
        if u.path == "/api/portal/answer":
            job = portal.JOBS.get(body.get("rid", ""))
            if job:
                job["answers"].put(dict(factor=body.get("factor"), value=body.get("value")))
            return self._send(200, "{}", "application/json")
        if u.path == "/api/portal/drift":
            tok = self._cookie("razta_sess")
            s = portal.session(tok)
            if not s:
                return self._send(401, json.dumps(dict(action="revoke")), "application/json")
            if not RUN_LOCK.acquire(timeout=60):
                return self._send(503, json.dumps(dict(error="busy")), "application/json")
            try:
                out = portal.drift(tok, body.get("kind", "network"), s["engine"], clients)
            finally:
                RUN_LOCK.release()
            return self._send(200, json.dumps(out), "application/json")
        return self._send(404, "not found", "text/plain")

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        protected = u.path == "/" or u.path.startswith("/api/info") or u.path.startswith("/api/run") or u.path.startswith("/charts")
        if protected and not OPEN_MODE and not self._sess():
            if u.path == "/":
                return self._redirect("/login")
            return self._send(401, "RAZTA: sign in first", "text/plain")
        if u.path == "/login":
            pre = portal.new_pre_token()
            data = open(os.path.join(HERE, "portal.html"), encoding="utf-8").read().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", f"razta_pre={pre}; Path=/; HttpOnly; SameSite=Strict")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if u.path == "/api/portal/info":
            tok = self._cookie("razta_sess")
            s = portal.session(tok)
            return self._send(200, json.dumps(dict(
                users=[dict(id=x, home=USERS[x]["home"], channel=USERS[x]["channel"], hours=USERS[x]["hours"],
                            enrolled=USERS[x]["enrolled"]) for x in portal.PORTAL_USERS],
                locations={k: v[0] for k, v in portal.LOCATIONS.items()}, devices=portal.DEVICE_CHOICES,
                live_ok=bool(os.environ.get("OPENROUTER_API_KEY")), demo_password=portal.DEMO_PASSWORD,
                resource=portal.RESOURCES[portal.RESOURCE]["name"],
                stepup=dict(user=s["user"]) if s and s.get("needs_stepup") else None)), "application/json")
        if u.path == "/api/portal/stream":
            job = portal.JOBS.get(q.get("rid", ""))
            if not job:
                return self._send(404, "unknown request", "text/plain")
            rid = q["rid"]
            if job["kind"] == "login":
                return self._stream(lambda put: (ambiguous.deactivate(), portal.run_login(rid, job["form"], job["engine"], clients, put)))
            return self._stream(lambda put: (ambiguous.deactivate(), portal.run_stepup(rid, job["token"], job["engine"], clients, put, job["form"])))
        if u.path == "/api/portal/memory":                     # Increment 7: what the real user remembers
            user = q.get("user", "")
            if user not in portal.PORTAL_USERS:
                return self._send(404, "{}", "application/json")
            return self._send(200, json.dumps(portal.memory_card(user), ensure_ascii=False), "application/json")
        if u.path == "/api/portal/phone":
            user = q.get("user", "")
            if user not in USERS:
                return self._send(404, "{}", "application/json")
            return self._send(200, json.dumps(dict(code=portal.totp(user), seconds=30 - int(time.time()) % 30)), "application/json")
        if u.path == "/portal/enter":
            tok = portal.GRANTS.pop(q.get("grant", ""), None)
            if not tok or not portal.session(tok):
                return self._redirect("/login")
            return self._redirect("/", [f"razta_sess={tok}; Path=/; HttpOnly; SameSite=Strict"])
        if u.path == "/api/portal/me":
            s = portal.session(self._cookie("razta_sess"))
            if not s:
                return self._send(401, json.dumps(dict(signed_in=False, open=OPEN_MODE)), "application/json")
            return self._send(200, json.dumps(dict(signed_in=True, user=s["user"], T=s["T"], band=s["band"], mfa=s["mfa"],
                                                   policy=s["policy"], expires_in=int(s["expires"] - time.time()),
                                                   needs_stepup=bool(s.get("needs_stepup")), engine=s["engine"],
                                                   drifts=portal.DRIFTS)), "application/json")
        if u.path == "/logout":
            portal.SESSIONS.pop(self._cookie("razta_sess") or "", None)
            return self._redirect("/login?msg=signed_out", ["razta_sess=; Path=/; Max-Age=0"])
        if u.path == "/":
            return self._send(200, open(os.path.join(HERE, "demo.html"), encoding="utf-8").read(), "text/html; charset=utf-8")
        if u.path == "/api/info":
          try:
              groups = [dict(key=k, label=l, items=[describe(s) for s in ALL if s["category"] == k]) for k, l in GROUPS]
              live_ok = bool(os.environ.get("OPENROUTER_API_KEY"))
              rows = latest_rows()
              summary = open(os.path.join(HERE, "results", "summary.md"), encoding="utf-8").read() \
                  if os.path.exists(os.path.join(HERE, "results", "summary.md")) else ""
              amb_path = os.path.join(HERE, "results_ambiguous", "summary.md")
              amb_summary = open(amb_path, encoding="utf-8").read() if os.path.exists(amb_path) else ""
              has_amb_replay = bool(latest_rows("results_ambiguous", "raw.jsonl"))
              return self._send(200, json.dumps(dict(
                  groups=groups, slm=config.SLM, llm=CLIENTS.get("live", (None, None))[1].models if "live" in CLIENTS else {},
                  live_ok=live_ok, has_replay=bool(rows), summary=summary, amb_summary=amb_summary,
                  has_amb_replay=has_amb_replay,
                  users=list(USERS), resources={k: v["name"] for k, v in RESOURCES.items()})), "application/json")
          except Exception as e:
            traceback.print_exc()
            return self._send(500, f"demo server error: {type(e).__name__}: {e}", "text/plain")

        if u.path.startswith("/charts/") or u.path.startswith("/charts_amb/"):
            folder = "results_ambiguous" if u.path.startswith("/charts_amb/") else "results"
            fp = os.path.join(HERE, folder, "charts", os.path.basename(u.path))
            if os.path.exists(fp):
                return self._send(200, open(fp, "rb").read(), "image/png")
            return self._send(404, "not found", "text/plain")
        if u.path == "/api/run":
            mode = q.get("mode", "replay")
            guard = q.get("guard", "1") == "1"
            if "custom" in q:
                sc = custom_scenario(json.loads(q["custom"]))
                if mode == "replay":
                    mode = "simulated" if not os.environ.get("OPENROUTER_API_KEY") else "live"
            else:
                sc = next((s for s in ALL if s["id"] == q.get("id")), None)
                if sc is None:
                    return self._send(404, "unknown scenario", "text/plain")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            qu = queue.Queue()

            def worker():
                if not RUN_LOCK.acquire(blocking=False):
                    qu.put(dict(type="error", msg="Another request is still running. Wait for it to finish."))
                    qu.put(None)
                    return
                try:
                    run_request(sc, mode, guard, qu.put, q.get("cfg", "bounded") if q.get("cfg") in CONFIGS else "bounded")
                except SystemExit as e:
                    qu.put(dict(type="error", msg=str(e)))
                except Exception as e:
                    traceback.print_exc()
                    qu.put(dict(type="error", msg=f"{type(e).__name__}: {e}"))
                finally:
                    RUN_LOCK.release()
                    qu.put(None)
            threading.Thread(target=worker, daemon=True).start()
            try:
                while True:
                    ev = qu.get()
                    if ev is None:
                        self.wfile.write(b"data: {\"type\": \"end\"}\n\n")
                        self.wfile.flush()
                        break
                    self.wfile.write(f"data: {json.dumps(ev, default=str)}\n\n".encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            return
        return self._send(404, "not found", "text/plain")


def main():
    if os.environ.get("OPENROUTER_API_KEY"):
        try:
            clients("live")
            print("Live mode ready. Global models:", CLIENTS["live"][1].models)
        except SystemExit as e:
            print("Live mode unavailable:", e)
    else:
        print("OPENROUTER_API_KEY not set: Live mode disabled (Replay and Simulated still work).")
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://localhost:{PORT}" + ("" if OPEN_MODE else "/login")
    print("Login required: the dashboard is now a resource protected by RAZTA." if not OPEN_MODE else
          "Open mode: no login required.")
    print(f"\nRAZTA demo running at {url}  (press Ctrl+C here to stop)")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    main()
