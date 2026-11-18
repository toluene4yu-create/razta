"""Stronger baseline: a conventional risk-based authentication (RBA) engine with step-up
and rule-based session re-scoring, in the style of RBA as deployed on large online
services (Wiefling et al., 2019). No language models. Uses the same signals RAZTA sees,
except that it has no threat-intelligence text reasoning and no channel-aware factors."""
import time

from scenarios import LOGS, USERS

FLAGGED_ASNS = {"AS9999"}            # IP-reputation list (credential-stuffing source)


def _features(sc):
    logs = [l for l in LOGS if l["user"] == sc["user"]]
    hours = [l["hour"] for l in logs]
    return dict(
        new_device=sc["endpoint"]["device_id"] not in {l["device"] for l in logs},
        new_location=sc["location"] not in {l["location"] for l in logs},
        foreign=sc["country"] != "NG",
        off_hours=not (min(hours) <= sc["hour"] <= max(hours) + 1),
        bad_asn=sc["asn"] in FLAGGED_ASNS,
        patch_late=sc["endpoint"]["patch_days"] > 30,
    )


def rba_decide(sc):
    t0 = time.perf_counter()
    ep = sc["endpoint"]
    user = USERS.get(sc["claim"])
    out = dict(decision="deny", reason="", risk=None, factors=[], session_outcome=None)
    if user is None or sc["token"] != "valid":
        out["reason"] = "invalid identity or token"
    elif not (ep["attest"] and ep["edr"] and ep["enc"] and not ep["rooted"]) or ep["patch_days"] > 365:
        out["reason"] = "device non-compliant"
    else:
        f = _features(sc)
        risk = (f["new_device"] + f["new_location"] + 2 * f["foreign"] + f["off_hours"]
                + 2 * f["bad_asn"] + f["patch_late"])
        out["risk"] = risk
        if risk >= 3:
            out["reason"] = f"risk {risk}: blocked"
        else:
            factors = ["password", "otp_sms"]
            if risk >= 1:   # step-up: authenticator app if enrolled, else a second SMS/USSD code
                factors.append("totp_app" if "totp_app" in user["enrolled"] else "otp_ussd")
            out["factors"] = factors
            missing = [x for x in factors if x not in sc["caps"]]
            if missing:
                out["reason"] = f"step-up failed: {missing[0]}"
            else:
                out["decision"], out["reason"] = "allow", f"risk {risk}: {'+'.join(factors)}"
    if sc.get("session") and out["decision"] == "allow":
        outcome = "continue"
        for ev in sc["session"]["tel"]:
            if ev["device"] != ep["device_id"] or ev["country"] != sc["country"]:
                outcome = "terminate"          # device or country change: end session
                break
            if ev["asn"] != sc["asn"] or ev["priv"]:
                caps = sc["caps"]              # same device: the legitimate user re-authenticates
                if not all(x in caps for x in out["factors"]):
                    outcome = "terminate"
                    break
        out["session_outcome"] = outcome
    out["latency_s"] = time.perf_counter() - t0
    return out
