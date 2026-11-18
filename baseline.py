"""Classical, non-agentic ZTA baseline (NIST SP 800-207 style): static rules, fixed MFA,
one-shot decision at session start, no session monitoring."""
import time

from scenarios import USERS

FIXED_MFA = ["password", "otp_sms"]


def baseline_decide(sc):
    t0 = time.perf_counter()
    reason = "allow"
    ep = sc["endpoint"]
    user = USERS.get(sc["claim"])
    if user is None or sc["token"] != "valid":
        reason = "invalid identity or token"
    elif not (ep["attest"] and ep["edr"] and ep["enc"] and not ep["rooted"] and ep["patch_days"] <= 30):
        reason = "device non-compliant"
    elif sc["country"] != "NG" or not (6 <= sc["hour"] < 22):
        reason = "outside geo/time rule"
    elif not all(f in sc["caps"] for f in FIXED_MFA):
        reason = "MFA failed"
    decision = "allow" if reason == "allow" else "deny"
    session_outcome = None
    if sc.get("session"):
        session_outcome = "continue" if decision == "allow" else "denied_at_start"
    return dict(decision=decision, reason=reason, session_outcome=session_outcome,
                latency_s=time.perf_counter() - t0)
