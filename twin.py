"""Stage 1c - Twin Builder: a behavioural 'identity digital twin' for each user.

The twin is a compact, exponentially weighted profile of how a user normally works:
when (hours), where (locations), on what (devices) and which resources, plus their failure rate.
Recent behaviour counts more than old behaviour (half-life of 30 days by default).

* A twin built from fewer than 25 sessions is PROVISIONAL: the orchestrator will not place a
  provisional user in the LOW risk band, whatever the score says (cold-start protection).
* The twin is consulted at Stage 0/2 (how familiar is this device? -> identity component I)
  and at Stage 1/2 (how unusual is this request? -> behaviour component B).
* update() folds a new, successful session into the twin with weight 1 and decays the rest,
  so the twin follows gradual change (a new phone, a new office) without forgetting at once.
"""
import math

HALF_LIFE_DAYS = 30.0
PROVISIONAL_SESSIONS = 25
TODAY = 30               # the synthetic logs cover days 0..29; requests happen on day 30


class Twin:
    def __init__(self, user, records, today=TODAY, half_life=HALF_LIFE_DAYS):
        self.user = user
        self.half_life = half_life
        self.n = 0
        self.w_total = 0.0
        self.hour_m1 = 0.0        # weighted sums for mean / variance of the hour
        self.hour_m2 = 0.0
        self.loc, self.dev, self.res = {}, {}, {}
        self.fail_w = 0.0
        for r in records:
            self._add(r, 0.5 ** ((today - r["day"]) / half_life))

    # ----------------------------------------------------------- building / updating
    def _add(self, r, w):
        self.n += 1
        self.w_total += w
        self.hour_m1 += w * r["hour"]
        self.hour_m2 += w * r["hour"] ** 2
        for table, key in ((self.loc, r["location"]), (self.dev, r["device"]), (self.res, r["resource"])):
            table[key] = table.get(key, 0.0) + w
        self.fail_w += w * (r["outcome"] == "fail")

    def update(self, record, days_elapsed=1.0):
        """Exponentially weighted update: decay everything, then add the new session at weight 1."""
        d = 0.5 ** (days_elapsed / self.half_life)
        self.w_total *= d
        self.hour_m1 *= d
        self.hour_m2 *= d
        self.fail_w *= d
        for table in (self.loc, self.dev, self.res):
            for k in table:
                table[k] *= d
        self._add(record, 1.0)

    # ----------------------------------------------------------- reading the twin
    @property
    def provisional(self):
        return self.n < PROVISIONAL_SESSIONS

    def share(self, table, key):
        return table.get(key, 0.0) / self.w_total if self.w_total else 0.0

    def hour_stats(self):
        if not self.w_total:
            return 12.0, 6.0
        mean = self.hour_m1 / self.w_total
        var = max(0.0, self.hour_m2 / self.w_total - mean ** 2)
        return mean, math.sqrt(var)

    def compare(self, hour, location, device, resource):
        """Returns the deviation features for a request (each 0 = typical, 1 = never seen)."""
        mean, sd = self.hour_stats()
        z = abs(hour - mean) / max(sd, 1.5)
        return dict(
            hour_dev=round(min(1.0, max(0.0, (z - 1.5) / 2.0)), 3),     # inside ~1.5 sd = normal
            location_dev=round(1 - self.share(self.loc, location), 3),
            device_dev=round(1 - self.share(self.dev, device), 3),
            resource_dev=round(1 - self.share(self.res, resource), 3),
            failure_rate=round(self.fail_w / self.w_total, 3) if self.w_total else 0.0,
            sessions=self.n, provisional=self.provisional,
            hour_mean=round(mean, 1), hour_sd=round(sd, 1))

    def device_familiarity(self, device):
        """Used for the identity component: 1.0 = the user's usual device."""
        return round(self.share(self.dev, device), 3)

    def summary(self):
        top = lambda t: sorted(t.items(), key=lambda kv: -kv[1])[:3]
        mean, sd = self.hour_stats()
        return dict(user=self.user, sessions=self.n, provisional=self.provisional,
                    hours=f"{mean:.1f} +/- {sd:.1f}",
                    locations={k: round(v / self.w_total, 2) for k, v in top(self.loc)},
                    devices={k: round(v / self.w_total, 2) for k, v in top(self.dev)},
                    resources={k: round(v / self.w_total, 2) for k, v in top(self.res)})


def build_twin(user, logs):
    return Twin(user, [l for l in logs if l["user"] == user])


def twin_anomaly(f):
    """Rule part of the behaviour score, same shape as the original five flags but graded."""
    return (f["hour_dev"] + f["location_dev"] + f["device_dev"] + f["resource_dev"]
            + min(1.0, f["failure_rate"] * 2)) / 5
