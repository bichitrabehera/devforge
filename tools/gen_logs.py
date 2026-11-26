#!/usr/bin/env python3
"""Generate a LABELLED synthetic access-log dataset in the organizer's
practice schema - for held-out detector evaluation.

    python tools/gen_logs.py --out DIR [--events 6000] [--seed 20261126]

Output (in DIR): events.csv, labels.csv, approvals.json - same columns and
label vocabulary as the organizer's practice set (routine, approved_change,
unexpected_role_change, review_after_role_change,
lateral_movement_candidate, routine_clock_offset, routine_delayed_delivery,
routine_denial, isolated_denial).

The generator is INDEPENDENT of the detector (it never imports src/) and
runs from a fixed seed, so the held-out set is reproducible and the rules
can be tuned on the practice set and evaluated ONCE here without leakage.

Scenario mix (defaults scale with --events):
  * benign traffic: sign-ins/reads over the documented service graph with
    role-consistent scopes; some with small clock offsets (labelled
    routine_clock_offset when offset != 0); some arrival-order inversions
    within the 10 s tolerance (routine_delayed_delivery)
  * approved administration: grant/revoke with a matching approval record
  * unexpected privilege changes with no approval, sometimes followed by
    an allowed read in the same session (review_after_role_change)
  * lateral-movement sessions: a burst of >= 2 unknown service edges
  * isolated denials (one unknown-edge deny alone) and post-revocation
    denials (routine_denial)
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# the SAME documented context the detector uses, restated here
# (independently - that is the point of a held-out set)
KNOWN_EDGES = {("portal", "identity"), ("portal", "catalog"),
               ("portal", "reports"), ("admin-console", "identity"),
               ("reports", "catalog"), ("reports", "reports-node-a"),
               ("reports", "reports-node-b"),
               ("reports-node-a", "catalog"),
               ("reports-node-b", "catalog")}
ROLE_SCOPES = {
    "viewer": {"portal", "catalog", "identity"},
    "report-reader": {"reports", "reports-node-a", "reports-node-b"},
    "operator": {"portal", "admin-console", "identity", "reports"},
}
UNKNOWN_TARGETS = ["billing", "archive", "storage", "payments", "search",
                   "data-lake", "vault", "reports-node-c"]
SERVICES = ["portal", "admin-console", "reports", "identity", "catalog",
            "reports-node-a", "reports-node-b"]
ACTOR_POOL = 60
OFFSET_RANGE_MS = 60_000      # supported range; beyond it order is uncertain
REORDER_TOL_S = 10.0

COLUMNS = ["event_id", "event_time_utc", "received_time_utc",
           "source_clock_offset_ms", "actor", "source_service",
           "target_service", "action", "role_before", "role_after",
           "outcome", "approval_id", "session_id", "correlation_id"]


class Gen:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.events = []
        self.labels = {}
        self.approvals = []
        self.t0 = datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc)
        self.now = self.t0
        self.n = 0
        self.flow = 0
        self.users = ["user-%04d" % i for i in range(ACTOR_POOL)]
        self.roles = {u: rng.choice(list(ROLE_SCOPES)) for u in self.users}

    def new_flow(self):
        self.flow += 1
        return "flow-%06d" % self.flow

    def ts(self, dt):
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + \
            "%03dZ" % (dt.microsecond // 1000)

    def add(self, actor, src, tgt, action, role_b, role_a, outcome,
            approval_id="", label="routine", reason="", offset_ms=0,
            recv_delay_ms=200, session=None, corr=None, recv_dt=None):
        self.n += 1
        et = self.now
        self.now = self.now + timedelta(milliseconds=100 +
                                        self.rng.randint(0, 900))
        rt = recv_dt if recv_dt is not None else \
            et + timedelta(milliseconds=recv_delay_ms)
        eid = "evt-%06d" % self.n
        rec = {
            "event_id": eid,
            "event_time_utc": self.ts(et),
            "received_time_utc": self.ts(rt),
            "source_clock_offset_ms": offset_ms,
            "actor": actor, "source_service": src, "target_service": tgt,
            "action": action, "role_before": role_b, "role_after": role_a,
            "outcome": outcome, "approval_id": approval_id,
            "session_id": session or ("sess-%s" % actor),
            "correlation_id": corr or ("flow-%06d" % self.n),
            "_label": label, "_reason": reason or label,
        }
        self.events.append(rec)
        return eid, et, rt

    # --- benign traffic --------------------------------------------------
    def benign(self, k=1):
        for _ in range(k):
            u = self.rng.choice(self.users)
            role = self.roles[u]
            scope = ROLE_SCOPES[role]
            src = self.rng.choice(["portal"] + list(scope))
            tgt = self.rng.choice(sorted(scope))
            if src == tgt or (src, tgt) not in KNOWN_EDGES:
                src, tgt = "portal", sorted(scope)[0]
            action = self.rng.choice(["read", "read", "read", "sign_in",
                                      "list"])
            offset_ms = self.rng.choice(
                [0, 0, 0, 0, 0, 200, -300, 1500, -2000, 2000, -5000])
            label = "routine"
            reason = "role-consistent access over a documented edge"
            if offset_ms:
                label = "routine_clock_offset"
                reason = "source clock %d ms %s, inside the supported range" \
                    % (abs(offset_ms),
                       "ahead" if offset_ms > 0 else "behind")
            self.add(u, src, tgt, action, role, role,
                     "allow" if action != "sign_in" else "success",
                     label=label, reason=reason, offset_ms=offset_ms)

    # arrival inversion within the tolerance
    def delayed_delivery(self):
        u = self.rng.choice(self.users)
        role = self.roles[u]
        scope = ROLE_SCOPES[role]
        # two events: the LATER (event-time) one is SENT first and arrives
        # first; the older one arrives late (within tolerance)
        tgt1, tgt2 = sorted(scope)[:2] or ["catalog", "identity"]
        flow = self.new_flow()
        eid2, et2, rt2 = self.add(u, "portal", tgt2, "read", role, role,
                                  "allow", label="routine",
                                  reason="arrives before an older event",
                                  corr=flow)
        self.now = max(self.now, rt2 + timedelta(milliseconds=50))
        self.add(u, "portal", tgt1, "read", role, role, "allow",
                 label="routine_delayed_delivery",
                 reason="older event arrives after a newer one (within "
                        "the %ss tolerance)" % REORDER_TOL_S,
                 recv_dt=rt2 + timedelta(seconds=self.rng.uniform(0.5, 8.0)),
                 corr=flow)

    # --- administration ---------------------------------------------------
    def approved_change(self):
        u = self.rng.choice(self.users)
        role = self.rng.choice(list(ROLE_SCOPES))
        aid = "ch-%06d" % len(self.approvals)
        valid_from = self.now + timedelta(seconds=1)
        valid_until = valid_from + timedelta(minutes=self.rng.randint(2, 20))
        self.approvals.append({
            "approval_id": aid, "approved_by": "user-admin",
            "subject": u, "operation": "grant_role", "role": role,
            "scope": sorted(ROLE_SCOPES[role]),
            "valid_from_utc": self.ts(valid_from),
            "valid_until_utc": self.ts(valid_until)})
        flow = self.new_flow()
        approve_at = self.now
        self.add("user-admin", "admin-console", "identity",
                 "approve_role_change", "operator", "operator", "success",
                 approval_id=aid, label="approved_change",
                 reason="operator approves %s" % aid, corr=flow)
        self.roles[u] = role
        # the role change happens AFTER the approval becomes valid
        # (the practice set: valid_from == approve time, change later)
        self.now = max(self.now, valid_from) + \
            timedelta(milliseconds=self.rng.randint(100, 500))
        self.add(u, "admin-console", "identity", "role_change",
                 "viewer", role, "success", approval_id=aid,
                 label="approved_change",
                 reason="subject, operation, role and time match %s" % aid,
                 corr=flow)
        # in-scope reads that follow
        for tgt in self.rng.sample(sorted(ROLE_SCOPES[role]),
                                   min(2, len(ROLE_SCOPES[role]))):
            self.add(u, "portal", tgt, "read", role, role, "allow",
                     approval_id=aid, label="routine",
                     reason="read within the approved role scope",
                     corr=flow)

    def approved_revoke(self):
        u = self.rng.choice(self.users)
        aid = "ch-%06d" % len(self.approvals)
        eff = self.now + timedelta(milliseconds=500)
        self.approvals.append({
            "approval_id": aid, "approved_by": "user-admin",
            "subject": u, "operation": "revoke_role",
            "role": self.roles[u],
            "effective_at_utc": self.ts(eff)})
        flow = self.new_flow()
        self.add("user-admin", "admin-console", "identity", "revoke_role",
                 "operator", "operator", "success", approval_id=aid,
                 label="approved_change",
                 reason="operator revokes %s's role under %s"
                        % (u, aid), corr=flow)
        self.now = eff + timedelta(milliseconds=100)
        for tgt in ("reports-node-a", "reports-node-b"):
            self.add(u, "portal", tgt, "read", "viewer", "viewer", "deny",
                     approval_id=aid, label="routine_denial",
                     reason="denial follows an effective revocation",
                     corr=flow)

    # --- incidents ---------------------------------------------------------
    def unexpected_role_change(self):
        u = self.rng.choice(self.users)
        old = self.roles[u]
        new = self.rng.choice([r for r in ROLE_SCOPES if r != old])
        flow = self.new_flow()
        self.add(u, "admin-console", "identity", "role_change", old, new,
                 "success", label="unexpected_role_change",
                 reason="no approval exists for %s becoming %s" % (u, new),
                 corr=flow)
        self.roles[u] = new
        if self.rng.random() < 0.7:      # exploited with an allowed read
            tgt = self.rng.choice(sorted(ROLE_SCOPES[new]))
            self.add(u, "portal", tgt, "read", new, new, "allow",
                     label="review_after_role_change",
                     reason="allowed read follows the unexpected role "
                            "change in the same session", corr=flow)

    def lateral_movement(self):
        u = self.rng.choice(self.users)
        role = self.roles[u]
        hops = self.rng.randint(2, 4)
        flow = self.new_flow()
        src = "portal"
        for i in range(hops):
            tgt = self.rng.choice(UNKNOWN_TARGETS)
            outcome = self.rng.choice(["deny", "deny", "allow"])
            self.add(u, src, tgt, self.rng.choice(["read", "list"]),
                     role, role, outcome,
                     label="lateral_movement_candidate",
                     reason="unexpected service edge %d of %d in one "
                            "session (credentials are valid; the PATH "
                            "is the signal)" % (i + 1, hops), corr=flow)
            src = tgt

    def isolated_denial(self):
        u = self.rng.choice(self.users)
        role = self.roles[u]
        self.add(u, "portal", self.rng.choice(UNKNOWN_TARGETS), "read",
                 role, role, "deny", label="isolated_denial",
                 reason="a single denied request alone does not establish "
                        "lateral movement")

    def run(self, total):
        while len(self.events) < total:
            roll = self.rng.random()
            if roll < 0.62:
                self.benign()
            elif roll < 0.72:
                self.delayed_delivery()
            elif roll < 0.80:
                self.approved_change()
            elif roll < 0.85:
                self.approved_revoke()
            elif roll < 0.93:
                self.unexpected_role_change()
            elif roll < 0.97:
                self.lateral_movement()
            else:
                self.isolated_denial()
        # shuffle CARRIES the labels with their events, then renumber
        self.rng.shuffle(self.events)
        labels = {}
        for i, e in enumerate(self.events):
            e["event_id"] = "evt-%06d" % (i + 1)
            if e.get("_label"):
                labels[e["event_id"]] = (e["_label"], e["_reason"])
            e.pop("_label", None)
            e.pop("_reason", None)
        self.labels = labels
        return self.events, self.labels, self.approvals


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--events", type=int, default=6000)
    p.add_argument("--seed", type=int, default=20261126)
    args = p.parse_args()
    rng = random.Random(args.seed)
    gen = Gen(rng)
    events, labels, approvals = gen.run(args.events)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "events.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for e in events:
            w.writerow(e)
    with open(out / "labels.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["event_id", "label", "reason"])
        for eid, (lab, reason) in labels.items():
            w.writerow([eid, lab, reason])
    with open(out / "approvals.json", "w") as f:
        json.dump({"synthetic": True, "changes": approvals}, f, indent=1)
    counts = {}
    for lab, _ in labels.values():
        counts[lab] = counts.get(lab, 0) + 1
    print("generated %d events, %d labelled -> %s" %
          (len(events), len(labels), out))
    print("label mix:", json.dumps(counts, sort_keys=True))


if __name__ == "__main__":
    main()
