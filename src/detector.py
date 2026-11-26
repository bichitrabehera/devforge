"""Deterministic rule-based detector - no AI/ML, no custom crypto.

Two entry points:

evaluate_labelled(events, labels, approvals, ...)
    Runs the rules over the organizer's labelled synthetic log
    (practice/events.csv + labels.csv + approvals.json) and reports
    explainable alerts, F1, median time-to-alert and false alerts per
    1,000 benign events.

evaluate_live(log)
    Runs simpler structural rules over this service's own signed audit
    log to give the operator an alert view of live activity.

Clock handling (documented ranges)
----------------------------------
* source_clock_offset_ms is removed before ordering events ("true time").
* Supported offset range: +/- 60 s.  Beyond that the event is flagged
  order_uncertain (order cannot be trusted).
* Arrival order may differ from event-time order; inversions within a
  10 s reorder tolerance are annotated ("delayed_delivery").  Larger
  inversions are flagged order_uncertain.

Context model
-------------
* Approvals authorize specific (subject, operation, role) inside a validity
  window, so approved administration is distinguished from suspicious
  privilege changes.
* A documented service graph plus role scopes define "known" access edges;
  an access path outside both is an unknown edge.  A burst of >= 2 unknown
  edges in one session is lateral movement (valid credentials do not matter);
  a single isolated unknown edge is NOT alerted.
* Allowed reads that follow an unexpected role change in the same session
  are reviewed ("review_after_role_change").
* Denials following an effective revocation approval are routine.
"""

import csv
import json
import os
import statistics
from datetime import datetime, timezone

SUPPORTED_OFFSET_MS = 60_000        # +/- 60 s clock offsets supported
REORDER_TOLERANCE_S = 10.0          # arrival inversions tolerated here
LATERAL_BURST_MIN = 2               # unknown edges per session to alert

ALERT_LABELS = {"unexpected_role_change", "review_after_role_change",
                "lateral_movement_candidate"}

SERVICE_GRAPH = {
    ("portal", "identity"),
    ("portal", "catalog"),
    ("portal", "reports"),
    ("admin-console", "identity"),
    ("reports", "catalog"),
}
ROLE_SCOPES = {
    "viewer": {"portal", "catalog", "identity"},
    "report-reader": {"reports", "reports-node-a", "reports-node-b"},
    "operator": {"portal", "admin-console", "identity", "reports"},
}
ADMIN_ACTORS = {"user-admin"}
PRIVILEGE_ACTIONS = {"role_change", "grant_role", "revoke_role"}


def _parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def load_events(events_path=None, events=None):
    if events is not None:
        return [dict(e) for e in events]
    with open(events_path, newline="") as f:
        return [dict(r) for r in csv.DictReader(f)]


def load_labels(labels_path=None, labels=None):
    if labels is not None:
        return {l["event_id"]: l for l in labels}
    with open(labels_path, newline="") as f:
        return {r["event_id"]: r for r in csv.DictReader(f)}


def load_approvals(approvals_path=None, approvals=None):
    if approvals is not None:
        return approvals
    with open(approvals_path) as f:
        return json.load(f)


def approval_matches(approvals, probe):
    """True if probe (subject/operation/role/approval_id/at) is authorized."""
    for ch in approvals.get("changes", []):
        if probe.get("approval_id") and ch.get("approval_id") != probe["approval_id"]:
            continue
        if ch.get("subject") != probe.get("subject"):
            continue
        if ch.get("operation") != probe.get("operation"):
            continue
        if probe.get("operation") == "grant_role" and ch.get("role") != probe.get("role"):
            continue
        at = probe.get("at", 0.0)
        if ch.get("valid_from_utc"):
            if at < _parse_ts(ch["valid_from_utc"]):
                continue
            if at > _parse_ts(ch["valid_until_utc"]):
                continue
        if ch.get("effective_at_utc") and at < _parse_ts(ch["effective_at_utc"]):
            continue
        return True
    return False


def _role_scope(actor, role):
    if actor.startswith("svc-"):
        return None    # service accounts rely on SERVICE_GRAPH only
    return ROLE_SCOPES.get(role, set())


def _edge_known(event):
    src, tgt = event.get("source_service", ""), event.get("target_service", "")
    if (src, tgt) in SERVICE_GRAPH:
        return True
    scope = _role_scope(event.get("actor", ""),
                        event.get("role_after") or event.get("role_before", ""))
    if scope is None:
        return False
    return tgt in scope


def evaluate_labelled(events_path=None, labels_path=None, approvals_path=None,
                      events=None, labels=None, approvals=None):
    events = load_events(events_path, events)
    label_map = load_labels(labels_path, labels)
    approvals = load_approvals(approvals_path, approvals)

    # Normalize: true time removes the source clock offset.
    norm = []
    for e in events:
        e = dict(e)
        offset_ms = float(e.get("source_clock_offset_ms") or 0)
        e["_offset_ms"] = offset_ms
        e["_true_time"] = _parse_ts(e["event_time_utc"]) - offset_ms / 1000.0
        e["_recv_time"] = _parse_ts(e["received_time_utc"])
        norm.append(e)
    norm.sort(key=lambda e: e["_true_time"])

    # Pass 1: classify privilege changes and access edges.
    unexpected_change = {}     # session_id -> event
    session_unknown = {}       # session_id -> [events]
    annotations = []
    order_uncertain = []
    for e in norm:
        sid = e.get("session_id", "")
        action = e.get("action", "")
        actor = e.get("actor", "")

        if action in PRIVILEGE_ACTIONS:
            if action == "revoke_role" and actor in ADMIN_ACTORS:
                # The approval subject is the revoked user, not the admin
                # actor; any effective revoke approval explains this event.
                approved = any(
                    ch.get("operation") == "revoke_role"
                    and e["_true_time"] >= _parse_ts(ch["effective_at_utc"])
                    for ch in approvals.get("changes", [])
                    if ch.get("effective_at_utc"))
            else:
                probe = {"approval_id": e.get("approval_id", "") or None,
                         "subject": actor,
                         "operation": "grant_role",
                         "role": e.get("role_after"), "at": e["_true_time"]}
                approved = approval_matches(approvals, probe)
            if approved:
                pass    # approved administration: not an alert
            else:
                unexpected_change[sid] = e
        elif e.get("outcome") == "deny":
            ok_revoke = approval_matches(approvals, {
                "subject": actor, "operation": "revoke_role",
                "at": e["_true_time"]})
            if ok_revoke:
                annotations.append({"event_id": e["event_id"],
                                    "note": "routine_denial",
                                    "detail": "denial follows effective "
                                              "revocation approval"})

        # Unknown-edge collection: lateral movement counts valid-credential
        # probes too, including denials that are NOT explained by a
        # revocation (post-revocation denials are routine, see above).
        routine_denial = (e.get("outcome") == "deny" and approval_matches(
            approvals, {"subject": actor, "operation": "revoke_role",
                        "at": e["_true_time"]}))
        if not routine_denial and action not in PRIVILEGE_ACTIONS and \
                not _edge_known(e):
            session_unknown.setdefault(sid, []).append(e)

        if abs(e["_offset_ms"]) > SUPPORTED_OFFSET_MS:
            order_uncertain.append(
                {"event_id": e["event_id"],
                 "reason": "clock_offset_%dms_beyond_supported_%dms"
                           % (int(e["_offset_ms"]), SUPPORTED_OFFSET_MS)})
        elif e["_offset_ms"]:
            annotations.append(
                {"event_id": e["event_id"], "note": "clock_offset",
                 "detail": "source clock %dms %s, within the supported "
                           "+/-%dms range (true time recovered by "
                           "subtracting the offset)"
                           % (int(abs(e["_offset_ms"])),
                              "ahead" if e["_offset_ms"] > 0 else "behind",
                              SUPPORTED_OFFSET_MS)})

    # Arrival-order inversions (per received order).
    by_recv = sorted(norm, key=lambda e: e["_recv_time"])
    for i in range(1, len(by_recv)):
        prev, cur = by_recv[i - 1], by_recv[i]
        if prev["_true_time"] > cur["_true_time"]:
            gap = prev["_true_time"] - cur["_true_time"]
            note = "delayed_delivery" if gap <= REORDER_TOLERANCE_S \
                else "order_uncertain"
            entry = {"event_id": cur["event_id"],
                     "detail": "older event (%s) arrived later by %.1fs; %s"
                               % (prev["event_id"], gap,
                                  "within reorder tolerance" if note ==
                                  "delayed_delivery" else "BEYOND tolerance")}
            (annotations if note == "delayed_delivery"
             else order_uncertain).append({"event_id": cur["event_id"],
                                           "note": note,
                                           "detail": entry["detail"]})

    # Pass 2: emit explainable alerts.
    alerts = []

    def emit(e, rule, related, explanation):
        alerts.append({
            "event_id": e["event_id"],
            "rule": rule,
            "identity": e.get("actor", ""),
            "services": [e.get("source_service", ""),
                         e.get("target_service", "")],
            "related_events": [r["event_id"] for r in related],
            "explanation": explanation,
            "alert_time": e["_recv_time"],
            "time_to_alert_s": round(e["_recv_time"]
                                     - related[0]["_true_time"], 3),
        })

    for sid, change in unexpected_change.items():
        e = change
        emit(e, "unexpected_role_change", [e],
             "identity=%s changed role %s->%s in session %s with no matching "
             "approval (checked subject, operation, role, validity window)"
             % (e["actor"], e.get("role_before"), e.get("role_after"), sid))
        for e2 in norm:
            if e2.get("session_id") == sid and e2["_true_time"] > e["_true_time"] \
                    and e2.get("action") == "read" \
                    and e2.get("outcome") in ("allow", "success"):
                emit(e2, "review_after_role_change", [e, e2],
                     "allowed data read in the same session follows the "
                     "unexpected role change of %s (rule: review-after-"
                     "unexpected-change)" % e["actor"])

    for sid, edges in session_unknown.items():
        if len(edges) >= LATERAL_BURST_MIN:
            first = edges[0]["event_id"]
            for e in edges:
                path = " -> ".join(["%s->%s" % (x["source_service"],
                                                x["target_service"])
                                    for x in edges])
                emit(e, "lateral_movement", edges,
                     "identity=%s traversed unusual service path [%s] in "
                     "session %s using valid credentials; edges are outside "
                     "the documented service graph and role scopes "
                     "(first edge %s)"
                     % (e["actor"], path, sid, first))

    # Metrics against ground truth.
    tp = fp = fn = 0
    benign = 0
    predicted = {a["event_id"] for a in alerts}
    for e in norm:
        lab = label_map.get(e["event_id"], {}).get("label", "routine")
        is_alert_truth = lab in ALERT_LABELS
        if is_alert_truth:
            benigntruth = False
        else:
            benigntruth = True
        if is_alert_truth and e["event_id"] in predicted:
            tp += 1
        elif not is_alert_truth and e["event_id"] in predicted:
            fp += 1
        elif is_alert_truth:
            fn += 1
        if benigntruth:
            benign += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if precision + recall else 0.0)
    ttas = [a["time_to_alert_s"] for a in alerts]
    return {
        "alerts": alerts,
        "annotations": annotations,
        "order_uncertain": order_uncertain,
        "f1": round(f1, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "median_time_to_alert_s": round(statistics.median(ttas), 3)
                                  if ttas else None,
        "false_alerts_per_1000_benign": round(fp / benign * 1000, 3)
                                        if benign else 0.0,
        "true_positives": tp, "false_positives": fp, "missed": fn,
        "benign_events": benign,
        "supported_offset_range_ms": SUPPORTED_OFFSET_MS,
        "reorder_tolerance_s": REORDER_TOLERANCE_S,
        "rules": ["unexpected_role_change", "review_after_role_change",
                  "lateral_movement"],
        "context_model": {
            "approvals": "subject + operation + role + validity window",
            "service_graph": sorted("%s->%s" % (a, b)
                                    for a, b in SERVICE_GRAPH),
            "role_scopes": ROLE_SCOPES,
            "lateral_burst_min": LATERAL_BURST_MIN,
        },
    }


def evaluate_live(log):
    """Structural rules over this service's own audit log.

    Each alert identifies identity, assets (services), events and rule.
    """
    alerts = []
    by_actor = {}
    for entry in log:
        by_actor.setdefault(entry.get("actor", ""), []).append(entry)

    for actor, entries in by_actor.items():
        denies = [e for e in entries if e.get("decision") == "deny"]
        # L1: >=3 denies across >=2 distinct assets within 60s -> lateral movement
        for i, e in enumerate(denies):
            window = [d for d in denies
                      if 0 <= e["ts"] - d["ts"] <= 60 and d["ts"] <= e["ts"]]
            assets = {d["asset"] for d in window}
            if len(window) >= 3 and len(assets) >= 2:
                alerts.append({
                    "rule": "lateral_movement",
                    "identity": actor,
                    "services": sorted(assets),
                    "events": [d["seq"] for d in window],
                    "explanation": "%d denied attempts across %d distinct "
                                   "assets within 60s by %s"
                                   % (len(window), len(assets), actor),
                    "alert_time": e["ts"],
                })
                break
        # L2: >10 actions in 60s -> volume anomaly
        if len(entries) > 10 and entries[-1]["ts"] - entries[0]["ts"] <= 60:
            alerts.append({
                "rule": "volume_anomaly",
                "identity": actor,
                "services": sorted({e["asset"] for e in entries}),
                "events": [e["seq"] for e in entries],
                "explanation": "%d events by %s within 60s"
                               % (len(entries), actor),
                "alert_time": entries[-1]["ts"],
            })
    return {"alerts": alerts, "log_entries": len(log)}
