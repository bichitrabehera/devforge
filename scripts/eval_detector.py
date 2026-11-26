#!/usr/bin/env python3
"""Evaluate the detector against labelled logs and report per-class metrics.

    python scripts/eval_detector.py --events DIR/events.csv \
        --labels DIR/labels.csv --approvals DIR/approvals.json \
        --title "held-out" --out docs/metrics/heldout.json

Runs src/detector.py's evaluate_labelled (the same code the service runs)
and computes, ON TOP of the overall F1 / median-time-to-alert /
false-alerts-per-1000:
  * per-class precision/recall/F1 and support
  * an incident-level view (an incident = the set of suspicious-labelled
    events sharing actor+session+correlation id)
  * a short error listing (missed incidents, false alerts)

No rule is changed by this script; it measures only.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src import detector as det  # noqa: E402

ALERT_LABELS = {"unexpected_role_change", "review_after_role_change",
                "lateral_movement_candidate"}


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--events", required=True)
    p.add_argument("--labels", required=True)
    p.add_argument("--approvals", required=True)
    p.add_argument("--title", default="dataset")
    p.add_argument("--out", default=None, help="write the JSON report here")
    args = p.parse_args()

    result = det.evaluate_labelled(events_path=args.events,
                                   labels_path=args.labels,
                                   approvals_path=args.approvals)
    alerts = result["alerts"]
    predicted = {a["event_id"] for a in alerts}

    # ground truth
    events = det.load_events(args.events)
    labels = det.load_labels(args.labels)
    truth_suspicious = {e["event_id"] for e in events
                        if labels.get(e["event_id"], {}).get("label")
                        in ALERT_LABELS}
    cls_of = {e["event_id"]: labels.get(e["event_id"], {}).get("label",
                                                             "unlabelled")
              for e in events}

    # per-class confusion
    per_class = {}
    classes = sorted({cls_of[eid] for eid in cls_of})
    for cls in classes:
        tp = fp = fn = tn = 0
        for eid, cls_actual in cls_of.items():
            is_cls = cls_actual == cls
            pred_alert = eid in predicted
            truth_alert = cls_actual in ALERT_LABELS
            if is_cls and pred_alert and truth_alert:
                tp += 1
            elif is_cls and not pred_alert and truth_alert:
                fn += 1
            elif not is_cls and pred_alert and not truth_alert:
                fp += 1
            elif not is_cls and not pred_alert and not truth_alert:
                tn += 1
        prec = tp / (tp + fp) if tp + fp else None
        rec = tp / (tp + fn) if tp + fn else None
        f1 = (2 * prec * rec / (prec + rec)
              if prec is not None and rec is not None and prec + rec
              else None)
        per_class[cls] = {
            "support": sum(1 for c in cls_of.values() if c == cls),
            "precision": round(prec, 3) if prec is not None else None,
            "recall": round(rec, 3) if rec is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
            "tp": tp, "fp": fp, "fn": fn,
        }

    # incident-level accounting
    def incident_key(eid):
        e = next(x for x in events if x["event_id"] == eid)
        return (e.get("actor", ""), e.get("session_id", ""),
                e.get("correlation_id", ""))

    truth_inc = defaultdict(set)
    for eid in truth_suspicious:
        truth_inc[incident_key(eid)].add(eid)
    pred_inc = defaultdict(set)
    for eid in predicted:
        if eid in cls_of:
            pred_inc[incident_key(eid)].add(eid)
    incidents_hit = sum(1 for k in truth_inc if pred_inc.get(k))
    incidents_missed = [sorted(v) for k, v in truth_inc.items()
                        if not pred_inc.get(k)]
    false_incidents = [sorted(v) for k, v in pred_inc.items()
                       if k not in truth_inc]

    benign = sum(1 for eid, c in cls_of.items()
                 if c not in ALERT_LABELS)
    fp_events = [eid for eid in predicted if eid not in truth_suspicious]

    report = {
        "title": args.title,
        "events": len(events),
        "labelled_events": len(labels),
        "detector": "deterministic rule/graph detector; no AI/ML; rules "
                    "tuned on the 22-event practice set only",
        "overall": {
            "f1": result["f1"], "precision": result["precision"],
            "recall": result["recall"],
            "true_positives": result["true_positives"],
            "false_positives": result["false_positives"],
            "missed": result["missed"],
            "benign_events": benign,
            "false_alerts_per_1000_benign":
                result["false_alerts_per_1000_benign"],
            "median_time_to_alert_s": result["median_time_to_alert_s"],
            "alerts_raised": len(alerts),
        },
        "incidents": {
            "truth": len(truth_inc),
            "detected": incidents_hit,
            "missed_examples": incidents_missed[:8],
            "false_examples": false_incidents[:8],
        },
        "per_class": per_class,
        "error_note":
            "Rules were NOT changed after this run (held-out discipline).",
    }
    print(json.dumps(report["overall"], indent=1))
    print("incidents: %d/%d detected, %d false incident groups"
          % (incidents_hit, len(truth_inc), len(false_incidents)))
    print("per-class F1:")
    for cls, m in sorted(per_class.items()):
        print("  %-28s support=%-6d P=%-6s R=%-6s F1=%s"
              % (cls, m["support"], m["precision"], m["recall"], m["f1"]))
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(report, f, indent=1, default=str)
        print("report -> %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
