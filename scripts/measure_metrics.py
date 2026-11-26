#!/usr/bin/env python3
"""Produce measured detector/performance metrics from THIS checkout.

No values are hardcoded: every number is computed by executing the detector,
the adapter operations, or the saved demo_networked.py run. Results are
written to docs/detector_metrics.json and docs/performance_metrics.json.
"""

import csv
import datetime
import json
import math
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import state as st  # noqa: E402
from src.detector import (SUPPORTED_OFFSET_MS, REORDER_TOLERANCE_S,  # noqa: E402
                          evaluate_labelled)
from src.dispatch import dispatch  # noqa: E402

PRACTICE = os.path.join(ROOT, "practice")
DOCS = os.path.join(ROOT, "docs")


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z")


def stats(samples, reps):
    ordered = sorted(samples)
    idx = min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)
    return {
        "repetitions": reps,
        "mean_s": round(statistics.mean(ordered), 6),
        "median_s": round(statistics.median(ordered), 6),
        "p95_s": round(ordered[idx], 6),
        "min_s": round(ordered[0], 6),
        "max_s": round(ordered[-1], 6),
    }


def measure(fn, reps=30):
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return stats(samples, reps)


def detector_metrics():
    events_path = os.path.join(PRACTICE, "events.csv")
    labels_path = os.path.join(PRACTICE, "labels.csv")
    approvals_path = os.path.join(PRACTICE, "approvals.json")
    events = list(csv.DictReader(open(events_path, newline="")))
    labels = list(csv.DictReader(open(labels_path, newline="")))
    approvals = json.load(open(approvals_path))
    result = evaluate_labelled(events_path=events_path,
                               labels_path=labels_path,
                               approvals_path=approvals_path)

    # Timing-range probes are derived from the same labelled practice set;
    # only a synthetic clock/receipt timestamp is varied.
    in_range = [dict(e) for e in events]
    in_range[1]["source_clock_offset_ms"] = "1000"     # 1 s, inside +/-60 s
    in_range_result = evaluate_labelled(events=in_range, labels=labels,
                                        approvals=approvals)
    beyond = [dict(e) for e in events]
    beyond[1]["source_clock_offset_ms"] = str(SUPPORTED_OFFSET_MS + 1000)
    beyond_result = evaluate_labelled(events=beyond, labels=labels,
                                      approvals=approvals)
    in_order = [dict(e) for e in events]
    in_order[1]["received_time_utc"] = "2026-01-15T09:01:03.000Z"
    in_order_result = evaluate_labelled(events=in_order, labels=labels,
                                        approvals=approvals)

    delayed = [a for a in result.get("annotations", [])
               if a.get("note") == "delayed_delivery"]

    return {
        "generated_at_utc": now_utc(),
        "dataset": {
            "name": "organizer synthetic practice set (practice/)",
            "events_file": "practice/events.csv",
            "labels_file": "practice/labels.csv",
            "approvals_file": "practice/approvals.json",
            "event_count": len(events),
            "label_count": len(labels),
            "synthetic": True,
            "scope": "These metrics apply ONLY to this practice set.",
        },
        "detector": "deterministic rule/graph detector; no AI/ML component",
        "f1": result["f1"],
        "precision": result["precision"],
        "recall": result["recall"],
        "median_time_to_alert_s": result["median_time_to_alert_s"],
        "false_alerts_per_1000_benign": result[
            "false_alerts_per_1000_benign"],
        "counts": {
            "true_positives": result["true_positives"],
            "false_positives": result["false_positives"],
            "missed": result["missed"],
            "benign_events": result["benign_events"],
            "alerts": len(result["alerts"]),
        },
        "alerts": [{
            "event_id": a["event_id"],
            "identity": a["identity"],
            "affected_services": a["services"],
            "triggering_event_ids": a["related_events"],
            "rule": a["rule"],
            "explanation": a["explanation"],
        } for a in result["alerts"]],
        "timing_range": {
            "supported_clock_skew_tolerance_s": SUPPORTED_OFFSET_MS / 1000.0,
            "supported_out_of_order_reorder_window_s": REORDER_TOLERANCE_S,
            "accepted_in_range_clock_case": {
                "event_id": "evt-002", "source_clock_offset_ms": 1000,
                "order_uncertain_count":
                    len(in_range_result.get("order_uncertain", [])),
            },
            "flagged_beyond_range_clock_case": {
                "event_id": "evt-002",
                "source_clock_offset_ms": SUPPORTED_OFFSET_MS + 1000,
                "order_uncertain": beyond_result.get("order_uncertain", []),
            },
            "accepted_in_range_reorder_case": delayed[:1],
            "flagged_beyond_range_reorder_case":
                in_order_result.get("order_uncertain", []),
        },
    }


def performance_metrics(demo):
    work = tempfile.mkdtemp(prefix="track4_metrics_")
    st.set_state_dir(work)
    try:
        dispatch({"op": "setup", "grace_seconds": 30,
                  "owners": {"report.txt": "user-alex"},
                  "contents": {"report.txt": "Q3 numbers are green"}})
        for actor, device in (("user-alex", "device-alex"),
                              ("user-blair", "device-blair")):
            dispatch({"op": "re_enroll", "actor": actor, "device": device})
        sid = dispatch({"op": "session_open", "sender": "user-alex",
                        "recipient": "user-blair"})["sid"]
        dispatch({"op": "session_accept", "sid": sid, "sender": "user-alex"})
        reps = 30
        operations = {
            "read": measure(lambda: dispatch({
                "op": "read", "actor": "user-alex",
                "asset": "report.txt"}), reps),
            "authentication": measure(lambda: dispatch({
                "op": "authenticate", "actor": "user-alex",
                "device": "device-alex", "node": "node-a"}), reps),
            "rotation": measure(lambda: dispatch({
                "op": "rotate_key", "grace_seconds": 30}), 10),
            "log_verification": measure(lambda: dispatch({
                "op": "verify_log"}), reps),
            "message_send": measure(lambda: dispatch({
                "op": "message_send", "sid": sid,
                "plaintext": "measured payload"}), reps),
            "detector_evaluation": measure(lambda: evaluate_labelled(
                events_path=os.path.join(PRACTICE, "events.csv"),
                labels_path=os.path.join(PRACTICE, "labels.csv"),
                approvals_path=os.path.join(PRACTICE, "approvals.json")), 20),
        }
    finally:
        st.set_state_dir(None)
        shutil.rmtree(work, ignore_errors=True)

    meas = demo["measurements"]
    rev = meas["revocation_last_node_enforcement_s"]
    operations["revocation_to_last_node_latency"] = {
        "value_s": rev,
        "last_node": meas["revocation_last_node"],
        "measurement_type": meas["revocation_measurement_type"],
        "per_node_s": {n: meas["revocation_propagation_%s_s" % n]
                       for n in ("node-a", "node-b", "node-c")},
        "note": "wall-clock measurement from demo_networked.py; NOT a "
                "guaranteed maximum",
    }
    return {
        "generated_at_utc": now_utc(),
        "context": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor() or "unreported",
            "logical_cpus": os.cpu_count(),
            "container_hint": os.path.exists("/.dockerenv"),
            "method": "time.perf_counter around in-process adapter calls; "
                      "revocation latency from real localhost processes",
            "statistics": "arithmetic mean, median and 95th percentile of "
                          "the listed repetitions; no synthetic values",
        },
        "grace_period": {
            "configured_s": meas["grace_period_s"],
            "accepted_during_grace": meas["grace_window_request"],
            "rejected_after_cutoff": meas["after_cutoff_request"],
        },
        "operations": operations,
    }


def main():
    demo_path = os.path.join(DOCS, "demo_networked_output.json")
    with open(demo_path) as f:
        demo = json.load(f)
    if not demo.get("all_checks_pass"):
        raise SystemExit("saved demo run did not pass all checks")
    det = detector_metrics()
    perf = performance_metrics(demo)
    with open(os.path.join(DOCS, "detector_metrics.json"), "w") as f:
        json.dump(det, f, indent=2)
        f.write("\n")
    with open(os.path.join(DOCS, "performance_metrics.json"), "w") as f:
        json.dump(perf, f, indent=2)
        f.write("\n")
    print(json.dumps({
        "detector_metrics": "docs/detector_metrics.json",
        "performance_metrics": "docs/performance_metrics.json",
        "f1": det["f1"],
        "median_time_to_alert_s": det["median_time_to_alert_s"],
        "revocation_last_node_s":
            perf["operations"]["revocation_to_last_node_latency"]["value_s"],
    }, indent=2))


if __name__ == "__main__":
    main()
