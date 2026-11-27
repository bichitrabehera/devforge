#!/usr/bin/env python3
"""Run the existing engine/demo functions and record a 17-step transcript.

Steps 1-14 are taken from the real multi-process demonstration
(``demo_networked.py``: 9 OS processes, real TCP, real clocks). Steps 15-17
use the embedded engine directly: live lateral-movement alerting, labelled
detector measurement and audit verification.

Outputs:
    docs/demo_transcript.txt
    docs/demo_metrics.json
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src import crypto, detector, dispatch, state as st  # noqa: E402

DOCS = ROOT / "docs"
NODES = ("node-a", "node-b", "node-c")

# (step, title, checks required from demo_networked.py)
NETWORKED_STEPS = [
    (1, "Login Alex and Blair", ["owner_read_allow", "peer_read_deny"]),
    (2, "Send encrypted message Node A -> Messenger -> Node B -> Node C",
     ["relay_session_established", "relayed_delivered_through_ABC"]),
    (3, "Blair reads the delivered message", ["endpoint_received_plaintext"]),
    (4, "Charlie cannot read the message",
     ["wrong_recipient_rejected_at_endpoint"]),
    (5, "Rotate Alex's key", ["new_key_every_node", "new_key_node_c"]),
    (6, "Old key accepted in grace, rejected after cutoff",
     ["old_key_in_real_grace", "old_key_after_real_cutoff"]),
    (7, "Revoke Blair's lost device",
     ["revoked_node-a", "revoked_node-b", "revoked_node-c"]),
    (8, "Every node denies the revoked device",
     ["revoked_node-a", "revoked_node-b", "revoked_node-c"]),
    (9, "Re-enrol a NEW Blair device with the recovery identity",
     ["recovery_identity_token_issued", "replacement_provisioned",
      "recovery_re_enroll_accepted"]),
    (10, "New device works; old device stays denied",
     ["replacement_device_access", "replacement_not_revoked",
      "old_device_still_revoked_after_recovery"]),
    (11, "Crash and journal recovery",
     ["registry_recovered_after_kill", "committed_key_version_after_restart"]),
    (12, "Revoked device still denied after restart",
     ["revocations_survive_crash", "revoked_after_restart_node-a",
      "revoked_after_restart_node-b", "revoked_after_restart_node-c"]),
    (13, "Corrupt backup copy and fail closed", ["damaged_backup_rejected"]),
    (14, "Tamper with a controlled log copy and detect it",
     ["node_log_tamper_detected", "registry_log_valid"]),
]


def run_networked_demo():
    proc = subprocess.run([sys.executable, str(ROOT / "demo_networked.py")],
                          cwd=str(ROOT), capture_output=True, text=True,
                          timeout=600)
    if not proc.stdout.strip():
        raise RuntimeError("demo_networked.py produced no JSON output: "
                           + proc.stderr[-500:])
    return json.loads(proc.stdout), proc.returncode


def run_embedded_checks():
    """Existing engine functions only: setup, read denies, detector, audit."""
    tmp = tempfile.mkdtemp(prefix="track4_demo_embedded_")
    st.set_state_dir(tmp)
    rec_pk, _ = crypto.dsa_keypair()   # runtime PQC key, never a credential output
    dispatch.dispatch({
        "op": "setup", "grace_seconds": 2.0,
        "owners": {"report.txt": "user-alex"},
        "contents": {"report.txt": "alex report"},
        "admins": ["user-admin"],
        "recovery_bindings": {"user-blair": "recovery-user-blair"},
        "recovery_public_keys": {"recovery-user-blair": rec_pk.hex()},
    })
    for user, device in (("user-alex", "device-alex"),
                         ("user-carol", "device-carol")):
        dispatch.dispatch({"op": "re_enroll", "actor": user, "device": device})

    # Real engine denials across two assets, then the existing live detector.
    for asset in ("asset-one", "asset-two", "asset-three"):
        dispatch.dispatch({"op": "read", "actor": "user-carol", "asset": asset})
    live = detector.evaluate_live(st.load_state()["log"])
    lateral = [a for a in live["alerts"] if a["rule"] == "lateral_movement"]

    measured = detector.evaluate_labelled(
        events_path=str(ROOT / "practice" / "events.csv"),
        labels_path=str(ROOT / "practice" / "labels.csv"),
        approvals_path=str(ROOT / "practice" / "approvals.json"))
    audit = dispatch.dispatch({"op": "verify_log"})
    return lateral, measured, audit


def main():
    DOCS.mkdir(exist_ok=True)
    net, net_exit = run_networked_demo()
    checks = net.get("checks", {})
    measured = net.get("measurements", {})

    lateral, labelled, audit = run_embedded_checks()
    steps = []
    for number, title, required in NETWORKED_STEPS:
        passed = all(checks.get(key) is True for key in required)
        evidence = ", ".join("%s=%s" % (k, checks.get(k)) for k in required)
        steps.append({"step": number, "title": title,
                      "status": "PASS" if passed else "FAIL",
                      "evidence": evidence})
    steps.append({
        "step": 15, "title": "Lateral movement produces an explainable alert",
        "status": "PASS" if lateral else "FAIL",
        "evidence": "live_alerts=%d; first=%s" % (
            len(live_alerts := [a for a in lateral]),
            (live_alerts[0]["rule"] if live_alerts else "none")),
    })
    steps.append({
        "step": 16, "title": "Run detector with real measured metrics",
        "status": "PASS" if labelled.get("f1") is not None else "FAIL",
        "evidence": "f1=%s precision=%s recall=%s median_tta_s=%s fp_per_1000=%s"
                    % (labelled["f1"], labelled["precision"],
                       labelled["recall"], labelled["median_time_to_alert_s"],
                       labelled["false_alerts_per_1000_benign"]),
    })
    steps.append({
        "step": 17, "title": "Verify the audit log",
        "status": "PASS" if audit.get("valid") is True else "FAIL",
        "evidence": "valid=%s entries=%s" % (audit.get("valid"),
                                             audit.get("entries")),
    })

    lines = [
        "Track 4 working demo transcript",
        "=" * 60,
        "Source: demo_networked.py (9 real processes) + existing embedded "
        "engine functions.",
        "All keys/credentials are generated at runtime; no private material "
        "is printed.",
        "",
    ]
    for step in steps:
        lines.append("%2d. [%s] %s" % (step["step"], step["status"],
                                       step["title"]))
        lines.append("    evidence: %s" % step["evidence"])
    lines += [
        "",
        "Networked checks: %d/%d passed (all_checks_pass=%s)" % (
            sum(1 for v in checks.values() if v is True), len(checks),
            net.get("all_checks_pass")),
        "Detector metrics apply only to the 22-event synthetic practice set.",
        "Crash recovery here is an embedded interrupted-rotation simulation; "
        "the networked demo separately kills and restarts a real registry "
        "process.",
    ]
    (DOCS / "demo_transcript.txt").write_text("\n".join(lines) + "\n")

    metrics = {
        "steps": steps,
        "all_steps_pass": all(s["status"] == "PASS" for s in steps),
        "networked_demo": {
            "exit_code": net_exit,
            "processes": net.get("processes"),
            "checks_passed": sum(1 for v in checks.values() if v is True),
            "checks_total": len(checks),
            "all_checks_pass": net.get("all_checks_pass"),
        },
        "measurements": measured,
        "detector": {
            "f1": labelled["f1"],
            "precision": labelled["precision"],
            "recall": labelled["recall"],
            "median_time_to_alert_s": labelled["median_time_to_alert_s"],
            "false_alerts_per_1000_benign":
                labelled["false_alerts_per_1000_benign"],
            "dataset_size": len(labelled.get("timeline", [])),
            "evaluation_scope":
                "22-event organizer synthetic practice set only; no AI/ML",
        },
        "audit": {"valid": audit.get("valid"),
                  "event_count": audit.get("entries")},
        "live_lateral_alerts": len(lateral),
    }
    (DOCS / "demo_metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print("transcript -> %s" % (DOCS / "demo_transcript.txt"))
    print("metrics -> %s" % (DOCS / "demo_metrics.json"))
    print("all_steps_pass = %s" % metrics["all_steps_pass"])
    return 0 if metrics["all_steps_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
