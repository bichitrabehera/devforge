"""Scripted end-to-end demonstration.

Runs the full protected workflow against a private state directory (never
disturbs operator state) and returns a compact summary of every checkpoint:

rotation/grace -> cutoff enforcement -> revocation timing per node ->
re-enrolment -> crash recovery -> backup integrity -> log injection &
tamper detection -> messaging (forward secrecy, replay, reordering,
binding) -> resumption -> detector metrics.
"""

import os
import tempfile

from . import state as st
from .dispatch import dispatch


def demo_script():
    outer = st._STATE_DIR
    st.set_state_dir(os.path.join(tempfile.gettempdir(), "track4_demo_state"))
    for p in (st.state_path(), st.journal_path()):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    steps = []
    try:
        def run(name, op, **kw):
            resp = dispatch({"op": op, **kw})
            steps.append({"name": name, "op": op, "resp": resp})
            return resp

        def out(name, *keys):
            resp = next(s["resp"] for s in steps if s["name"] == name)
            for k in keys:
                resp = resp.get(k) if isinstance(resp, dict) else None
            return resp

        run("init", "setup", owners={"report.txt": "user-alex"},
            roles={"user-alex": "report-reader"})
        run("clock+5", "advance_time", seconds=5)
        r = run("transfer-current", "authenticate", actor="user-alex",
                node="node-b", request_id="tx-1")
        v1 = r["key_version"]
        r = run("rotate", "rotate_key", grace_seconds=30)
        run("clock+10", "advance_time", seconds=10)
        run("transfer-old-in-grace", "authenticate", actor="user-alex",
            key_version=v1, node="node-a", request_id="tx-2")
        run("clock+25", "advance_time", seconds=25)      # past cutoff
        run("old-after-cutoff", "authenticate", actor="user-alex",
            key_version=v1, node="node-b", request_id="tx-3")
        run("current-after-rotation", "authenticate", actor="user-alex",
            node="node-b", request_id="tx-4")
        run("revoke", "revoke", device="device-blair")
        run("revoked-node-a", "authenticate", actor="user-blair",
            device="device-blair", node="node-a", request_id="tx-5")
        run("revoked-node-b-pending", "authenticate", actor="user-blair",
            device="device-blair", node="node-b", request_id="tx-6")
        run("clock+3", "advance_time", seconds=3)
        run("revoked-node-b", "authenticate", actor="user-blair",
            device="device-blair", node="node-b", request_id="tx-7")
        run("revoked-node-c-pending", "authenticate", actor="user-blair",
            device="device-blair", node="node-c", request_id="tx-9")
        run("clock+2", "advance_time", seconds=2)
        run("revoked-node-c-last", "authenticate", actor="user-blair",
            device="device-blair", node="node-c", request_id="tx-10")
        run("re-enroll", "re_enroll", device="device-blair",
            actor="user-blair")
        run("after-re-enroll", "authenticate", actor="user-blair",
            device="device-blair", node="node-b", request_id="tx-8")
        # interrupted rotation + recovery
        run("begin-rotation", "begin_rotation")
        run("crash", "crash_rotation", seconds=1)
        run("recover", "recover_state")
        run("after-recover", "authenticate", actor="user-alex",
            node="node-a", request_id="tx-9")
        # backup integrity
        run("backup", "create_backup", backup_id="bak-good")
        run("restore-good", "restore_backup", backup_id="bak-good")
        run("damage", "damage_backup", backup_id="bak-good")
        run("restore-damaged", "restore_backup", backup_id="bak-good")
        # log integrity: injection + tamper
        run("log-injection", "append_log", actor="mallory", action="read",
            asset="report.txt",
            detail='"}},"actor":"root","action":"grant_all","seq":99')
        run("verify-clean", "verify_log")
        run("tamper", "tamper_log", seq=2, field="actor", value="attacker")
        run("verify-tampered", "verify_log")
        # messaging
        run("enroll-alex", "re_enroll", device="device-alex",
            actor="user-alex")
        run("enroll-blair", "re_enroll", device="device-blair",
            actor="user-blair")
        r = run("session-open", "session_open", sender="user-alex",
                recipient="user-blair")
        sid = r["sid"]
        run("session-accept", "session_accept", sid=sid, sender="user-alex")
        m1 = run("send-1", "message_send", sid=sid,
                 plaintext="quarterly report v1")
        m2 = run("send-2", "message_send", sid=sid,
                 plaintext="quarterly report v2")
        m3 = run("send-3", "message_send", sid=sid,
                 plaintext="quarterly report v3")
        run("recv-reordered", "message_receive", sid=sid,
            recipient="user-blair", sender="user-alex",
            msg_id=m2["msg_id"], counter=m2["counter"], nonce=m2["nonce"],
            ciphertext=m2["ciphertext"])                    # buffered
        run("recv-duplicate", "message_receive", sid=sid,
            recipient="user-blair", sender="user-alex",
            msg_id=m2["msg_id"], counter=m2["counter"], nonce=m2["nonce"],
            ciphertext=m2["ciphertext"])                    # duplicate
        run("recv-fill", "message_receive", sid=sid,
            recipient="user-blair", sender="user-alex",
            msg_id=m1["msg_id"], counter=m1["counter"], nonce=m1["nonce"],
            ciphertext=m1["ciphertext"])                    # delivers 1+2
        run("recv-binding", "message_receive", sid=sid,
            recipient="user-mallory", sender="user-alex",
            msg_id=m3["msg_id"], counter=m3["counter"], nonce=m3["nonce"],
            ciphertext=m3["ciphertext"])                    # binding reject
        run("recv-3", "message_receive", sid=sid, recipient="user-blair",
            sender="user-alex", msg_id=m3["msg_id"],
            counter=m3["counter"], nonce=m3["nonce"],
            ciphertext=m3["ciphertext"])                    # delivers 3
        r = run("close", "session_close", sid=sid, peer="user-blair")
        run("resume-legit", "session_resume", sid=sid, peer="user-blair",
            resumption_token=r.get("resumption_token", ""))
        run("resume-imposter", "session_resume", sid=sid,
            peer="user-mallory",
            resumption_token=r.get("resumption_token", ""))
        # detector on labelled logs + live log
        practice = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "practice")
        run("detector-labelled", "detector_evaluate",
            events_path=os.path.join(practice, "events.csv"),
            labels_path=os.path.join(practice, "labels.csv"),
            approvals_path=os.path.join(practice, "approvals.json"))
        run("detector-live", "detector_live")
    finally:
        st.set_state_dir(outer)

    expected_errors = {"restore-damaged"}   # damaged backup must fail
    return {
        "steps": len(steps),
        "all_ok": all(
            s["resp"].get("status") == "ok"
            or s["name"] in expected_errors for s in steps),
        "highlights": {
            "transfer_during_rotation_current_key":
                out("transfer-current", "decision"),
            "old_key_inside_grace": out("transfer-old-in-grace", "outcome"),
            "old_key_after_cutoff": out("old-after-cutoff", "reason"),
            "current_key_after_rotation":
                out("current-after-rotation", "decision"),
            "revoke_reported_enforcement_s":
                out("revoke", "time_until_last_node_enforces"),
            "revoked_enforced_node_a": out("revoked-node-a", "reason"),
            "revoked_node_b_pending": out("revoked-node-b-pending",
                                          "decision"),
            "revoked_enforced_node_b": out("revoked-node-b", "reason"),
            "re_enroll_ok": out("after-re-enroll", "decision"),
            "recover_after_crash": out("recover", "recovered"),
            "still_revoked_after_recovery": out("recover", "still_revoked"),
            "valid_backup_restored": out("restore-good", "restored"),
            "damaged_backup_rejected": out("restore-damaged", "message"),
            "log_injection_stays_single_record":
                out("log-injection", "seq") is not None,
            "log_tamper_detected":
                out("verify-tampered", "valid") is False,
            "ephemeral_sk_retained":
                out("session-accept", "ephemeral_sk_retained"),
            "reordered_msg_buffered": out("recv-reordered", "decision"),
            "duplicate_rejected": out("recv-duplicate", "reason"),
            "reordered_delivered_with_fill": out("recv-fill", "decision"),
            "delivered_plaintexts":
                [m["plaintext"] for m in out("recv-fill", "messages") or []],
            "wrong_recipient_rejected": out("recv-binding", "reason"),
            "resumption_legit_peer": out("resume-legit", "decision"),
            "resumption_imposter_rejected":
                out("resume-imposter", "reason"),
            "detector_f1": out("detector-labelled", "f1"),
            "detector_median_tta_s":
                out("detector-labelled", "median_time_to_alert_s"),
            "detector_false_alerts_per_1000":
                out("detector-labelled", "false_alerts_per_1000_benign"),
        },
    }
