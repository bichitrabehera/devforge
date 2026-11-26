#!/usr/bin/env python3
"""Networked Track 4 demonstration - everything runs as REAL processes.

Topology (all separate OS processes over real TCP):
    registry (control plane, port A)      idp (identity provider, port B)
        |                                        |
   node-a (poll 0.5s)   node-b (poll 2.0s)   tokens issued per identity
        \                    |                  |
         \             recv endpoint (messaging, keys in RAM only)
          \____________________|___________________/
                     real HTTP delivery, loss + reordering

What is measured with the REAL clock (nothing simulated):
  * revocation -> enforcement at each node (real poll interval + latency)
  * old-key cutoff enforcement after a real grace window
  * registry kill -9 mid-rotation -> journal replay recovery on restart
  * damaged backup detection; log tamper detection
  * E2E delivery under real reordering/loss over sockets; keys never on disk

Usage:  python3 demo_networked.py
"""

import json
import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from src import crypto, netutil, tokens  # noqa: E402
from src.messaging import CONTEXT, _msg_aad  # noqa: E402

POLL_A, POLL_B, POLL_C = 0.5, 2.0, 4.0
GRACE = 6.0          # real seconds


def wait_port_proc(proc, url, name):
    if not netutil.wait_healthy(url, timeout=15):
        proc.kill()
        raise RuntimeError("%s failed to start" % name)


def start(cmd, env):
    e = dict(os.environ, **env)
    errfile = open(os.path.join(env_dir_hint(e), "stderr.log"), "ab")
    return subprocess.Popen([sys.executable] + cmd, cwd=ROOT, env=e,
                            stdout=errfile,
                            stderr=errfile)


def env_dir_hint(e):
    for k, v in e.items():
        if k.startswith("TRACK4_") and os.path.isdir(v):
            return v
    return "."


def main():
    scratch = os.path.join(ROOT, ".redteam")
    os.makedirs(scratch, exist_ok=True)
    work = tempfile.mkdtemp(prefix="track4net_", dir=scratch)
    ports = {k: netutil.free_port() for k in
             ("registry", "idp", "node-a", "node-b", "node-c", "recv",
              "msgr-a", "msgr-b", "msgr-c")}
    base = {k: "http://127.0.0.1:%d" % v for k, v in ports.items()}
    procs = []
    report = {"processes": 9, "measurements": {}, "checks": {}}

    def env_for(*dirs):
        e = {}
        for i, d in enumerate(dirs):
            e[d] = os.path.join(work, d.lower().replace("track4_", ""))
        return e

    reg_env = env_for("TRACK4_REGISTRY_DIR")
    idp_env = env_for("TRACK4_IDP_DIR")
    node_a_env = env_for("TRACK4_NODE_NODE_A_DIR")
    node_b_env = env_for("TRACK4_NODE_NODE_B_DIR")
    node_c_env = env_for("TRACK4_NODE_NODE_C_DIR")
    recv_env = env_for("TRACK4_MESSENGER_RECV_DIR")

    procs.append(start(["services/registry_server.py",
                        "--port", str(ports["registry"]),
                        "--idp", base["idp"]], reg_env))
    procs.append(start(["services/idp_server.py",
                        "--port", str(ports["idp"])], idp_env))
    wait_port_proc(procs[0], base["registry"], "registry")
    wait_port_proc(procs[1], base["idp"], "idp")

    procs.append(start(["services/node_server.py", "--name", "node-a",
                        "--port", str(ports["node-a"]),
                        "--registry", base["registry"], "--idp", base["idp"],
                        "--poll-interval", str(POLL_A),
                        "--relay-next", base["node-b"],
                        "--gossip-next", base["msgr-b"]], node_a_env))
    procs.append(start(["services/node_server.py", "--name", "node-b",
                        "--port", str(ports["node-b"]),
                        "--registry", base["registry"], "--idp", base["idp"],
                        "--poll-interval", str(POLL_B),
                        "--relay-next", base["node-c"],
                        "--gossip-next", base["msgr-c"]], node_b_env))
    procs.append(start(["services/node_server.py", "--name", "node-c",
                        "--port", str(ports["node-c"]),
                        "--registry", base["registry"], "--idp", base["idp"],
                        "--poll-interval", str(POLL_C),
                        "--deliver-to", base["recv"],
                        "--gossip-next", base["msgr-a"]], node_c_env))
    wait_port_proc(procs[2], base["node-a"], "node-a")
    wait_port_proc(procs[3], base["node-b"], "node-b")
    wait_port_proc(procs[4], base["node-c"], "node-c")

    procs.append(start(["services/messenger_server.py", "--name", "recv",
                        "--port", str(ports["recv"]),
                        "--idp", base["idp"], "--registry", base["registry"],
                        "--identity", "user-blair",
                        "--peer", "user-alex"], recv_env))
    wait_port_proc(procs[5], base["recv"], "recv")

    # per-node messaging inboxes: node-a/b/c each own an identity; the
    # node PROCESSES gossip encrypted policy-acks into the next node's
    # inbox (a->b->c->a ring)
    for name, port_key, peer in (("node-a", "msgr-a", "node-c"),
                                 ("node-b", "msgr-b", "node-a"),
                                 ("node-c", "msgr-c", "node-b")):
        procs.append(start(["services/messenger_server.py",
                            "--name", "msgr-" + name,
                            "--port", str(ports[port_key]),
                            "--idp", base["idp"],
                            "--registry", base["registry"],
                            "--identity", name,
                            "--peer", peer], recv_env))
    for i, key in ((6, "msgr-a"), (7, "msgr-b"), (8, "msgr-c")):
        wait_port_proc(procs[i], base[key], key)

    # register the NODE identities at the IdP with each node's OWN
    # long-term key (read from the node's real keyfile): gossip tokens
    # are proof-of-possession of the node's key, exactly like users
    node_dirs = {"node-a": os.path.join(work, "node_node_a_dir"),
                 "node-b": os.path.join(work, "node_node_b_dir"),
                 "node-c": os.path.join(work, "node_node_c_dir")}
    for name, d in node_dirs.items():
        with open(os.path.join(d, "node_key.json")) as f:
            k = json.load(f)
        netutil.request(base["idp"] + "/register",
                        {"identity": name, "device": name,
                         "dsa_pk": k["dsa_pk"]}, method="POST")

    def R(op, **kw):
        return netutil.request(base["registry"] + op, kw or None,
                               method="POST" if kw else "GET")[1]

    def NODE(node, op, **kw):
        url = base[node] + op
        code, r = netutil.request(url, kw or None,
                                  method="POST" if kw else "GET")
        if "DEBUG" in os.environ and code != 200:
            print("DEBUG %s %s -> %s %s" % (node, op, code, r), file=sys.stderr)
        return r

    try:
        # setup + identities: each identity registers its DEVICE ML-DSA
        # PUBLIC KEY; token issuance later requires proof-of-possession
        # (fresh signature over {identity, device, ts} with that key).
        dev = {}
        for name, dev_name in (("user-alex", "device-alex"),
                               ("user-blair", "device-blair"),
                               ("user-carol", "device-carol"),
                               ("user-mallory", "device-mallory"),
                               ("user-admin", "device-admin"),
                               ("recovery-user-blair",
                                "device-recovery-blair")):
            pk, sk = crypto.dsa_keypair()
            dev[name] = (dev_name, pk.hex(), sk.hex())
            netutil.request(base["idp"] + "/register",
                            {"identity": name, "device": dev_name,
                             "dsa_pk": pk.hex()}, method="POST")
        r = R("/setup", owners={"report.txt": "user-alex",
                                "notes.txt": "user-blair"},
              contents={"report.txt": "Q3 numbers are green",
                        "notes.txt": "blair's own notes"},
              grace_seconds=GRACE)
        # registry identities (nodes enforce relay permission from policy)
        for name in ("user-alex", "user-blair", "user-carol",
                     "user-mallory"):
            R("/identities/register", identity=name,
              device=dev[name][0])
        for name in ("node-a", "node-b", "node-c"):
            R("/identities/register", identity=name, device=name)
        toks = {}
        tok_blair_old = None
        for name in ("user-alex", "user-blair", "user-carol"):
            dev_name, _, sk_hex = dev[name]
            req = tokens.device_proof(sk_hex, name, dev_name)
            req["ttl_s"] = 900
            _, resp = netutil.request(base["idp"] + "/token", req,
                                      method="POST")
            toks[name] = resp["token"]
        tok_alex, tok_blair, tok_carol = (toks["user-alex"],
                                          toks["user-blair"],
                                          toks["user-carol"])
        tok_blair_old = tok_blair   # pre-loss token (device-blair)
        time.sleep(max(POLL_A, POLL_B, POLL_C) + 0.3)  # nodes pick up policy

        def make_env(sid, shared, counter, plaintext, recipient="user-blair",
                     sender="user-alex", version=1, mangle=None):
            """Build a wire envelope with FULL AAD binding."""
            key = crypto.hkdf(shared, ("track4-session:%s:%s:%s"
                                       % (sid, sender, recipient)).encode())
            nonce = crypto.hkdf(key, b"track4-nonce:%d" % counter, 12)
            msg_id = crypto.sha256_hex(crypto.canonical(
                {"sid": sid, "counter": counter}).encode())[:24]
            aad = _msg_aad(sid, sender, recipient, counter, msg_id=msg_id,
                           context=CONTEXT, key_version=version)
            ct = crypto.aead_encrypt(key, nonce, plaintext.encode(), aad)
            env = {"sid": sid, "sender": sender, "recipient": recipient,
                   "counter": counter, "nonce": nonce.hex(),
                   "ciphertext": ct.hex(), "msg_id": msg_id,
                   "context": CONTEXT, "key_version": version}
            if mangle == "truncate":
                env["ciphertext"] = env["ciphertext"][:-8]
            elif mangle == "flip":
                env["ciphertext"] = env["ciphertext"][:-4] + "0000"
            elif mangle == "context":
                env["context"] = "other-protocol"
            return env

        # 1. real reads through real nodes
        r = NODE("node-a", "/read", token=tok_alex, asset="report.txt")
        report["checks"]["owner_read_allow"] = r["decision"] == "allow"
        r = NODE("node-b", "/read", token=tok_blair, asset="report.txt")
        report["checks"]["peer_read_deny"] = r["decision"] == "deny"

        # 2. rotation with REAL grace: nodes apply at their own poll times
        r = R("/keys/rotate", grace_seconds=GRACE)
        v_new = r["new_version"]
        t_rotate = time.time()
        time.sleep(POLL_A + 0.3)
        r = NODE("node-a", "/authenticate", token=tok_alex, key_version=1)
        report["measurements"]["grace_period_s"] = GRACE
        report["measurements"]["grace_window_request"] = {
            "decision": r.get("decision"), "outcome": r.get("outcome"),
            "key_version": 1}
        report["checks"]["old_key_in_real_grace"] = \
            r["decision"] == "allow" and r.get("outcome") == "grace"
        time.sleep(GRACE + 0.5)                    # real cutoff passes
        r = NODE("node-a", "/authenticate", token=tok_alex, key_version=1)
        report["measurements"]["after_cutoff_request"] = {
            "decision": r.get("decision"), "reason": r.get("reason"),
            "key_version": 1}
        report["checks"]["old_key_after_real_cutoff"] = \
            r["decision"] == "deny" and \
            r.get("reason") == "old_key_after_cutoff"
        r = NODE("node-b", "/authenticate", token=tok_alex,
                 key_version=v_new)
        report["checks"]["new_key_every_node"] = r["decision"] == "allow"
        r = NODE("node-c", "/authenticate", token=tok_alex,
                 key_version=v_new)
        report["checks"]["new_key_node_c"] = r["decision"] == "allow"

        # A session opened BEFORE revocation: its ciphertext is captured,
        # then replayed after revocation to prove the recipient node rejects
        # it; the resumption token is later tried with the lost device.
        _, offer_pre = netutil.request(
            base["recv"] + "/session/offer",
            {"sender": "user-alex", "token": tok_alex}, method="POST")
        sid_pre = offer_pre["sid"]
        ct_pre, ss_pre = crypto.kem_encaps(
            bytes.fromhex(offer_pre["encapsulation_key"]))
        netutil.request(base["recv"] + "/session/establish",
                        {"sid": sid_pre, "ciphertext": ct_pre.hex(),
                         "sender": "user-alex", "token": tok_alex},
                        method="POST")
        env_pre = make_env(sid_pre, ss_pre, 1, "captured before loss",
                           version=v_new)

        # 3. revocation with REAL propagation measurement per node.
        # A deny must carry reason "revoked" - a routine not-owner denial
        # would pass trivially (same discipline as tests/test_networked).
        # self-service revocation: blair reports her own device lost,
        # proven with her ML-DSA token (registry verifies subject==actor)
        r = R("/revoke", actor="user-blair", device="device-blair",
              token=tok_blair)
        t_revoke = time.time()
        for name, deadline_s in (("node-a", 3.0), ("node-b", POLL_B + 3.0),
                                 ("node-c", POLL_C + 3.0)):
            deadline = time.time() + deadline_s
            while time.time() < deadline:
                r = NODE(name, "/read", token=tok_blair, asset="report.txt")
                if r["decision"] == "deny" and r.get("reason") == "revoked":
                    break
                time.sleep(0.1)
            enforced = time.time()
            report["checks"]["revoked_" + name] = \
                r["decision"] == "deny" and r.get("reason") == "revoked"
            report["measurements"]["revocation_propagation_%s_s" % name] = \
                round(enforced - t_revoke, 3)
            _, status = netutil.request(base[name] + "/status", None)
            report["measurements"]["%s_reported_propagation_s" % name] = \
                (status.get("enforcement_log") or [{}])[-1].get(
                    "propagation_s")
        report["measurements"]["revocation_last_node"] = "node-c"
        report["measurements"]["revocation_last_node_enforcement_s"] = max(
            report["measurements"]["revocation_propagation_%s_s" % n]
            for n in ("node-a", "node-b", "node-c"))
        report["measurements"]["revocation_measurement_type"] = \
            "single measured run (not a guaranteed maximum)"

        # 4. other users unaffected; a message captured BEFORE the loss is
        # relayed to the still-revoked recipient. Nodes A and B allow the
        # sender; the FINAL node (node-c) denies the recipient.
        r = NODE("node-a", "/read", token=tok_alex, asset="report.txt")
        report["checks"]["other_users_unaffected"] = r["decision"] == "allow"
        v_now = R("/keys/current")["version"]
        r = NODE("node-a", "/message/send", token=tok_alex, **env_pre)
        report["checks"]["relayed_denied_at_recipient_node"] = \
            r["decision"] == "deny" and r.get("reason") == "recipient_revoked"
        report["measurements"]["route_revoked_recipient"] = \
            [h["node"] for h in r.get("route", [])]
        report["measurements"]["revoked_recipient_node_decisions"] = \
            r.get("route", [])
        report["checks"]["revoked_recipient_never_delivered"] = \
            r.get("delivered") is False
        _, inbox = netutil.request(base["recv"] + "/messages")
        report["checks"]["revoked_recipient_no_plaintext"] = \
            not any(m["plaintext"] == "captured before loss"
                    for m in inbox["delivered"])

        # 5. REAL crash: SIGKILL the registry, restart it, and prove that
        # the STILL-REVOKED device remains revoked on every node. No
        # re-enrolment happens before this point.
        procs[0].send_signal(signal.SIGKILL)
        procs[0].wait()
        procs[0] = start(["services/registry_server.py",
                          "--port", str(ports["registry"]),
                          "--idp", base["idp"]], reg_env)
        wait_port_proc(procs[0], base["registry"], "registry")
        r = R("/keys/current")
        report["checks"]["registry_recovered_after_kill"] = \
            r["status"] == "ok" and r["version"] >= v_new
        report["checks"]["committed_key_version_after_restart"] = \
            r["version"] == v_new
        p = netutil.request(base["registry"] + "/policy")[1]
        report["checks"]["revocations_survive_crash"] = \
            "device-blair" in p["revoked"]
        # committed protected data survives on the restarted registry
        r = NODE("node-a", "/read", token=tok_alex, asset="report.txt")
        report["checks"]["protected_data_after_restart"] = \
            r["decision"] == "allow" and \
            r.get("body") == "Q3 numbers are green"
        # every node still denies the old token/device after real restart
        for name in ("node-a", "node-b", "node-c"):
            rr = NODE(name, "/read", token=tok_blair_old,
                      asset="notes.txt")
            report["checks"]["revoked_after_restart_" + name] = \
                rr["decision"] == "deny" and rr.get("reason") == "revoked"
        rr = NODE("node-a", "/message/send", token=tok_alex, **env_pre)
        report["checks"]["revoked_recipient_after_restart"] = \
            rr["decision"] == "deny" and \
            rr.get("reason") == "recipient_revoked"

        # 6. REAL lost-device recovery (Task 1). The lost device private
        # key is gone: a SEPARATE recovery identity proves possession of its
        # OWN runtime-generated ML-DSA key, then the IdP generates a fresh
        # replacement device keypair/credential at runtime. Only a random
        # enrolment credential is returned; no private key is exposed.
        # The recovery identity was registered at startup with its own
        # runtime-generated ML-DSA key; the lost device key is not used.
        _, rec_sk_hex = dev["recovery-user-blair"][1:]
        rec_req = tokens.device_proof(rec_sk_hex, "recovery-user-blair",
                                      dev["recovery-user-blair"][0])
        rec_req["ttl_s"] = 300
        rec_tok = netutil.request(base["idp"] + "/token", rec_req,
                                  method="POST")[1]["token"]
        report["checks"]["recovery_identity_token_issued"] = bool(rec_tok)
        # Knowing the user id alone, or presenting another user's token,
        # must never authorize provisioning.
        r = netutil.request(
            base["idp"] + "/recover/provision",
            {"identity": "user-blair", "token": tok_carol},
            method="POST")[1]
        report["checks"]["foreign_token_cannot_provision"] = \
            r.get("reason") == "not_permitted"
        r = netutil.request(base["idp"] + "/recover/provision",
                            {"identity": "user-blair"}, method="POST")[1]
        report["checks"]["unauthenticated_provision_rejected"] = \
            r["status"] == "error"
        prov = netutil.request(
            base["idp"] + "/recover/provision",
            {"identity": "user-blair", "token": rec_tok},
            method="POST")[1]
        NEW_DEV = prov.get("device", "")
        report["checks"]["replacement_provisioned"] = prov["status"] == "ok"
        report["checks"]["replacement_device_is_distinct"] = \
            NEW_DEV not in ("", "device-blair")
        report["checks"]["no_private_key_in_recovery_response"] = \
            not any(k in prov for k in
                    ("dsa_sk", "kem_sk", "private_key", "enrolment_secret_hash"))
        report["checks"]["runtime_credential_generated"] = \
            bool(prov.get("enrolment_secret")) and \
            len(prov["enrolment_secret"]) >= 32
        # The registry also requires the recovery identity: an ordinary
        # user token cannot re-enrol the lost device.
        r = R("/re_enroll", actor="user-blair", old_device="device-blair",
              device=NEW_DEV, token=tok_alex)
        report["checks"]["wrong_token_cannot_re_enroll"] = \
            r.get("reason") == "not_permitted"
        r_re = R("/re_enroll", actor="user-blair",
                 old_device="device-blair", device=NEW_DEV, token=rec_tok)
        report["checks"]["recovery_re_enroll_accepted"] = \
            r_re.get("status") == "ok"
        report["checks"]["old_device_still_revoked_after_recovery"] = \
            r_re.get("old_device_still_revoked") is True
        p = netutil.request(base["registry"] + "/policy")[1]
        report["checks"]["old_device_revoked_in_policy"] = \
            "device-blair" in p["revoked"]
        report["checks"]["replacement_not_revoked"] = \
            NEW_DEV not in p["revoked"]
        # The lost key can no longer mint a token.
        old_proof = tokens.device_proof(dev["user-blair"][2], "user-blair",
                                        "device-blair")
        old_proof["ttl_s"] = 300
        r = netutil.request(base["idp"] + "/token", old_proof,
                            method="POST")[1]
        report["checks"]["lost_key_cannot_mint_token"] = \
            r["status"] == "error"
        time.sleep(POLL_C + 0.6)   # every node applies the replacement
        # The replacement obtains a token with the runtime credential and
        # accesses its own authorized data.
        r = netutil.request(
            base["idp"] + "/token",
            {"identity": "user-blair", "ttl_s": 300,
             "enrolment_secret": prov["enrolment_secret"]},
            method="POST")[1]
        tok_blair_new = r.get("token", "")
        report["checks"]["replacement_token_issued"] = bool(tok_blair_new)
        rr = NODE("node-c", "/read", token=tok_blair_new,
                  asset="notes.txt")
        report["checks"]["replacement_device_access"] = \
            rr["decision"] == "allow" and \
            rr.get("body") == "blair's own notes"
        # The old device/token/session stays denied AFTER replacement.
        for name in ("node-a", "node-b", "node-c"):
            rr = NODE(name, "/read", token=tok_blair_old,
                      asset="notes.txt")
            report["checks"]["old_device_denied_after_recovery_" + name] = \
                rr["decision"] == "deny" and rr.get("reason") == "revoked"
        rr = NODE("node-a", "/read", token=tok_alex, asset="report.txt")
        report["checks"]["other_users_still_ok_after_recovery"] = \
            rr["decision"] == "allow"
        _, idp_audit = netutil.request(base["idp"] + "/audit")
        acts = [a["action"] for a in idp_audit["audit"]]
        report["checks"]["recovery_audited_at_idp"] = \
            "recover_provision" in acts
        _, reg_log = netutil.request(base["registry"] + "/log")
        reg_actions = [a.get("action") for a in reg_log["log"]]
        report["checks"]["recovery_audited_at_registry"] = \
            "recovery_enrol" in reg_actions and "revoke" in reg_actions
        report["checks"]["registry_log_valid_after_recovery"] = \
            R("/verify_log")["valid"]

        # 7. NODE-TO-NODE MESSAGE DELIVERY (real processes, real sockets).
        # Alex -> node-a -> node-b -> node-c -> Blair's messaging endpoint.
        # Every hop verifies the token and enforces identity/device/key/
        # permission/revocation. The final node enforces recipient state;
        # the endpoint enforces full AEAD AAD binding and replay windows.
        v_msg = R("/keys/current")["version"]

        def open_session():
            _, offer = netutil.request(
                base["recv"] + "/session/offer",
                {"sender": "user-alex", "token": tok_alex}, method="POST")
            sid = offer["sid"]
            ct, ss = crypto.kem_encaps(
                bytes.fromhex(offer["encapsulation_key"]))
            est = netutil.request(
                base["recv"] + "/session/establish",
                {"sid": sid, "ciphertext": ct.hex(), "sender": "user-alex",
                 "token": tok_alex}, method="POST")[1]
            return sid, ss, est

        def env_for(sid, ss, counter, plaintext, recipient="user-blair",
                    sender="user-alex", mangle=None, version=None):
            return make_env(sid, ss, counter, plaintext,
                            recipient=recipient, sender=sender,
                            version=v_msg if version is None else version,
                            mangle=mangle)

        def relayed(env, token):
            body = dict(env, token=token)
            return NODE("node-a", "/message/send", **body)

        sid_m, ss_m, est = open_session()
        report["checks"]["relay_session_established"] = \
            est.get("status") == "ok" and \
            est.get("ephemeral_sk_retained") is False
        r = relayed(env_for(sid_m, ss_m, 1, "hello via nodes A,B,C"),
                    tok_alex)
        route = r.get("route", [])
        report["measurements"]["message_route"] = \
            ["user-alex"] + [h["node"] for h in route] + ["user-blair"]
        report["measurements"]["node_decisions"] = route
        report["checks"]["relayed_delivered_through_ABC"] = \
            r["decision"] == "deliver" and \
            [h["node"] for h in route] == \
            ["node-a", "node-b", "node-c", "node-c/messaging-endpoint"] and \
            [m["plaintext"] for m in r.get("delivered_messages", [])] == \
            ["hello via nodes A,B,C"]
        _, inbox = netutil.request(base["recv"] + "/messages")
        report["checks"]["endpoint_received_plaintext"] = \
            any(m["plaintext"] == "hello via nodes A,B,C"
                for m in inbox["delivered"])

        # Reordered segment: counter 1 is delivered, counter 3 arrives
        # early (buffered), then the delayed counter 2 is recovered and
        # releases 2 and 3 in strict order.
        r3 = relayed(env_for(sid_m, ss_m, 3, "third"), tok_alex)
        r2 = relayed(env_for(sid_m, ss_m, 2, "second"), tok_alex)
        report["measurements"]["gap_step_decisions"] = \
            [{"counter": 3, "decision": r3.get("decision"),
              "reason": r3.get("reason")},
             {"counter": 2, "decision": r2.get("decision"),
              "reason": r2.get("reason"),
              "delivered": [m["plaintext"] for m in
                            r2.get("delivered_messages", [])]}]
        report["checks"]["gap_buffered_at_endpoint"] = \
            r3["decision"] == "buffered" and r2["decision"] == "deliver" and \
            [m["plaintext"] for m in r2.get("delivered_messages", [])] == \
            ["second", "third"]
        report["measurements"]["reorder_arrival_sequence"] = [1, 3, 2]
        report["measurements"]["delivery_order"] = \
            [m["plaintext"] for m in r2.get("delivered_messages", [])]
        # Replaying the recovered segment in the SAME session is rejected.
        r = relayed(env_for(sid_m, ss_m, 2, "second"), tok_alex)
        report["checks"]["relayed_replay_rejected"] = \
            r["decision"] == "reject" and \
            r.get("reason") == "duplicate_replay"

        # A separate session/endpoint state for the remaining negative
        # cases keeps their counters independent of the reorder sequence.
        sid_r, ss_r, _ = open_session()
        relayed(env_for(sid_r, ss_r, 1, "first"), tok_alex)

        # Wrong recipient, unknown recipient, tampering and an incomplete
        # message are all rejected with explicit decisions.
        r = relayed(env_for(sid_r, ss_r, 4, "for mallory",
                            recipient="user-mallory"), tok_alex)
        report["checks"]["wrong_recipient_rejected_at_endpoint"] = \
            r["decision"] == "reject" and \
            r.get("reason") == "recipient_binding_mismatch"
        r = relayed(env_for(sid_r, ss_r, 5, "to ghost",
                            recipient="user-ghost"), tok_alex)
        report["checks"]["unknown_recipient_denied_at_origin"] = \
            r["decision"] == "deny" and \
            r.get("reason") == "recipient_not_active"
        r = relayed(env_for(sid_r, ss_r, 6, "tampered", mangle="flip"),
                    tok_alex)
        report["checks"]["tampered_message_rejected"] = \
            r["decision"] == "reject" and \
            r.get("reason") == "authentication_failed"
        r = relayed(env_for(sid_r, ss_r, 7, "truncated", mangle="truncate"),
                    tok_alex)
        report["checks"]["incomplete_message_rejected"] = \
            r["decision"] == "reject" and \
            r.get("reason") == "authentication_failed"
        r = relayed(env_for(sid_r, ss_r, 8, "wrong context",
                            mangle="context"), tok_alex)
        report["checks"]["context_binding_enforced"] = \
            r["decision"] == "reject" and \
            r.get("reason") == "context_mismatch"
        _, inbox = netutil.request(base["recv"] + "/messages")
        failures = inbox.get("failures", [])
        report["measurements"]["delivery_failures"] = failures
        report["checks"]["delivery_failure_reported"] = any(
            f.get("failure") in ("authentication_failed", "context_mismatch")
            for f in failures)

        # A revoked sender is denied at the ORIGIN node, before any relay.
        r = R("/revoke", actor="user-carol", device="device-carol",
              token=tok_carol)
        report["checks"]["carol_revoked_for_origin_test"] = \
            r["status"] == "ok"
        time.sleep(POLL_A + 0.4)
        r = relayed(env_for(sid_r, ss_r, 9, "carol trying",
                            sender="user-carol"), tok_carol)
        report["checks"]["revoked_sender_denied_at_origin"] = \
            r["decision"] == "deny" and r.get("reason") == "revoked" and \
            [h["node"] for h in r.get("route", [])] == ["node-a"]
        _, inbox = netutil.request(base["recv"] + "/messages")
        report["checks"]["revoked_sender_never_delivered"] = \
            not any(m["plaintext"] == "carol trying"
                    for m in inbox["delivered"])

        # 8. backup integrity with real files
        R("/backup", backup_id="net-bak")
        R("/damage_backup", backup_id="net-bak")
        r = R("/restore_backup", backup_id="net-bak")
        report["checks"]["damaged_backup_rejected"] = \
            r["message"] == "backup_integrity_failure"
        R("/backup", backup_id="net-bak2")
        r = R("/restore_backup", backup_id="net-bak2")
        report["checks"]["good_backup_restored"] = r["restored"] is True

        # 9. log integrity at a node (real local log, real tamper)
        r = NODE("node-a", "/tamper_log", seq=1, field="actor",
                 value="attacker")
        r = NODE("node-a", "/verify_log")
        report["checks"]["node_log_tamper_detected"] = r["valid"] is False
        r = netutil.request(base["registry"] + "/verify_log")[1]
        report["checks"]["registry_log_valid"] = r["valid"] is True

        # 10. NODE-TO-NODE GOSSIP: a key rotation triggers each node
        # PROCESS to gossip an encrypted, authenticated policy-ack into
        # the NEXT node's messaging inbox (ring a->b->c->a) over the same
        # E2E machinery as user messaging: PoP token from the node's own
        # key, fresh ephemeral ML-KEM session, AEAD bound to the session.
        v_g = R("/keys/rotate", grace_seconds=GRACE)["new_version"]

        def node_ack(inbox_key, sender):
            _, inbox = netutil.request(base[inbox_key] + "/messages")
            out = []
            for m in inbox["delivered"]:
                try:
                    p = json.loads(m["plaintext"])
                except (ValueError, TypeError):
                    continue
                if p.get("type") == "policy_ack" and p.get("node") == sender:
                    out.append(p)
            return out

        time.sleep(POLL_A + 0.6)       # node-a applies + gossips
        acks = node_ack("msgr-b", "node-a")
        report["checks"]["gossip_node-a_to_node-b"] = \
            any(p["key_version"] == v_g for p in acks)
        report["measurements"]["gossip_plaintext_node-a"] = \
            acks[0] if acks else None
        time.sleep(POLL_B + 0.6)       # node-b applies + gossips
        acks = node_ack("msgr-c", "node-b")
        report["checks"]["gossip_node-b_to_node-c"] = \
            any(p["key_version"] == v_g for p in acks)
        time.sleep(POLL_C + 0.6)       # node-c applies + gossips (ring)
        acks = node_ack("msgr-a", "node-c")
        report["checks"]["gossip_node-c_to_node-a"] = \
            any(p["key_version"] == v_g for p in acks)
        for name in ("node-a", "node-b", "node-c"):
            st = NODE(name, "/status")
            report["measurements"]["gossip_log_%s" % name] = \
                (st.get("gossip_log") or [{}])[-1].get("decision")

        # 11. DIRECT endpoint E2E: keys stay in RAM only, never on disk.
        v_direct = R("/keys/current")["version"]
        sid_d, ss_d, est_d = open_session()
        report["checks"]["direct_session_ephemeral_zeroized"] = \
            est_d.get("ephemeral_sk_retained") is False
        envs = [env_for(sid_d, ss_d, 1, "msg one", version=v_direct),
                env_for(sid_d, ss_d, 2, "msg two", version=v_direct)]
        netutil.request(base["recv"] + "/message/receive", envs[1],
                        method="POST")
        res = netutil.request(base["recv"] + "/message/receive", envs[0],
                              method="POST")[1]
        report["measurements"]["direct_reorder_response"] = res
        report["checks"]["direct_reorder_delivered_in_order"] = \
            res["decision"] == "deliver" and \
            [m["plaintext"] for m in res["messages"]] == \
            ["msg one", "msg two"]
        r = netutil.request(base["recv"] + "/message/receive", envs[0],
                            method="POST")[1]
        report["checks"]["direct_duplicate_rejected"] = \
            r.get("reason") == "duplicate_replay"
        recv_dir = os.path.join(work, "messenger_recv_dir")
        on_disk = []
        for dirpath, _, files in os.walk(recv_dir):
            on_disk += files
        report["checks"]["no_session_keys_on_disk"] = \
            not any("key" in f.lower() for f in on_disk)
        _, stt = netutil.request(base["recv"] + "/session/status")
        report["checks"]["endpoint_reports_keys_in_ram"] = \
            stt["key_in_ram"] and not stt["keys_persisted_to_disk"]

        # 12. detector on real node logs (lateral movement over real logs)
        sys.path.insert(0, ROOT)
        from src.detector import evaluate_live
        node_logs = []
        for n in ("node-a", "node-b", "node-c"):
            _, l = netutil.request(base[n] + "/log")
            node_logs.extend(l["log"])
        r = evaluate_live(node_logs)
        report["measurements"]["live_alerts_from_node_logs"] = len(r["alerts"])

        report["all_checks_pass"] = all(
            v is True for k, v in report["checks"].items())
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
        if report.get("all_checks_pass"):
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("work dir kept for diagnosis: %s" % work, file=sys.stderr)

    print(json.dumps(report, indent=2))
    return 0 if report.get("all_checks_pass") else 1


if __name__ == "__main__":
    sys.exit(main())
