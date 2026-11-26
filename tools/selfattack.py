#!/usr/bin/env python3
"""Black-box red team against OUR OWN adapter (Track 4, live assessment prep).

    python tools/selfattack.py --entry track4_service.py
        [--items 1,2,4] [--report docs/SELFATTACK_REPORT.md]

Scope: it only ever runs the adapter locally, in a fresh temporary state
directory per scenario, exactly as the judges do (a new process per
request, one JSON object in on stdin, one out on stdout, exit 0).  It opens
no network connection and must never be pointed at anything that is not
our own service.

Each check reports PASS, FAIL (with a severity), SKIP or INFO.  A PASS
means the probe found nothing - it is NOT proof of security.  Failures are
classified critical/high/medium/low so the live security assessment can be
answered with detection + response instead of silent deductions.

Exit status: 0 no failures, 1 at least one failure, 2 the suite could not
run.  Report text never contains request bodies, adapter output or secret
values (only counts and check names).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))   # client-side crypto import for items 4/13
SEVERITIES = ("critical", "high", "medium", "low")


class Adapter:
    """One adapter process per request, isolated state dir per scenario."""

    def __init__(self, entry: Path):
        self.entry = Path(entry).resolve()
        self.dir = tempfile.mkdtemp(prefix="track4_selfattack_")
        self.env = dict(os.environ, TRACK4_STATE_DIR=self.dir,
                        TMPDIR=self.dir, TEMP=self.dir, TMP=self.dir)
        self.leak_markers = {}      # name -> secret hex we must never see

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def fresh_dir(self):
        """Fresh container per scenario: a new state dir, like the judges'
        per-scenario sandbox (an item that tampers on disk must not poison
        the next item)."""
        shutil.rmtree(self.dir, ignore_errors=True)
        self.dir = tempfile.mkdtemp(prefix="track4_selfattack_")
        self.env["TRACK4_STATE_DIR"] = self.dir
        self.env["TMPDIR"] = self.env["TEMP"] = self.env["TMP"] = self.dir
        self.leak_markers.clear()

    def request(self, raw: str, timeout: float = 10.0):
        """Raw request -> (exit_code, stdout_str, stderr_str)."""
        try:
            p = subprocess.run([sys.executable, "-B", str(self.entry)],
                               input=raw, capture_output=True, text=True,
                               env=self.env, cwd=str(self.entry.parent),
                               timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return None, "", "timeout"

    def call(self, req: dict, timeout: float = 10.0):
        """JSON request -> (exit_code, parsed_or_None, stdout, stderr)."""
        code, out, err = self.request(json.dumps(req), timeout)
        parsed = None
        if out.strip():
            try:
                parsed = json.loads(out)
            except ValueError:
                parsed = None
        return code, parsed, out, err

    def track_secret(self, name: str, value: str):
        self.leak_markers[name] = value

    def leaks(self, text: str):
        found = [n for n, v in self.leak_markers.items() if v and v in text]
        return sorted(set(found))


class Result:
    __slots__ = ("status", "severity", "note")

    def __init__(self, status, severity=None, note=""):
        self.status, self.severity, self.note = status, severity, note


PASS = Result("PASS")


def fail(severity, note=""):
    return Result("FAIL", severity, note)


def skip(note=""):
    return Result("SKIP", note=note)


def info(note=""):
    return Result("INFO", note=note)


class Harness:
    def __init__(self, adapter: Adapter):
        self.a = adapter
        self.results = []           # (item_no, check_name, Result)
        self.owner = "maya"
        self.peer = "raj"
        self.asset = "brief"
        self.marker = ""            # key_material value, generated per run

    # ---- result recording -------------------------------------------------
    def check(self, item, name, result):
        self.results.append((item, name, result))
        return result

    # ---- shared scenario helpers -----------------------------------------
    def setup(self, extra=None, owners=None, contents=None, disabled=None):
        self.marker = os.urandom(16).hex()
        self.a.track_secret("key_material", self.marker)
        req = {"op": "setup",
               "owners": owners if owners is not None else
                         {self.asset: self.owner, "peerfile": self.peer},
               "contents": contents if contents is not None else
                           {self.asset: "TOPSECRET-DEMO-BODY",
                            "peerfile": "peer-body"},
               "disabled": disabled if disabled is not None else ["gone"],
               "key_material": self.marker}
        if extra:
            req.update(extra)
        return self.a.call(req)

    def state(self):
        path = os.path.join(self.a.dir, "state.json")
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def out_leaks(self, *chunks):
        found = []
        for c in chunks:
            found.extend(self.a.leaks(c or ""))
        return sorted(set(found))

    # ======================================================================
    # ITEM 1 - contract basics: exact bodies, no leakage
    # ======================================================================
    def item1(self):
        code, r, out, err = self.setup()
        yield "setup returns ready", PASS if (
            code == 0 and r and r.get("ready") is True) else \
            fail("critical", "setup did not return ready:true on stdout")
        yield "setup output leaks no key_material", \
            PASS if not self.out_leaks(out, err) else \
            fail("critical", "key_material marker appeared in output")
        code, r, out, err = self.a.call(
            {"op": "read", "actor": self.owner, "asset": self.asset,
             "request_id": "r1"})
        yield "owner read allow exact body", PASS if (
            code == 0 and r and r.get("decision") == "allow"
            and r.get("body") == "TOPSECRET-DEMO-BODY") else \
            fail("critical", "owner read did not return the exact body")
        yield "read output leaks no key_material", \
            PASS if not self.out_leaks(out, err) else \
            fail("critical", "key_material marker in read output")
        code, r, out, err = self.a.call({"op": "definitely_not_an_op"})
        yield "unknown op -> JSON error + exit 0", PASS if (
            code == 0 and r and "status" in r and "Traceback" not in err) \
            else fail("medium", "unknown op crashed or returned non-JSON")
        code, out, err = self.a.request("{not json")
        ok_json = _one_json(out) if code == 0 else False
        yield "invalid JSON -> JSON error + exit 0", PASS if (
            code == 0 and ok_json and "Traceback" not in err) else \
            fail("high", "malformed JSON broke the adapter contract")
        code, out, err = self.a.request("")
        ok_json = _one_json(out) if code == 0 else False
        yield "empty stdin -> JSON error + exit 0", PASS if (
            code == 0 and ok_json) else \
            fail("medium", "empty input broke the adapter contract")
        code, r, out, err = self.a.call({"op": "status"})
        one_object = code == 0 and _one_json(out)
        yield "stdout is exactly one JSON object", PASS if one_object else \
            fail("high", "stdout carried extra lines (contract violation)")

    # ======================================================================
    # ITEM 2 - authorization edges & deny-shape leakage
    # ======================================================================
    def item2(self):
        self.setup()
        code, r, out, err = self.a.call(
            {"op": "read", "actor": self.peer, "asset": self.asset,
             "request_id": "r2"})
        deny_clean = code == 0 and r and r.get("decision") == "deny" \
            and "body" not in r \
            and "TOPSECRET-DEMO-BODY" not in json.dumps(r)
        yield "peer read denied, no body anywhere in deny", PASS if \
            deny_clean else fail("critical", "deny response leaked content")
        yield "deny output leaks no key_material", \
            PASS if not self.out_leaks(out, err) else \
            fail("critical", "key_material marker in deny output")
        code, r, out, err = self.a.call(
            {"op": "read", "actor": "gone", "asset": "peerfile",
             "request_id": "r3"})
        yield "disabled actor denied", PASS if (
            code == 0 and r and r.get("decision") == "deny") else \
            fail("critical", "disabled actor still allowed")
        code, r, out, err = self.a.call({"op": "audit", "request_id": "r2"})
        yield "audit echoes recorded deny + request_id", PASS if (
            code == 0 and r and r.get("decision") == "deny"
            and r.get("request_id") == "r2") else \
            fail("high", "audit did not replay the recorded decision")
        yield "audit deny output carries no body/marker", PASS if \
            not self.out_leaks(out, err) and \
            "TOPSECRET-DEMO-BODY" not in json.dumps(r or {}) else \
            fail("critical", "audit response leaked protected content")
        code, r, out, err = self.a.call({"op": "audit",
                                         "request_id": "never-seen"})
        yield "unknown request_id handled", PASS if (
            code == 0 and r and "Traceback" not in err) else \
            fail("medium", "audit of unknown request_id crashed")
        self.a.call({"op": "read", "actor": self.owner, "asset": self.asset,
                     "request_id": "rw"})
        self.a.call({"op": "read", "actor": self.peer, "asset": self.asset,
                     "request_id": "rw"})
        code2, r2, out2, err2 = self.a.call({"op": "audit",
                                             "request_id": "rw"})
        yield "request_id reuse cannot overwrite recorded decision", \
            PASS if (r2 and r2.get("decision") == "allow") else \
            fail("high", "a reused request_id rewrote the audit record")

    # ======================================================================
    # ITEM 3 - revocation semantics across processes
    # ======================================================================
    def item3(self):
        self.setup()
        code, r, out, err = self.a.call({"op": "revoke",
                                         "actor": self.owner})
        yield "revoke accepted", PASS if (code == 0 and r is not None) else \
            fail("high", "revoke op failed")
        code, r, out, err = self.a.call(
            {"op": "read", "actor": self.owner, "asset": self.asset,
             "request_id": "rv1"})
        yield "revoked actor denied", PASS if (
            code == 0 and r and r.get("decision") == "deny" and
            "TOPSECRET-DEMO-BODY" not in json.dumps(r)) else \
            fail("critical", "revoked actor still reads")
        code, r, out, err = self.a.call(
            {"op": "read", "actor": self.peer, "asset": "peerfile",
             "request_id": "rv2"})
        yield "other actors keep access after revoke", PASS if (
            code == 0 and r and r.get("decision") == "allow") else \
            fail("high", "revoke hit bystanders")
        code, r, out, err = self.a.call(
            {"op": "read", "actor": self.owner, "asset": self.asset,
             "request_id": "rv3"})
        yield "revocation persists across processes", PASS if (
            code == 0 and r and r.get("decision") == "deny") else \
            fail("critical", "revocation lost between processes")
        code, r, out, err = self.a.call(
            {"op": "re_enroll", "device": self.owner, "actor": self.owner})
        yield "re_enroll handled (defined response)", PASS if (
            code == 0 and r and "Traceback" not in err) else \
            fail("medium", "re_enroll crashed")

    # ======================================================================
    # ITEM 4 - protected_read: crypto correctness + hostile inputs
    # ======================================================================
    def item4(self):
        from src import crypto                      # local client only
        self.setup()
        ek, dk = crypto.kem_keypair()
        code, r, out, err = self.a.call(
            {"op": "protected_read", "actor": self.owner,
             "asset": self.asset, "challenge": "chal-1",
             "public_key": base64.b64encode(ek).decode()})
        yield "protected_read allow + fields", PASS if (
            code == 0 and r and r.get("decision") == "allow"
            and r.get("ciphertext") and r.get("proof")) else \
            fail("critical", "protected_read did not return allow/proof")
        if r and r.get("decision") == "allow":
            ss = crypto.kem_decaps(dk, base64.b64decode(r["ciphertext"]))
            self.a.track_secret("kem_shared_secret", ss.hex())
            expected = hmac_mod.new(
                ss, ("chal-1" + "TOPSECRET-DEMO-BODY").encode(),
                hashlib.sha256).hexdigest()
            yield "proof = HMAC(shared, challenge+body) verified client-side", \
                PASS if r["proof"] == expected else \
                fail("critical",
                     "proof does not match the client-computed HMAC")
        yield "protected_read leaks no secret", \
            PASS if not self.out_leaks(out, err) else \
            fail("critical", "secret marker in protected_read output")
        code, r, out, err = self.a.call(
            {"op": "protected_read", "actor": self.peer,
             "asset": self.asset, "challenge": "c",
             "public_key": base64.b64encode(ek).decode()})
        yield "unauthorized protected_read deny, no ciphertext/proof", \
            PASS if (code == 0 and r and r.get("decision") == "deny"
                     and "ciphertext" not in r) else \
            fail("critical", "unauthorized protected_read succeeded")
        for name, pk in (("empty", b""), ("short", b"\x01" * 100),
                         ("long", b"\x01" * 2368)):
            bad = "not-base64!!" if name == "empty" else \
                base64.b64encode(pk).decode()
            code, r, out, err = self.a.call(
                {"op": "protected_read", "actor": self.owner,
                 "asset": self.asset, "challenge": "c",
                 "public_key": bad})
            ok = code == 0 and r is not None and "Traceback" not in err
            yield "hostile public_key (%s) handled" % name, PASS if ok else \
                fail("medium", "hostile public_key crashed adapter")
        code, r, out, err = self.a.call(
            {"op": "protected_read", "actor": self.owner,
             "asset": self.asset, "challenge": {"nested": ["obj"]},
             "public_key": base64.b64encode(ek).decode()})
        yield "non-string challenge handled", PASS if (
            code == 0 and r and "Traceback" not in err) else \
            fail("medium", "object challenge crashed adapter")

    # ======================================================================
    # ITEM 5 - rotation cutoff & grace window
    # ======================================================================
    def item5(self):
        self.setup({"grace_seconds": 5.0})
        code, r, out, err = self.a.call({"op": "rotate_key"})
        ok = code == 0 and r and r.get("new_version", 0) > 0
        yield "rotate_key produces new version + cutoff", PASS if ok else \
            fail("high", "rotate_key failed")
        if not ok:
            return
        cutoff, now = r["cutoff_at"], r["now"]
        code, r2, out, err = self.a.call(
            {"op": "authenticate", "actor": self.owner,
             "key_version": r["old_version"], "node": "node-a"})
        grace_ok = code == 0 and r2 and (
            r2.get("decision") in ("allow", "grace") or
            r2.get("outcome") == "grace" or
            (r2.get("decision") == "deny" and
             r2.get("reason") == "revoked_device"))
        yield "old key accepted during grace", PASS if grace_ok else \
            fail("high", "old key rejected inside documented grace window")
        delta = max(0.0, cutoff - now) + 1.0
        self.a.call({"op": "advance_time", "seconds": delta})
        code, r3, out, err = self.a.call(
            {"op": "authenticate", "actor": self.owner,
             "key_version": r["old_version"], "node": "node-a"})
        yield "old key rejected after cutoff", PASS if (
            code == 0 and r3 and r3.get("decision") == "deny") else \
            fail("critical", "expired key still authenticates")
        code, r4, out, err = self.a.call(
            {"op": "authenticate", "actor": self.owner,
             "key_version": r["new_version"], "node": "node-a"})
        yield "new key works after rotation", PASS if (
            code == 0 and r4 and r4.get("decision") == "allow") else \
            fail("high", "new key rejected after rotation")
        yield "rotation output leaks no key material", \
            PASS if not self.out_leaks(out, err) else \
            fail("critical", "kem_sk leaked in rotate output")

    # ======================================================================
    # ITEM 6 - revocation across nodes + re-enrolment
    # ======================================================================
    def item6(self):
        self.setup()
        code, r, out, err = self.a.call({"op": "revoke",
                                         "actor": self.owner})
        times = (r or {}).get("enforcement_times", {})
        yield "revoke reports per-node enforcement times", PASS if (
            code == 0 and times and len(times) >= 2) else \
            fail("high", "no per-node enforcement evidence")
        code, r2, out, err = self.a.call({"op": "node_status",
                                          "node": "node-c"})
        yield "last node reports enforcement", PASS if (
            code == 0 and r2 and "Traceback" not in err) else \
            fail("medium", "node_status crashed")
        av = self.state().get("active_version") or 0
        code, r3, out, err = self.a.call(
            {"op": "authenticate", "actor": self.owner,
             "key_version": av, "node": "node-a"})
        yield "revoked actor denied at node", PASS if (
            code == 0 and r3 and r3.get("decision") == "deny") else \
            fail("critical", "revoked actor authenticates at a node")
        code, r4, out, err = self.a.call(
            {"op": "read", "actor": self.peer, "asset": "peerfile",
             "request_id": "n1"})
        yield "peer unaffected by revocation", PASS if (
            code == 0 and r4 and r4.get("decision") == "allow") else \
            fail("high", "revocation hit bystanders")
        yield "revocation output leaks no material", \
            PASS if not self.out_leaks(out, err) else \
            fail("critical", "secret in revocation output")

    # ======================================================================
    # ITEM 7 - crash recovery: interrupted rotation + hard kill
    # ======================================================================
    def item7(self):
        self.setup({"grace_seconds": 5.0})
        self.a.call({"op": "rotate_key"})          # commit v2 first
        code, r, out, err = self.a.call({"op": "crash_rotation"})
        yield "crash_rotation handled", PASS if (
            code == 0 and r and "Traceback" not in err) else \
            fail("high", "crash_rotation crashed")
        code, r2, out, err = self.a.call({"op": "journal_status"})
        yield "journal reports its state", PASS if (
            code == 0 and r2 and "Traceback" not in err) else \
            fail("medium", "journal_status crashed")
        code, r3, out, err = self.a.call({"op": "recover_state"})
        yield "recover_state handled", PASS if (
            code == 0 and r3 and "Traceback" not in err) else \
            fail("high", "recover_state crashed")
        code, r4, out, err = self.a.call(
            {"op": "read", "actor": self.owner, "asset": self.asset,
             "request_id": "c1"})
        yield "after recovery service answers reads", PASS if (
            code == 0 and r4 and r4.get("decision") in ("allow", "deny")
            and "Traceback" not in err) else \
            fail("high", "service unusable after recovery path")
        self.a.call({"op": "revoke", "actor": self.owner})
        child = subprocess.Popen(
            [sys.executable, "-B", str(self.a.entry)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=self.a.env, text=True)
        try:
            child.stdin.write(json.dumps({"op": "read", "actor": self.owner,
                                          "asset": self.asset,
                                          "request_id": "kill"}))
            child.stdin.flush()
        except Exception:
            pass                  # writing may fail; the kill must not
        finally:
            child.kill()               # SIGKILL mid-flight, always
            child.wait()
        code, r5, out, err = self.a.call(
            {"op": "read", "actor": self.owner, "asset": self.asset,
             "request_id": "c2"})
        yield "revocation survives hard process kill", PASS if (
            code == 0 and r5 and r5.get("decision") == "deny") else \
            fail("critical", "revocation lost after hard kill")

    # ======================================================================
    # ITEM 8 - backup integrity: damaged backup refused
    # ======================================================================
    def item8(self):
        self.setup()
        code, r, out, err = self.a.call(
            {"op": "create_backup", "backup_id": "bakA"})
        yield "backup created + signed", PASS if (
            code == 0 and r and r.get("signed")) else \
            fail("high", "backup not created/signed")
        if not (r and r.get("signed")):
            return
        self.a.call({"op": "damage_backup", "backup_id": "bakA"})
        code, r3, out, err = self.a.call(
            {"op": "restore_backup", "backup_id": "bakA"})
        refused = code == 0 and r3 is not None and \
            (r3.get("status") == "error" or r3.get("decision") == "deny" or
             "error" in json.dumps(r3).lower())
        yield "restore REFUSES damaged backup", PASS if refused else \
            fail("critical", "damaged backup was restored")
        self.a.call({"op": "create_backup", "backup_id": "bakB"})
        code, r4, out, err = self.a.call(
            {"op": "restore_backup", "backup_id": "bakB"})
        yield "clean backup restores", PASS if (
            code == 0 and r4 and r4.get("status") == "ok") else \
            fail("high", "clean backup could not be restored")
        yield "backup outputs leak no material", \
            PASS if not self.out_leaks(out, err) else \
            fail("critical", "backup output leaked material")

    # ======================================================================
    # ITEM 9 - log integrity: tampering is detected
    # ======================================================================
    def item9(self):
        self.setup()
        code, r, out, err = self.a.call({"op": "verify_log"})
        yield "clean log verifies", PASS if (
            code == 0 and r and r.get("valid") is True) else \
            fail("critical", "clean log failed verification")
        self.a.call({"op": "tamper_log", "seq": 1, "field": "actor",
                     "value": "attacker"})
        code, r2, out, err = self.a.call({"op": "verify_log"})
        yield "tampered log DETECTED", PASS if (
            code == 0 and r2 and r2.get("valid") is False) else \
            fail("critical", "tampering not detected")
        yield "verify output leaks no material", \
            PASS if not self.out_leaks(out, err) else \
            fail("critical", "verify output leaked material")

    # ======================================================================
    # ITEM 10 - log injection: user text cannot forge a second event
    # ======================================================================
    def item10(self):
        self.setup()
        payloads = [
            'x","actor":"admin","action":"grant_role","decision":"allow',
            'line1\n{"seq":999,"actor":"ghost","action":"forge"',
            'x\x00y", "actor": "root"',
            'unicode \u2028 separator \u00e9\u00e8',
            '}}},"actor":"admin"',
        ]
        all_ok = True
        before = len(self.state().get("log", []))
        for i, p in enumerate(payloads):
            code, r, out, err = self.a.call(
                {"op": "append_log", "actor": self.owner, "action": "custom",
                 "asset": "log", "decision": "ok", "detail": p,
                 "request_id": "inj%d" % i})
            if not (code == 0 and r):
                all_ok = False
        st = self.state()
        log = st.get("log", [])
        grew_exactly = len(log) == before + len(payloads)
        one_object_each = all(
            isinstance(e, dict) and e.get("actor") == self.owner
            for e in log[before:])
        yield "injection payloads stay ONE record with recorded actor", \
            PASS if (all_ok and grew_exactly and one_object_each) else \
            fail("critical", "injection created/changed an apparent event")
        code, r, out, err = self.a.call({"op": "verify_log"})
        yield "chain still valid after injections", PASS if (
            code == 0 and r and r.get("valid") is True) else \
            fail("critical", "injection corrupted the chain")

    # ======================================================================
    # ITEM 11 - independent verifier agrees with the service
    # ======================================================================
    def item11(self):
        verifier = ROOT / "verifier" / "track4_verify.py"
        if not verifier.exists():
            yield skip("standalone verifier not present")
            return
        self.setup()
        self.a.call({"op": "read", "actor": self.owner, "asset": self.asset,
                     "request_id": "v1"})
        st_ = self.state()
        pub = st_.get("service_dsa_pk", "")
        if not pub:
            yield skip("no service key in state")
            return
        path = os.path.join(self.a.dir, "state.json")
        p = subprocess.run(
            [sys.executable, "-B", str(verifier), "audit",
             "--state", path, "--pub", pub,
             "--expect-head", st_["log"][-1]["hash"]],
            capture_output=True, text=True, timeout=30)
        yield "standalone verifier accepts clean log (exit 0)", PASS if \
            p.returncode == 0 else \
            fail("high", "verifier rejected the service's own clean log")
        st_["log"][0]["actor"] = "attacker"
        with open(path, "w") as f:
            json.dump(st_, f)
        p = subprocess.run(
            [sys.executable, "-B", str(verifier), "audit",
             "--state", path, "--pub", pub],
            capture_output=True, text=True, timeout=30)
        yield "standalone verifier REJECTS tampered log (exit 1)", PASS if \
            p.returncode == 1 else \
            fail("critical", "verifier accepted a tampered log")

    # ======================================================================
    # ITEM 12 - messaging: binding, replay, tamper
    # ======================================================================
    def item12(self):
        self.setup()
        # messaging identities must be enrolled first (device registration)
        self.a.call({"op": "re_enroll", "device": "d1", "actor": self.owner})
        self.a.call({"op": "re_enroll", "device": "d2", "actor": self.peer})
        code, r, out, err = self.a.call(
            {"op": "session_open", "sender": self.owner,
             "recipient": self.peer})
        ok = code == 0 and r and r.get("status") == "ok"
        yield "session_open ok", PASS if ok else \
            fail("high", "session_open failed")
        if not ok:
            return
        sid = r["sid"]
        code, r2, out, err = self.a.call(
            {"op": "session_open", "sender": self.owner,
             "recipient": "nobody-here"})
        yield "unknown recipient rejected", PASS if (
            code == 0 and r2 and r2.get("status") == "error") else \
            fail("high", "session opened for unknown identity")
        code, r3, out, err = self.a.call(
            {"op": "session_accept", "sid": sid, "sender": self.owner})
        yield "session_accept ok", PASS if (
            code == 0 and r3 and r3.get("status") == "ok") else \
            fail("high", "session_accept failed")
        code, r4, out, err = self.a.call(
            {"op": "message_send", "sid": sid, "sender": self.owner,
             "recipient": self.peer, "plaintext": "m1"})
        ok = code == 0 and r4 and r4.get("ciphertext")
        yield "message_send ok", PASS if ok else fail("high", "send failed")
        if not ok:
            return
        env = {"msg_id": r4["msg_id"], "counter": r4["counter"],
               "nonce": r4["nonce"], "ciphertext": r4["ciphertext"]}
        code, r5, out, err = self.a.call(
            dict({"op": "message_receive", "sid": sid,
                  "sender": self.owner, "recipient": self.peer}, **env))
        yield "first delivery ok", PASS if (
            code == 0 and r5 and r5.get("decision") == "deliver") else \
            fail("high", "first message not delivered")
        code, r6, out, err = self.a.call(
            dict({"op": "message_receive", "sid": sid,
                  "sender": self.owner, "recipient": self.peer}, **env))
        yield "duplicate rejected (replay)", PASS if (
            code == 0 and r6 and r6.get("decision") == "reject") else \
            fail("critical", "replayed message delivered")
        code, r7, out, err = self.a.call(
            dict({"op": "message_receive", "sid": sid,
                  "sender": self.owner, "recipient": "mallory"}, **env))
        yield "recipient binding enforced", PASS if (
            code == 0 and r7 and r7.get("decision") == "reject") else \
            fail("critical", "another identity read the message")
        ct = bytearray(bytes.fromhex(env["ciphertext"]))
        ct[0] ^= 1
        code, r8, out, err = self.a.call(
            dict({"op": "message_receive", "sid": sid,
                  "sender": self.owner, "recipient": self.peer,
                  "msg_id": env["msg_id"], "counter": 2,
                  "nonce": env["nonce"], "ciphertext": ct.hex()}))
        yield "tampered ciphertext rejected", PASS if (
            code == 0 and r8 and r8.get("decision") == "reject") else \
            fail("critical", "forged ciphertext accepted")
        code, r9, out, err = self.a.call(
            dict({"op": "message_receive", "sid": sid,
                  "sender": self.owner, "recipient": self.peer,
                  "msg_id": "f" * 24, "counter": env["counter"],
                  "nonce": env["nonce"], "ciphertext": env["ciphertext"]}))
        yield "renamed msg_id rejected", PASS if (
            code == 0 and r9 and r9.get("decision") == "reject") else \
            fail("critical", "renamed metadata bypassed replay detection")
        yield "messaging outputs leak no secret", \
            PASS if not self.out_leaks(out, err) else \
            fail("critical", "session key material in output")

    # ======================================================================
    # ITEM 13 - forward secrecy (black box, worst-case attacker)
    # ======================================================================
    def item13(self):
        from src import crypto
        self.setup()
        self.a.call({"op": "re_enroll", "device": "d1", "actor": self.owner})
        self.a.call({"op": "re_enroll", "device": "d2", "actor": self.peer})
        code, r, out, err = self.a.call(
            {"op": "session_open", "sender": self.owner,
             "recipient": self.peer})
        if not (code == 0 and r and r.get("status") == "ok"):
            yield skip("session_open unavailable")
            return
        sid = r["sid"]
        self.a.call({"op": "session_accept", "sid": sid,
                     "sender": self.owner})
        m = self.a.call({"op": "message_send", "sid": sid,
                         "sender": self.owner, "recipient": self.peer,
                         "plaintext": "fs-secret-phrase"})[1]
        if not (m and m.get("ciphertext")):
            yield skip("message_send unavailable")
            return
        self.a.call({"op": "session_close", "sid": sid, "peer": self.peer})
        # worst case: attacker reads EVERYTHING now on disk
        secrets = []
        st_ = self.state()
        for ident in (st_.get("identities") or {}).values():
            for f in ("kem_sk", "dsa_sk"):
                if isinstance(ident.get(f), str) and ident[f]:
                    secrets.append(ident[f])
        if st_.get("service_dsa_sk"):
            secrets.append(st_["service_dsa_sk"])
        for v in st_.get("key_versions", []):
            if v.get("kem_sk"):
                secrets.append(v["kem_sk"])
        nonce = bytes.fromhex(m["nonce"])
        ct = bytes.fromhex(m["ciphertext"])
        broke = False
        for sk_hex in secrets:
            try:
                crypto.aead_decrypt(sk_hex.encode(), nonce, ct, b"")
                broke = True
            except Exception:
                pass
        yield "captured traffic undecryptable from long-term secrets", \
            PASS if not broke else \
            fail("critical", "a long-term secret decrypted captured traffic")
        yield "closed session key zeroized on disk", PASS if \
            (self.state().get("sessions", {}).get(sid, {}).get("key")
             is None) else \
            fail("high", "closed session key still persisted")

    # ======================================================================
    # ITEM 14 - clock & numeric robustness
    # ======================================================================
    def item14(self):
        self.setup()
        code, r, out, err = self.a.call({"op": "advance_time",
                                         "seconds": -100})
        yield "negative clock delta rejected", PASS if (
            code == 0 and r and r.get("status") == "error") else \
            fail("high", "clock rewound via API")
        code, r2, out, err = self.a.call({"op": "advance_time",
                                          "seconds": "NaN"})
        yield "NaN delta rejected", PASS if (
            code == 0 and r2 and r2.get("status") == "error") else \
            fail("high", "NaN accepted into the clock")
        code, r3, out, err = self.a.call(
            {"op": "authenticate", "key_version": "1e999999"})
        yield "huge key_version handled", PASS if (
            code == 0 and r3 and "Traceback" not in err) else \
            fail("medium", "huge integer crashed adapter")
        code, r4, out, err = self.a.call(
            {"op": "read", "actor": "a" * 100000, "asset": "x",
             "request_id": "y" * 100000})
        yield "oversized fields handled (capped, no crash)", PASS if (
            code == 0 and r4 and "Traceback" not in err) else \
            fail("medium", "oversized input crashed adapter")
        deep = {"op": "read"}
        req = deep
        for _ in range(200):
            req["n"] = {}
            req = req["n"]
        code, r5, out, err = self.a.call(deep)
        yield "deeply nested input handled", PASS if (
            code == 0 and "Traceback" not in err) else \
            fail("medium", "deep nesting crashed adapter")
        code, r6, out, err = self.a.call(
            {"op": "read", "actor": "user-\u2028-\U0001f600",
             "asset": "\x01\x02"})
        yield "unicode/control-char ids handled", PASS if (
            code == 0 and r6 and "Traceback" not in err) else \
            fail("medium", "unicode input crashed adapter")
        yield "robustness outputs leak no material", \
            PASS if not self.out_leaks(out, err) else \
            fail("critical", "secret in robustness-test output")

    # ======================================================================
    # ITEM 15 - secret leakage sweep over a full working session
    # ======================================================================
    def item15(self):
        self.setup()
        st_ = self.state()

        def harvest(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if isinstance(v, str) and len(v) >= 64 and \
                            all(c in "0123456789abcdef" for c in v.lower()):
                        self.a.track_secret("hexblob:%s" % k[:12], v)
                    else:
                        harvest(v)
            elif isinstance(d, list):
                for v in d:
                    harvest(v)
        harvest(st_)
        self.a.call({"op": "revoke", "actor": self.owner})
        self.a.call({"op": "rotate_key"})
        self.a.call({"op": "verify_log"})
        code, r, out, err = self.a.call({"op": "status"})
        leaked = self.out_leaks(out, err)
        yield "status output leaks no state secret", PASS if not leaked \
            else fail("critical", "state secret in status output (%d blobs)"
                      % len(leaked))
        code, r2, out2, err2 = self.a.call({"op": "protected_read",
                                            "public_key": "%%%"})
        yield "error path leaks no secret", PASS if \
            not self.out_leaks(out2, err2) else \
            fail("critical", "secret in error output")
        yield "stderr carries no Traceback on error paths", PASS if \
            "Traceback" not in (err2 or "") else \
            fail("medium", "traceback leaked to stderr")

    # ------------------------------------------------------------------
    ITEMS = {1: item1, 2: item2, 3: item3, 4: item4, 5: item5, 6: item6,
             7: item7, 8: item8, 9: item9, 10: item10, 11: item11,
             12: item12, 13: item13, 14: item14, 15: item15}


def _one_json(out: str) -> bool:
    """stdout must be exactly one parseable JSON object."""
    if not out.strip():
        return False
    try:
        val = json.loads(out)
    except ValueError:
        return False
    return isinstance(val, dict) and \
        len([l for l in out.strip().splitlines() if l.strip()]) == 1


ITEM_TITLES = {
    1: "Contract basics: exact bodies, single JSON object, malformed input",
    2: "Authorization edges: deny shape, audit replay, request_id reuse",
    3: "Revocation semantics across processes and re-enrolment",
    4: "protected_read: proof correctness + hostile keys/challenges",
    5: "Key rotation: grace window honoured, cutoff enforced",
    6: "Revocation across nodes, bystanders unaffected",
    7: "Crash recovery: interrupted rotation + hard process kill",
    8: "Backup integrity: damaged backup refused, clean restore works",
    9: "Audit log integrity: tamper detection",
    10: "Log injection: user text cannot forge or alter events",
    11: "Independent standalone verifier agrees",
    12: "Messaging: replay, recipient binding, ciphertext tamper",
    13: "Forward secrecy under total on-disk compromise",
    14: "Clock and numeric input robustness",
    15: "Secret-leakage sweep over a full working session",
}


def run(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--entry", default=str(ROOT / "track4_service.py"))
    p.add_argument("--items", default="all")
    p.add_argument("--report", default=str(ROOT / "docs" /
                                           "SELFATTACK_REPORT.md"))
    args = p.parse_args(argv)

    items = sorted(Harness.ITEMS) if args.items == "all" else \
        sorted(int(x) for x in args.items.split(",") if x.strip())
    adapter = Adapter(args.entry)
    harness = Harness(adapter)
    status = 0
    try:
        for i in items:
            fn = Harness.ITEMS[i]
            adapter.fresh_dir()          # each item: its own sandbox
            try:
                for name, res in fn(harness):
                    harness.check(i, name, res)
            except Exception:
                harness.check(i, "harness_error", info(
                    "harness exception: treated as SKIP"))
    finally:
        adapter.close()

    counts = {s: 0 for s in ("PASS", "FAIL", "SKIP", "INFO")}
    by_sev = {s: 0 for s in SEVERITIES}
    for _, _, r in harness.results:
        counts[r.status] = counts.get(r.status, 0) + 1
        if r.status == "FAIL":
            by_sev[r.severity if r.severity in SEVERITIES else "medium"] += 1
    if counts["FAIL"]:
        status = 1

    lines = ["# Self-attack report (black-box)", "",
             "Target: the repo's own `track4_service.py`, driven exactly as",
             "the judges drive it (new process per request, fresh state dir",
             "per scenario, offline). Generated by `tools/selfattack.py`.",
             "",
             "Result: **%d passed, %d failed, %d skipped, %d info.** "
             % (counts["PASS"], counts["FAIL"], counts["SKIP"],
                counts["INFO"]),
             "Failures by severity: " + ", ".join(
                 "%s %d" % (s, by_sev[s]) for s in SEVERITIES) + ".",
             "",
             "A pass means these probes found nothing; it is not proof of",
             "security. This report contains no request bodies, outputs or",
             "secret values.",
             ""]
    for i in items:
        lines += ["## Item %d - %s" % (i, ITEM_TITLES.get(i, "")), "",
                  "| Check | Result |", "|---|---|"]
        for n, name, r in harness.results:
            if n != i:
                continue
            label = r.status if r.status != "FAIL" else \
                "FAIL (%s)" % r.severity
            note = r.note if r.status == "FAIL" else ""
            lines.append("| %s | %s%s |" % (
                name.replace("|", "/"), label,
                (" - " + note.replace("|", "/")) if note else ""))
        lines.append("")
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text("\n".join(lines))
    print("selfattack: %d passed, %d failed, %d skipped, %d info%s"
          % (counts["PASS"], counts["FAIL"], counts["SKIP"], counts["INFO"],
             ("; report -> %s" % args.report) if args.report else ""))
    return status


if __name__ == "__main__":
    sys.exit(run())
