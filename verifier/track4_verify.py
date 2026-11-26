#!/usr/bin/env python3
"""Standalone verifier for Track 4 evidence. Imports NOTHING from src/.

It needs only the pinned `pqcrypto` package (for ML-DSA-65 checks) and the
standard library. It reads files, never writes, never needs a private key,
and re-implements every format rule here instead of calling the service's
own checker - so a bug in the service's checker cannot hide a bad log.

    python verifier/track4_verify.py audit  --state STATE.json --pub HEX [--expect-head SHA256]
    python verifier/track4_verify.py journal --dir  STATE_DIR --pub HEX
    python verifier/track4_verify.py state  --state STATE.json
    python verifier/track4_verify.py backup --file backups/ID.json --pub HEX

What it proves:
* audit  - the log is an unbroken, correctly signed hash chain; with
  --expect-head, that it ends exactly where you independently recorded it.
* journal - every durable journal record is signed by the service key.
* state  - the state file's integrity manifest matches its contents.
* backup - the manifest is signed by the service and the payload matches
  its recorded SHA-256; the embedded audit chain is re-verified.

Exit codes: 0 = verified AND completeness established; 1 = verification
failed (first failing check printed); 2 = everything verified but
completeness could NOT be established (audit without --expect-head).
A script that tests only the exit code is therefore never told OK about a
possibly truncated log.

What it does NOT prove: that the service made the right decisions, or that
nothing newer was removed unless you give it a head/counter you recorded
elsewhere.
"""

import argparse
import hashlib
import json
import os
import sys

from pqcrypto.sign import ml_dsa_65

GENESIS = "0" * 64
CORE_FIELDS = ("seq", "ts", "actor", "action", "asset", "decision",
               "request_id", "detail", "prev_hash")


def canonical(obj) -> bytes:
    """Same serialization the service uses, re-implemented independently."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mldsa_verify(pk_hex: str, msg: bytes, sig_hex: str) -> bool:
    try:
        result = ml_dsa_65.verify(bytes.fromhex(pk_hex), msg,
                                  bytes.fromhex(sig_hex))
    except Exception:
        return False
    return result is None or result is True


def load_state(path):
    with open(path) as f:
        return json.load(f)


def fail(msg):
    print("FAIL %s" % msg)
    return 1


def ok(msg):
    print("OK   %s" % msg)
    return 0


def verify_audit(entries, pk_hex):
    """Returns (True, None) or (False, reason_with_seq)."""
    prev = GENESIS
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return False, "entry_%d_not_an_object" % (i + 1)
        try:
            core = {k: entry[k] for k in CORE_FIELDS}
        except KeyError as exc:
            return False, "entry_missing_field_%s_seq_%s" % (
                exc.args[0], entry.get("seq", i + 1))
        if entry.get("prev_hash") != prev or entry.get("seq") != i + 1:
            return False, "chain_break_at_seq_%s" % entry.get("seq", i + 1)
        digest = sha256_hex(canonical(core))
        if entry.get("hash") != digest:
            return False, "hash_mismatch_at_seq_%s" % entry.get("seq", i + 1)
        if entry.get("unsigned"):
            return False, ("unsigned_entry_at_seq_%s (pre-setup entries are "
                           "not covered by the service key)"
                           % entry.get("seq", i + 1))
        if not mldsa_verify(pk_hex, digest.encode(),
                            entry.get("signature", "")):
            return False, "bad_signature_at_seq_%s" % entry.get("seq", i + 1)
        prev = digest
    return True, prev


def cmd_audit(args):
    try:
        state = load_state(args.state)
    except (OSError, ValueError) as exc:
        return fail("state unreadable (%s)" % type(exc).__name__)
    entries = state.get("log", [])
    if not isinstance(entries, list):
        return fail("log is not a list")
    ok_, res = verify_audit(entries, args.pub)
    if not ok_:
        return fail(res)
    if not entries:
        return fail("log is empty")
    if not args.expect_head:
        print("OK   audit chain verified: %d signed entries, head %s"
              % (len(entries), res))
        print("NOTE completeness NOT established: pass --expect-head "
              "recorded out of band to prove nothing newer was removed")
        return 2
    if args.expect_head != res:
        return fail("head mismatch: recorded %s, log ends %s"
                    % (args.expect_head, res))
    return ok("audit chain verified, %d signed entries, head matches the "
              "independently recorded value %s" % (len(entries), res))


def cmd_journal(args):
    path = os.path.join(args.dir, "journal.jsonl")
    if not os.path.exists(path):
        return fail("no journal at %s" % path)
    n_ok = n_bad = 0
    first_bad = None
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                n_bad += 1
                if first_bad is None:
                    first_bad = "line_%d_not_json" % lineno
                continue
            sig = rec.get("journal_sig")
            if not sig:
                n_bad += 1
                if first_bad is None:
                    first_bad = "line_%d_unsigned" % lineno
                continue
            core = {k: v for k, v in rec.items() if k != "journal_sig"}
            if not mldsa_verify(args.pub, canonical(core), sig):
                n_bad += 1
                if first_bad is None:
                    first_bad = "line_%d_bad_signature" % lineno
            else:
                n_ok += 1
    if n_bad:
        return fail("%s (+%d further bad records)" % (first_bad, n_bad - 1))
    if n_ok == 0:
        return fail("journal is empty")
    if not args.expect_records or args.expect_records < 0:
        print("OK   journal verified: %d signed records" % n_ok)
        print("NOTE completeness NOT established: pass --expect-records N "
              "recorded out of band to prove nothing was removed")
        return 2
    if n_ok < args.expect_records:
        return fail("record count %d < independently recorded %d"
                    % (n_ok, args.expect_records))
    return ok("journal verified: %d signed records, >= expected %d"
              % (n_ok, args.expect_records))


def cmd_state(args):
    try:
        data = load_state(args.state)
    except (OSError, ValueError) as exc:
        return fail("state unreadable (%s)" % type(exc).__name__)
    stored = data.pop("state_hash", None)
    if stored is None:
        return fail("state manifest (state_hash) MISSING - the file was "
                    "modified or produced by a tampered service")
    digest = sha256_hex(canonical(data))
    if stored != digest:
        return fail("state manifest mismatch: contents were altered")
    entries = data.get("log", [])
    return ok("state manifest verified over %d top-level keys, %d audit "
              "entries; note this proves CONTENT integrity only - run the "
              "'audit' command with --pub to verify the log signatures"
              % (len(data), len(entries)))


def cmd_backup(args):
    try:
        with open(args.file) as f:
            blob = json.load(f)
    except (OSError, ValueError) as exc:
        return fail("backup unreadable (%s)" % type(exc).__name__)
    manifest = blob.get("manifest")
    payload = blob.get("payload")
    signature = blob.get("signature")
    if not isinstance(manifest, dict) or payload is None or not signature:
        return fail("backup blob missing manifest/payload/signature")
    if not mldsa_verify(args.pub, canonical(manifest), signature):
        return fail("backup manifest signature invalid")
    if manifest.get("payload_sha256") != sha256_hex(
            canonical(payload) if not isinstance(payload, str) else
            payload.encode()):
        return fail("backup payload hash mismatch - payload was modified "
                    "after signing")
    # The embedded audit chain is re-verified inside the payload.
    try:
        core = (json.loads(payload) if isinstance(payload, str)
                else payload)
    except ValueError:
        return fail("backup payload is not JSON")
    entries = core.get("log", [])
    chain_ok, res = verify_audit(entries, manifest.get("service_dsa_pk", ""))
    if not chain_ok:
        return fail("backup's embedded audit chain broken: %s" % res)
    return ok("backup verified: manifest signed by the service, payload "
              "matches its hash, embedded audit chain valid (%d entries)"
              % len(entries))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="verify the audit hash chain + signatures")
    a.add_argument("--state", required=True, help="path to state.json")
    a.add_argument("--pub", required=True, help="service ML-DSA public key, hex")
    a.add_argument("--expect-head", help="chain head you recorded out of band")

    j = sub.add_parser("journal", help="verify journal.jsonl record signatures")
    j.add_argument("--dir", required=True, help="state directory")
    j.add_argument("--pub", required=True)
    j.add_argument("--expect-records", type=int, default=-1,
                   help="minimum record count recorded out of band")

    s = sub.add_parser("state", help="verify the state integrity manifest")
    s.add_argument("--state", required=True)

    b = sub.add_parser("backup", help="verify a signed backup file")
    b.add_argument("--file", required=True)
    b.add_argument("--pub", required=True)

    args = p.parse_args(argv)
    try:
        if args.cmd == "audit":
            return cmd_audit(args)
        if args.cmd == "journal":
            return cmd_journal(args)
        if args.cmd == "state":
            return cmd_state(args)
        if args.cmd == "backup":
            return cmd_backup(args)
    except Exception as exc:               # never leak a traceback to a
        return fail("verifier error (%s)" % type(exc).__name__)  # report
    return 1


if __name__ == "__main__":
    sys.exit(main())
