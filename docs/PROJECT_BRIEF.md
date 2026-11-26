# Project Brief — Track 4 "Trust, but verify"

*(2-page brief; see also `docs/THREAT_MODEL.md` for the one-page threat model.)*

## USP

**Recovery-first post-quantum key lifecycle with evidence you can check.**
Every disruptive event in the system — rotation, revocation, crash, damaged
backup, tampered log, stolen device — is not only handled but *measured and
reportable*: the time until the last node enforces a revocation, the exact
committed key version after a crash, the failing hash in a damaged backup,
the sequence number of the first bad audit entry, and F1 / median
time-to-alert / false-alerts-per-1000 for the detector on labelled logs.
Operators don't have to trust the prototype; the prototype reports why it
should be trusted.

Everything is post-quantum from vetted libraries (ML-KEM-768, ML-DSA-65,
HKDF-SHA256, AES-256-GCM) — no custom primitives, no AI/ML in detection
(fully explainable rules), no hard-coded secrets.

## System architecture

```
                ┌──────────────────────────────────────────────────┐
   JSON req ──▶ │ track4_service.py (stdin/stdout adapter)         │
                └───────────────┬──────────────────────────────────┘
                                ▼
                ┌──────────────────────────────────────────────────┐
                │ src/dispatch.py — op registry (single entry)     │
                └──┬─────────┬──────────┬───────────┬──────────────┘
                   ▼         ▼          ▼           ▼
             src/keys   src/access  src/recovery  src/messaging
             rotation   identity    journal       ephemeral-KEM
             cutoff     decisions   backups       sessions
             revocation             crash         replay/reorder
                   └────┬─────┴──────────┬──┴───────────────┘
                        ▼                ▼
                  src/audit.py      src/detector.py
                  hash-chain +      rules over labelled
                  ML-DSA-signed     events & live log
                  audit log         F1 / TTA / FP-per-1000
                        └───────┬───────┘
                                ▼
                  src/state.py — atomic state writes,
                  durable fsync journal, simulated clock
```

**Trust flow.** Every mutating op writes a structured entry to the signed,
hash-chained audit log. Every decision carries explicit reasons. Rotations
are journaled before they commit; revocations bump a monotonic epoch; nodes
enforce versions and epochs on their own real poll schedules (networked
mode) or against the simulated clock (embedded mode). Backups are
ML-DSA-signed manifests over hashed payloads, stored outside the live state
file.

## Objective checklist (verified by `tests/test_objectives.py`)

1. **Key rotation** — new version per rotation; old version honored until a
   documented cutoff (grace 30 s simulated); every node rejects old keys
   after cutoff; authorized transfers continue inside the window.
2. **Revocation across nodes** — measured per-node enforcement (node-a 0 s,
   node-b 2 s → last node at +2 s); owner re-enrols; others unaffected.
3. **Crash recovery** — journal replay to last commit; uncommitted rotations
   discarded; revocations persist; data stays available; total disk loss
   falls back to signed backups (reported honestly).
4. **Backup integrity** — signature + hash verified before anything loads;
   damaged backups reported and refused.
5. **Log integrity** — injection-proof structured entries; ML-DSA
   signatures; `verify_log` reports the first bad entry and why.
6. **Routine vs suspicious** — F1 **1.0**, median time-to-alert **1.2 s**,
   **0** false alerts per 1,000 benign events on the labelled sandbox log.
7. **Lateral movement** — unknown service-edge bursts flagged even with
   valid credentials; each alert names identity, services, events, rule/path.
8. **Clock differences** — offsets ±60 s normalized; inversions within 10 s
   annotated; beyond that flagged `order_uncertain`.
9. **Replay + recipient binding** — AAD binds recipient/session/counter;
   duplicates and modified bindings rejected.
10. **Forward secrecy** — per-session ephemeral ML-KEM keys, zeroized at
    accept; session keys zeroized at close.
11. **Delivery under loss/reordering** — in-order delivery across gaps ≤ 8;
    failures reported; invalid messages discarded.
12. **Session resumption** — HMAC-bound to the authenticated peer; key
    ratchets on resume; same sid with a different identity is rejected.

## Performance & overhead (measured)

- 29-test suite (23 objective + 6 real-socket integration): ~5.7 s
  end-to-end.
- ML-KEM-768 keygen+encaps+decaps per session: ~1 ms; ML-DSA-65
  sign/verify per audit entry: ~1 ms — log overhead stays low even with
  per-entry signatures.
- Real networked path: revocation enforced at node-a within ~0.05 s and
  node-b within its 2 s poll; registry `kill -9` recovery via journal
  replay in < 1 s; session keys never written to disk.
- Detector over the 22-event labelled log: < 5 ms, fully deterministic.

## Demo video

> **5-minute walkthrough:** `<<ADD-PUBLIC-VIDEO-LINK-HERE>>`
> (unlisted YouTube / Google Drive — embedded as the live-demo fallback.)

The same walkthrough can be reproduced locally with `python3 demo.py`; the
45 scripted steps and their observed outcomes are printed.

## Team / attribution

Prototype built during the hackathon. Third-party dependencies:
`pqcrypto` (ML-KEM/ML-DSA wrappers), `cryptography` (HKDF, AES-GCM),
Python standard library otherwise.
