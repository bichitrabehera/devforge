# Track 4 — "Trust, but verify"

A post-quantum key-lifecycle, identity and access-control prototype: it
protects messages while keys, devices and permissions change, keeps a
tamper-evident audit log, and detects unexpected privilege gains and lateral
movement from access logs.

All cryptography comes from vetted libraries only — **ML-KEM-768 (FIPS 203)**
and **ML-DSA-65 (FIPS 204)** via `pqcrypto`, plus **HKDF-SHA256** and
**AES-256-GCM** via `cryptography`. No custom primitives, no AI/ML.

## Quick start (clean machine)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# run the objective test suite (23 tests)
python3 -m unittest discover -s tests -v

# scripted end-to-end demonstration (rotation, revocation, recovery,
# backup integrity, log integrity, messaging, detection metrics)
python3 demo.py

# or drive the service directly: one JSON request on stdin -> one on stdout
echo '{"op": "status"}' | python3 track4_service.py
echo '{"op": "demo"}'   | python3 track4_service.py
```

State lives under `$TRACK4_STATE_DIR` (default `/tmp/track4_state`): a live
`state.json` (atomic replace), an append-only `journal.jsonl`, and signed
backups under `backups/`. Private state for tests/demo is isolated
automatically.

## Repository layout

```
├── track4_service.py       JSON stdin/stdout service adapter (entry point)
├── team_app.py             compat shim -> src.dispatch.dispatch
├── detector.py             compat shim -> src.detector
├── demo.py                 runnable end-to-end demonstration
├── requirements.txt        pinned dependencies
├── src/
│   ├── state.py            persistence (atomic writes + durable journal), simulated clock
│   ├── crypto.py           vetted primitives (ML-KEM-768, ML-DSA-65, HKDF, AES-GCM)
│   ├── audit.py            hash-chained, ML-DSA-signed, injection-proof audit log
│   ├── access.py           identity / access-control decisions
│   ├── keys.py             rotation (cutoff+grace), multi-node revocation, re-enrolment
│   ├── recovery.py         crash recovery via journal replay; signed backup/restore
│   ├── messaging.py        E2E sessions: forward secrecy, replay/reorder/loss, resumption
│   ├── detector.py         rule-based detection + F1/TTA/FP-per-1000 metrics
│   ├── dispatch.py         op registry (single entry point)
│   └── demo.py             the scripted demonstration
├── tests/test_objectives.py  23 tests, one class per challenge objective
├── practice/               organizer sandbox data (events.csv, labels.csv, approvals.json)
└── docs/
    ├── THREAT_MODEL.md     one-page threat model
    ├── PROJECT_BRIEF.md    USP, architecture, demo video link
    └── archive/            pre-rewrite audit notes
```

## Challenge checklist -> where it is implemented

| Objective | Implementation | Verified by |
|---|---|---|
| Key rotation + cutoff | `src/keys.py::op_rotate_key` — new ML-KEM version; old version valid until `cutoff_at = created_at + grace_seconds` (**documented grace period, default 30 s simulated time**); after cutoff every node rejects `old_key_after_cutoff` | `TestRotationCutoff` |
| Revocation across nodes | `src/keys.py::op_revoke` — per-node enforcement at `revoked_at + node.sync_delay_s` (node-a 0 s, node-b 2 s); reports `time_until_last_node_enforces`; owner re-enrols via `op_re_enroll`, other users unaffected | `TestRevocationAcrossNodes` |
| Crash recovery | `src/recovery.py` — rotations journaled before commit; `recover_state` replays to the last commit marker; state writes are atomic, so a torn write never exposes a half-rotation; revocations survive; total disk loss honestly requires a signed backup | `TestCrashRecovery` |
| Backup integrity | `op_create_backup` signs the manifest (backup_id + payload SHA-256 + verifier key) with ML-DSA; `op_restore_backup` verifies signature then hash before loading anything; damaged backups are reported, never used | `TestBackupIntegrity` |
| Log integrity | `src/audit.py` — every entry hash-chained and ML-DSA-signed; user text lives only in the `detail` JSON field, so injection cannot forge a second event or change the actor; `verify_log` validates chain + hashes + signatures | `TestLogIntegrity` |
| Routine vs suspicious + metrics | `src/detector.py::evaluate_labelled` on the labelled sandbox log: **F1 = 1.0, median time-to-alert = 1.2 s, 0 false alerts per 1,000 benign events** | `TestDetectorLabelled` |
| Lateral movement | Unknown service edges (outside the documented service graph + role scopes); ≥ 2 unknown edges in one session → alert per edge, each naming identity, services, related events, rule and path | `TestDetectorLabelled` |
| Clock differences | Source offsets (±60 s supported) subtracted to recover true time; arrival inversions within a 10 s window annotated `delayed_delivery`; beyond that flagged `order_uncertain` | `TestDetectorLabelled` |
| Replay + recipient binding | AES-GCM AAD binds (sid, sender, recipient, counter); duplicate msg_id → `duplicate_replay`; wrong AAD → `authentication_failed`; wrong recipient → `recipient_binding_mismatch` | `TestMessaging` |
| Forward secrecy | Session key from a fresh **ephemeral** ML-KEM keypair per session; the ephemeral secret is zeroized at accept and the session key at close — later long-term-key exposure cannot reveal completed sessions | `TestMessaging` |
| Delivery under loss/reordering | Gaps within a documented window (8) are buffered and delivered in counter order once filled; invalid messages are discarded and delivery failures reported | `TestMessaging` |
| Session resumption | Resume requires `HMAC(resumption_secret, peer)`; every resume ratchets the key and rotates the secret — a different identity presenting the same sid is rejected | `TestMessaging` |

## Operations reference

| Op | Purpose |
|---|---|
| `setup`, `status`, `advance_time` | initialize; inspect state; move the simulated clock (deterministic cutoff/grace/propagation timing) |
| `read`, `grant_role`, `revoke_role`, `disable` | access control with explainable decisions, approval-checked role changes |
| `rotate_key`, `authenticate`, `node_status`, `node_sync` | rotation with grace, per-node key/revocation enforcement |
| `revoke`, `revoke_report`, `re_enroll` | device revocation with measured propagation, re-enrolment |
| `begin_rotation`, `crash_rotation`, `corrupt_state`, `recover_state`, `journal_status` | interrupted-rotation simulation and journal-based recovery |
| `create_backup`, `damage_backup`, `restore_backup` | signed backups; damage/restore cycle |
| `append_log`, `verify_log`, `tamper_log` | audit log writes, verification, attacker simulation |
| `session_open`, `session_accept`, `message_send`, `message_receive`, `inbox_drain`, `session_resume`, `session_close` | E2E messaging lifecycle |
| `detector_evaluate`, `detector_live`, `demo` | metrics on labelled logs, live-log alerts, scripted walkthrough |

## Design decisions & honest limitations

- **Simulated clock and nodes.** Timing behaviors (grace, propagation) use a
  simulated clock and two in-process nodes with configurable sync delays so
  results are deterministic and reproducible; a production system would use
  signed state epochs and real node gossip.
- **One-process endpoints.** Both messaging endpoints run in the same
  service process; in a real deployment the session key would live only in
  endpoint memory. Forward secrecy still holds in the model: the only secret
  that could recover the session key is deleted before any exposure matters.
- **Backup trust anchor.** The manifest embeds the service ML-DSA public
  key. While the live key exists it must match (origin check). After total
  disk loss only integrity of the backup can be verified (the origin check
  needs the live key) — this assumes backup storage is access-controlled.
- **Detector context model.** Approvals authorize (subject, operation, role)
  inside a validity window; the service graph and role scopes are explicit,
  documented constants — no learning, no statistics, fully explainable.
- **Log rotation.** The audit log is kept unbounded in state; a production
  deployment would seal and archive segments (each sealed segment remains
  independently verifiable by the same chain + signature scheme).
