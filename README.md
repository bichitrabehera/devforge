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
├── demo.py                 runnable end-to-end demonstration (embedded mode)
├── demo_networked.py       REAL multi-process deployment demonstration
├── services/               real processes: registry, IdP, nodes, messenger
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
├── tests/test_networked.py   6 integration tests over real localhost sockets
├── practice/               organizer sandbox data (events.csv, labels.csv, approvals.json)
└── docs/
    ├── THREAT_MODEL.md     one-page threat model
    ├── PROJECT_BRIEF.md    USP, architecture, demo video link
    └── archive/            pre-rewrite audit notes
```

## Adapter contract v1 compliance

The organizer worker (`docs/adapter-v1.md` in the toolkit) drives exactly
five ops against the root `track4_service.py`:

- **setup** resets state and initializes from `owners`, `contents`,
  `disabled`, and `key_material`. The sensitive `key_material` value is
  stored only as a SHA-256 digest and never appears in any response or
  diagnostic (validator check: "fake key stays out of output").
- **read** returns `allow` with the exact stored body, or `deny` with no
  content, and records the decision against `request_id`.
- **revoke** is actor-based, persists across processes; other actors keep
  their permissions.
- **audit** returns the **recorded** decision for the supplied
  `request_id` (not a re-evaluation).
- **protected_read** (scored KEM interop, not covered by the public
  validator): encapsulates against the caller's standard-Base64 raw
  ML-KEM-768 public key; returns the ciphertext as standard Base64 and
  `proof` = lowercase-hex HMAC-SHA256 keyed by the shared secret over the
  UTF-8 bytes of `challenge + stored_body` (no separator). The shared
  secret never leaves the application and is not persisted. Verified
  end-to-end from the client side in `tests/test_contract.py`.

Root-level `threat-model.json` declares `{"asset":
"protected-resource", "boundary": "identity-check"}` (accurate for this
design).

Judging-container notes: Python 3.12 + `pqcrypto==0.4.0`, read-only root
filesystem, no dependency installs during a run. All five contract ops run
on stdlib + pqcrypto alone — HKDF-SHA256 is the RFC 5869 standard
construction on `hmac`/`hashlib` (test-verified identical to
`cryptography`'s HKDF), and AES-GCM (needed only by the messaging ops) is
lazy-imported with a clean `aead_unavailable` failure if the package is
absent. State persists in `$TRACK4_STATE_DIR` or the OS temp dir.

## Networked deployment (real processes — nothing modeled)

The embedded engine above is deterministic and testable, but the same core
also runs as a REAL distributed system: separate OS processes over real TCP
with real clocks:

```
registry (control plane) ── policy/keys/epochs served over HTTP
idp (identity provider) ── issues ML-DSA-signed tokens, publishes /jwks.json
node-a / node-b ── poll the registry at their own real intervals (0.5 s / 2 s);
                    propagation delay is REAL network eventual consistency
messaging endpoint ── session keys live in RAM only, never on disk
```

```bash
# one command: spawns 5 processes, kills the registry with SIGKILL mid-rotation,
# measures real revocation propagation, real grace cutoffs, real token expiry
python3 demo_networked.py

# or run each process by hand
python3 services/registry_server.py --port 8300
python3 services/idp_server.py --port 8400
python3 services/node_server.py --name node-a --port 8310 \
    --registry http://127.0.0.1:8300 --idp http://127.0.0.1:8400 --poll-interval 0.5
python3 services/messenger_server.py --name recv --port 8320 \
    --identity user-blair --peer user-alex
```

Real behaviors demonstrated: `kill -9` crash + journal replay on restart,
per-node measured enforcement times, ML-DSA-JWT verification against the
IdP's JWKS with real expiry, E2E delivery across real reordered/lost
messages, tamper-evident per-node logs, and signed backup files stored
outside the live state.

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

- **Two modes, one codebase.** The embedded engine (single process,
  simulated clock and nodes) powers deterministic tests and the organizer's
  stdin/stdout validator. The networked deployment (`services/`,
  `demo_networked.py`) runs the same core as real processes with real
  clocks and real propagation; nothing in the networked path is simulated.
- **Identity.** The IdP is a separate process issuing ML-DSA-65-signed
  tokens; nodes verify against `/jwks.json` with real expiry. It is
  OIDC-shaped (register/token/jwks) but self-hosted so the sandbox needs no
  internet; swapping in an external OIDC provider would replace the token
  format/verification, not the enforcement model.
- **Propagation model.** Nodes poll the registry's policy endpoint; real
  propagation delay = real poll interval + network latency, measured and
  reported per node by the node itself.
- **Backup trust anchor.** The manifest embeds the service ML-DSA public
  key. While the live key exists it must match (origin check). After total
  disk loss only integrity of the backup can be verified (the origin check
  needs the live key) — this assumes backup storage is access-controlled.
- **Detector context model.** Approvals authorize (subject, operation, role)
  inside a validity window; the service graph and role scopes are explicit,
  documented constants — no learning, no statistics, fully explainable.
- **Log rotation.** Audit logs (registry and per-node) are kept unbounded;
  a production deployment would seal and archive segments (each sealed
  segment remains independently verifiable by the same chain + signature
  scheme).
- **Messaging endpoints.** In networked mode the receiving endpoint is a
  separate process holding session keys in RAM only; the sending side is
  currently driven by a client (the demo driver). A full sender endpoint
  process is straightforward follow-on work.
