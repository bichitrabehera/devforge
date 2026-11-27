# Track 4 — "Trust, but verify"

A post-quantum key-lifecycle, identity and access-control prototype: it
protects messages while keys, devices and permissions change, keeps a
tamper-evident audit log, and detects unexpected privilege gains and lateral
movement from access logs.

All cryptography comes from vetted libraries only — **ML-KEM-768 (FIPS 203)**
and **ML-DSA-65 (FIPS 204)** via `pqcrypto`, plus **HKDF-SHA256** and
**AES-256-GCM** via `cryptography`. No custom primitives, no AI/ML.
Correctness is evidenced, not assumed: official RFC 5869 HKDF vectors,
cross-implementation interop between pqcrypto (PQClean) and `cryptography`
(OpenSSL), and an optional NIST ACVP loader (`tests/test_kat.py`). The
adapter also runs on BOTH pqcrypto APIs (0.4.x `generate_keypair` and 1.x
`keygen`) — the judging container's pin is covered.

**AES-GCM key commitment:** GCM does not prove which key produced a
ciphertext, so every message envelope carries an HMAC key-commitment tag
inside its authenticated AAD — a message made under any other key fails
authentication before delivery (`src/messaging.py`, `TestKeyCommitment`).

## Quick start (clean machine)

No virtual environment is required — the project runs on the system
Python with exactly two third-party packages (see `requirements.txt`):

```bash
# system Python is fine (verified: no venv needed)
pip install -r requirements.txt      # or: pip install --user -r requirements.txt

# run the full test suite (135 tests incl. KAT, verifier, red team; 3 skipped)
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

## Operator console (FastAPI + Next.js)

The API is a **thin layer** over the existing engine: every cryptographic,
authorization, revocation, recovery, audit and detection decision is made by
`src.dispatch.dispatch()` and the existing functions in `src/` and `services/`.
The frontend makes no security decisions; it submits forms and displays safe
backend responses. No private keys, tokens, stack traces, paths or raw internal
errors are returned.

### Backend

```bash
pip install -r requirements.txt -r server/requirements.txt

cd server
uvicorn main:app --reload --port 8000
```

CORS allows only `http://localhost:3000`. API endpoints:

| Method | Path | Existing engine function called |
|---|---|---|
| POST | `/api/demo/setup` | `keys.op_setup` + `keys.op_re_enroll` for the local practice identities (idempotent) |
| POST | `/api/demo/reset` | demo-only forced `engine.demo_setup(force=True)` for a fresh practice state after a previous run |
| POST | `/api/demo/recovery-proof` | demo-only proof generation with the engine-held recovery signing key; do not expose in production |
| POST | `/api/login` | `keys.op_authenticate`, `keys.op_status`; recovery proof verified with `crypto.dsa_verify` against the registered recovery public key |
| GET | `/api/status` | `keys.op_status`, `keys.op_node_status`, `detector.evaluate_live`, `detector.evaluate_labelled`, `audit.verify` |
| POST | `/api/messages/send` | `messaging.op_session_open`, `op_session_accept`, `op_message_send`, `keys.op_authenticate` on node-a/b/c |
| GET | `/api/messages/{message_id}` | `messaging.op_message_receive` (opaque reference sent as `Authorization: Bearer …`, never in the URL) |
| POST | `/api/admin/rotate-key` | `keys.op_rotate_key` |
| POST | `/api/admin/revoke-device` | `keys.op_revoke`, `keys.op_revoke_report`, per-node `keys.op_authenticate` |
| POST | `/api/recovery/enroll-device` | `keys.op_recover_device`; only the recovery session reference is accepted, plus a proof signed by the bound recovery identity |
| POST | `/api/admin/crash-recovery-test` | `recovery.op_begin_rotation`, `op_crash_rotation`, `op_recover_state` |
| POST | `/api/admin/backup-integrity-test` | `recovery.op_create_backup`, `op_damage_backup`, `op_restore_backup` |
| POST | `/api/admin/log-integrity-test` | `dispatch._op_tamper_log` + `audit.verify` on an isolated state copy |
| GET | `/api/detector/alerts` | `detector.evaluate_live` |
| POST | `/api/detector/run` | `detector.evaluate_labelled` |
| GET | `/api/audit/verify` | `audit.verify` |

A freshly started API auto-creates the local practice state on the first
`/api/status`, `/api/login` or recovery-login call, so the console works from an
empty state directory. The explicit `/api/demo/setup` button is idempotent and
does not clear a stale revoked device. Use `/api/demo/reset` (the console's
**Reset demo state** button) for a fresh practice state before re-running the
demo. `/api/demo/recovery-proof` exists only to generate pasteable demo proofs; a
production deployment must provision proofs at the recovery identity instead.
The health route is available at both `/api/health` and `/health`.

Safe error categories only: `unauthorized`, `revoked`, `invalid_message`,
`key_expired`, `backup_corrupt`, `log_tampered`, `invalid_request`.
Every response — success or failure — carries the stable decision envelope
`decision`, `reason`, `identity` and `device`; failures additionally carry one
safe `error` category. No private keys, reference values, stack traces, paths
or raw internal errors are returned.

Normal `/api/login` accepts `username` and `device_id` and returns an opaque
session reference (not a key or IdP token); every protected route re-validates
it through the engine's authentication function before calling the target op.
Admin routes additionally check the engine's configured `admins` list.

Recovery login accepts `username` plus `recovery_proof`, where the proof is
signed by the bound recovery identity over the engine-canonical challenge
`{"actor": "<recovery-username>", "purpose": "recovery_login"}`. The resulting
recovery reference is the **only** session accepted by
`/api/recovery/enroll-device`; the lost-device reference is refused. Re-enrol
still requires the engine's recovery proof over
`{"actor", "old_device", "device"}`, but never asks for the lost device's
private key. For POST requests the reference is sent in the JSON body; for the
authenticated GET message read it is sent in the `Authorization` header.

Stable projections used by the console include `/api/status` (`users`,
`devices`, `key_versions.active/grace_until/old_key_cutoff`,
`revocations.epoch/devices`, `nodes[].node/status/last_enforced_revocation`,
`audit.integrity_status/event_count`, and the three named detector metrics),
`/api/detector/alerts` (`count`, `alerts[]` with identity/alert/services/
event_ids/rule/explanation/timestamp), and `/api/messages/send`
(`status="delivered"`, `message_id`, `route[]`, `policy_decisions[]`).

### Frontend

```bash
cd frontend
npm install
npm run dev
```

`frontend/.env.local` sets `NEXT_PUBLIC_API_URL=http://localhost:8000`. The
single text-only page (created with the official `create-next-app` CLI) uses a
large-screen `3fr_1fr` grid: operator actions on the left (Identity, Secure
message, Key lifecycle, Device lifecycle, Resilience checks, Detection) and
live results on the right (Latest result, Message route, Alerts, Key /
revocation state, Integrity, Raw API response). It uses plain HTML inputs and
Tailwind only; no UI, icon, chart or animation libraries. Session references,
recovery proofs and keys are never rendered, and the raw JSON panel redacts
those fields before display. The theme is cream (`#fbf7ec`) with light pastel
card headers and hover/focus affordances; `frontend/design.md` remains the
layout and section-order reference. On wide screens the console is a single
fixed-height dashboard with no page scroll; the raw JSON preview is collapsed
by default.

#### Console walkthrough

1. Start the API with `uvicorn main:app --reload --port 8000` from `server/`,
   then start the frontend with `npm run dev` from `frontend/`. Open
   `http://localhost:3000`; `GET /health` also returns `200` on port 8000.
2. The first page load calls `/api/status` and creates the practice identities.
   The **Setup** button is an idempotent fallback. If the banner says
   `device-blair is revoked`, click **Reset demo state** first; this clears the
   stale state that would make recipient sign-in return `403 revoked`.
3. In **Identity**, click **Authenticate operator** with the default `user-alex` /
   `device-alex`. In **Secure message**, type a message, set recipient to
   `user-blair`, and click **Send encrypted message**. The returned `Message ID`
   is copied into the read field automatically. Click **Authenticate recipient**
   and then **Read as recipient** before revoking Blair's device. Each envelope
   can be read once; a second read is correctly refused as a replay.
4. Click **Authenticate admin** in **Identity**. Admin controls in **Key
   lifecycle**, **Device lifecycle** and **Resilience checks** use this
   session; sending uses the operator session and recipient reads use the
   recipient session. The right column's progress strip is interactive: click
   **Run next** or any active step chip; grey chips wait for their prerequisites.
5. For recovery, click **Run next** (or the **Recovery proof** chip) then
   **Recovery** (or the **Recovery session** chip). In **Device lifecycle**,
   keep `user-blair` / `device-blair` / `device-blair-replacement`, click
   **Enrol proof**, **Revoke device**, then **Re-enrol** (or the
   **Device re-enrolled** chip). The re-enrol uses only the recovery session.
6. Run **Crash-recovery test**, **Backup-integrity test**, **Log-integrity
   test**, **Run detector** and **Refresh alerts**. The right column shows the
   latest decision, message route, alerts, key/revocation state, integrity and
   the redacted raw JSON.

### Demo and checks

```bash
python3 scripts/run_working_demo.py   # docs/demo_transcript.txt, docs/demo_metrics.json
python3 -m unittest discover -s tests -v
python3 /home/daaku/Desktop/Track-4-Toolkit/validate.py \
    --entry /absolute/path/to/track4_service.py \
    > docs/organizer_validation_local.txt
```

### Known limitations of the console layer

- Login with only `username + device_id` cannot perform IdP proof-of-possession;
  it relies on the engine's node authentication. A production console should
  obtain a real IdP token from the device key.
- `/api/messages/send` uses the engine's embedded node-a/b/c policy checks as
  the closest existing multi-node path. The genuine 9-process A -> messenger ->
  B -> C delivery is exercised by `demo_networked.py` and the demo script.
- The interrupted rotation in `/api/admin/crash-recovery-test` is the existing
  embedded crash simulation, not a real `SIGKILL` during rotation.
- Session references are in-memory only and expire after one hour; restarting
  the API process invalidates them.
- Read-only endpoints (`/api/status`, `/api/detector/*`, `/api/audit/verify`,
  `/api/health`, `/health`) are not authenticated in this prototype; a production
  deployment should gate them behind the IdP as well.
- Detector metrics are from the 22-event synthetic practice set only and are
  not a production accuracy claim. Timings are single local runs.

## Verify everything yourself (operator view)

The service's own checks are not the evidence — an operator who does not
code trust the service re-checks the artifacts with the standalone
verifier, and the red team probes the adapter the way the judges will:

```bash
python3 tools/selfattack.py                 # 15 items / 76 black-box checks
python3 scripts/check_all.py                # repo hygiene gate (see header)
python3 verifier/track4_verify.py audit --state /tmp/track4_state/state.json \
    --pub <service-dsa-pk-hex> --expect-head <head-you-recorded>
python3 tools/gen_logs.py --out /tmp/heldout --events 12000 --seed 20261126
python3 scripts/eval_detector.py --events /tmp/heldout/events.csv \
    --labels /tmp/heldout/labels.csv --approvals /tmp/heldout/approvals.json
```

Exit-code discipline of the verifier: `0` = verified AND completeness
established (head/counter recorded out of band), `2` = verified but
completeness NOT established, `1` = verification failed. A script that
tests only the exit code is never told OK about a possibly truncated log.

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
├── tools/
│   ├── selfattack.py       black-box red team against our own adapter
│   │                       (15 items, 76 checks, severity-classified)
│   └── gen_logs.py         independent labelled-log generator (held-out
│                           detector evaluation, fixed seed)
├── scripts/
│   ├── check_all.py        ONE command: layout, AST static scan, secrets
│   │                       (tree + full git history), AI-identity scan,
│   │                       validator, tests
│   ├── eval_detector.py    detector scoring incl. per-class P/R/F1
│   ├── make_brief_pdf.py   renders the 2-page brief
│   └── run_working_demo.py 17-step transcript + measured metrics
├── server/                 thin FastAPI wrapper (engine adapters + routes)
├── frontend/               basic Next.js + Tailwind operator console
├── verifier/
│   └── track4_verify.py    STANDALONE verifier: imports nothing from src/;
│                           audit/journal/state/backup; exit 0 verified +
│                           complete, 1 failed, 2 verified-but-incomplete
├── tests/test_objectives.py  23 tests, one class per challenge objective (plus
│                              118 more across adversarial/contract/networked/
│                              KAT/verifier/selfattack suites)
├── tests/test_networked.py   6 integration tests over real localhost sockets
├── tests/test_kat.py         official RFC 5869 vectors + pqcrypto↔OpenSSL
│                              cross-implementation checks (+ optional NIST
│                              ACVP loader, see file docstring)
├── tests/test_verifier.py    verifier agrees with the service, rejects tamper
├── tests/test_selfattack.py  the whole red-team run stays clean
├── practice/               organizer sandbox data (events.csv, labels.csv, approvals.json)
└── docs/
    ├── THREAT_MODEL.md     one-page threat model
    ├── PROJECT_BRIEF.md    USP, architecture, demo video link
    ├── EVIDENCE_MATRIX.md  12 objectives: demo, expected-before-run,
    │                       measured result, limit — one row each
    ├── DETECTOR_METRICS.md practice AND held-out (12k events) metrics
    ├── SELFATTACK_REPORT.md generated by tools/selfattack.py
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
node-a / node-b / node-c ── poll the registry at their own real intervals (0.5 s / 2 s / 4 s);
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
| Revocation across nodes | `src/keys.py::op_revoke` — per-node enforcement at `revoked_at + node.sync_delay_s` (node-a 0 s, node-b 2 s, node-c 4 s); reports `time_until_last_node_enforces`; owner re-enrols via `op_re_enroll`, other users unaffected | `TestRevocationAcrossNodes` |
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
