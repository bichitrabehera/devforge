# Evidence Sheet — Track 4 "Trust, but verify"

Mirrors the organizer template (`Track-4-Toolkit/templates/evidence-sheet.md`):
one row per goal, the behavior demonstrated, and where it is verified.
All metrics measured with real processes/sockets where noted; nothing here is
estimated. State is isolated per run; no synthetic values are reused.

## Adapter contract v1 (five ops) — demonstrated behavior

| Op | Demonstrated behavior | Verified by | Result |
|---|---|---|---|
| setup | resets state; honors `disabled`; `key_material` stored as SHA-256 digest only, never disclosed (validator marker check passes) | `tests/test_contract.py::TestSetupReset`; organizer validator | PASS |
| read | allow with exact stored body / deny with no content; decision recorded against request_id | organizer validator (all 23 checks) | PASS |
| revoke | actor-based, persists across processes, others unaffected | organizer validator | PASS |
| audit | returns the RECORDED decision for the request_id, surviving later policy changes | `TestRecordedAudit` | PASS |
| protected_read | KEM interop: encapsulate against caller's Base64 raw ML-KEM-768 key; ciphertext (Base64) + lowercase-hex HMAC-SHA256(shared secret, challenge + body); verified by decapsulating client-side; secret never leaves the app | `TestProtectedRead`, `TestAdapterEndToEnd` (subprocess) | PASS |

Container hardening: the five contract ops need only stdlib + pqcrypto
(HKDF is the RFC 5869 standard construction, test-verified identical to
`cryptography`'s implementation); AES-GCM is lazy-imported for messaging
ops only; stdin is read through EOF; state persists across the one-
process-per-request model.

## Twelve security goals — demonstrated behavior

| # | Goal | Demonstrated behavior | Verified by | Result |
|---|------|----------------------|-------------|--------|
| 1 | Key rotation | Authorized transfers continue during rotation; old key accepted until a **documented cutoff (grace 30 s simulated in embedded mode; real seconds in networked mode)**; after cutoff every node rejects `old_key_after_cutoff` | `tests/test_objectives.py::TestRotationCutoff`; networked: `tests/test_networked.py::test_02` | PASS |
| 2 | Revocation across nodes | Node-a and node-b enforce at their own real poll intervals (0.5 s / 2.0 s); enforcement time measured and reported per node (~0.05 s / within one poll); owner re-enrols with fresh keys; other users retain access | `TestRevocationAcrossNodes`; networked `test_03`; organizer lost-device validator: all checks PASS | PASS |
| 3 | Crash recovery | Rotation journaled before commit; journal replay to last commit marker; uncommitted rotations discarded; revocations persist; protected data available; registry `kill -9` recovers consistently | `TestCrashRecovery` | PASS |
| 4 | Backup integrity | ML-DSA-signed manifest over SHA-256 payload, stored outside live state; signature+hash verified before load; damaged backup reported (`backup_integrity_failure`), never used | `TestBackupIntegrity`; networked `test_04` | PASS |
| 5 | Log integrity | Structured, hash-chained, ML-DSA-signed entries; injection text cannot forge a second event or change the actor (injection probe tested); `verify_log` reports first bad entry + reason | `TestLogIntegrity` | PASS |
| 6 | Routine vs suspicious | Context-driven rules (approvals validity window, role scopes); metrics on the organizer's 22-event labelled log: **F1 = 1.0, median time-to-alert = 1.2 s, 0 false alerts per 1,000 benign events** | `TestDetectorLabelled::test_metrics_on_labelled_log` | PASS |
| 7 | Lateral movement | Burst of >= 2 unexpected service edges flagged even when denied/valid-credentials; each alert names identity, services, events, rule and path; reported as CANDIDATE (does not imply successful compromise); isolated denial not flagged | `TestDetectorLabelled::test_alerts_are_explainable` | PASS |
| 8 | Clock differences | Source offsets up to ±60 s normalized to true time (documented supported range); arrival inversions within a 10 s tolerance annotated `delayed_delivery`; beyond that flagged `order_uncertain`; receipt order and event order kept separately | `TestDetectorLabelled::test_clock_differences_and_out_of_order`, `test_offset_beyond_range_flagged_uncertain` | PASS |
| 9 | Replay + recipient binding | AES-GCM AAD binds (session, sender, recipient, counter); duplicate msg_id → `duplicate_replay`; tampered counter/ciphertext → `authentication_failed`; wrong recipient → `recipient_binding_mismatch` | `TestMessaging::test_replay_and_recipient_binding`; networked `test_05` | PASS |
| 10 | Forward secrecy | Per-session ephemeral ML-KEM-768 keypair; ephemeral secret zeroized at accept (verified absent from state); session key zeroized at close; later long-term-key exposure cannot reveal completed sessions | `TestMessaging::test_forward_secrecy`; networked endpoint reports keys in RAM only | PASS |
| 11 | Delivery under loss/reordering | Gaps within documented window (8) buffered; in-order delivery when hole fills; stale counters rejected; gaps beyond window reported as failures (`gap_too_large`) | `TestMessaging::test_delivery_under_loss_and_reordering`; networked `test_05` | PASS |
| 12 | Session resumption | Resumption requires `HMAC(resumption_secret, peer)`; key ratchets and secret rotates per resume; same sid + different identity rejected (`peer_not_bound_to_session`) | `TestMessaging::test_session_resumption_peer_binding` | PASS |

## Beyond the adapter interface (adapter contract v1)

The five adapter ops (`setup`, `read`, `revoke`, `audit`, `protected_read`)
are exercised by the organizer's lost-device validator (all checks PASS).
End-to-end messaging, replay protection, forward secrecy, key lifecycle,
recovery, backups, and detection each require separate evidence — provided
above via the objective and networked test suites and `demo.py` /
`demo_networked.py`.

## Measurement record

| Metric | Value | Method |
|---|---|---|
| Detector F1 (labelled 22-event log) | 1.0 | rules run label-blind; labels only used for scoring (`evaluate_labelled`) |
| Median time-to-alert | 1.2 s | alert collector receipt time minus first related event's true time, median over 5 alerts |
| False alerts / 1,000 benign | 0.0 | 0 alerts on 17 benign events |
| Revocation propagation (networked, real) | node-a ~0.05 s; node-b within its 2.0 s poll | measured per node, recorded in node `/status` |
| Registry crash recovery (real `kill -9`) | < 1 s | journal replay on restart (`demo_networked.py`) |
| Test suite | 29 tests, ~5.7 s | `python3 -m unittest discover -s tests` |
| KEM/AEAD/signature latency | ~1 ms per operation | ML-KEM-768 / ML-DSA-65 / AES-GCM via vetted libs |

## Limitations and caveats (honest)

- The 22-event practice dataset demonstrates functional detection only; it
  cannot establish accuracy, false-positive rate, resilience, cryptographic
  security, or throughput at scale. Rules are deterministic and
  context-driven; the labelled set is public and small.
- Networked-mode revocation coverage depends on the registry as the policy
  trust anchor; a compromised registry controls policy (documented).
- The receiving messaging endpoint is a separate process with RAM-only
  keys; the sending side is a client library (full sender endpoint process
  is follow-on work).
- Audit logs (registry and per-node) are unbounded; segment sealing is
  future work.
- pqcrypto is pinned to the judging runtime (0.4.0) while development used
  1.0.0; API compatibility must be re-verified on Python 3.12.
