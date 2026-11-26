# Security Assessment — Track 4 (self red-team)

Date: during hackathon. Scope: our own submission only (organizer sandbox;
no external systems). Method: adversarial testing against the embedded
adapter (`track4_service.py` / `src/*`), the registry (`services/`) and the
messaging endpoint. Every finding was converted into a permanent regression
test in `tests/test_adversarial.py`.

## Summary

| # | Attack | Before | Severity | Status after hardening |
|---|--------|--------|----------|------------------------|
| 1 | **On-disk state tampering**: attacker rewrites `owners` in `state.json` and reads protected content | exploited — content disclosed | **Critical** (local-attacker model) | **Fixed**: state integrity manifest (SHA-256 over full state); tamper → quarantine (`state_integrity_failure`), every op refused except verified-recovery paths; restore-from-backup verified before use. Deleting the manifest itself is also detected. |
| 2 | **Journal forgery**: append a fake rotation commit signed with attacker's own ML-DSA key; recovery adopts attacker key material | exploited — version 999 adopted | **High** | **Fixed**: every journal record is ML-DSA-signed by the service key; replay verifies signatures and rejects forged/tampered/unsigned records (`journal_records_rejected` reported). Tampering an existing signed record breaks its signature → skipped. |
| 3 | **Decision-record overwrite**: attacker re-uses a victim's `request_id` to overwrite the recorded audit decision | exploited — victim's `allow` audited as `deny` | Low–Medium | **Fixed**: first-write-wins on recorded decisions. |
| 4 | **Backup blob swap**: attacker replaces manifest+payload+signature with their own keypair | blocked (`backup_identity_mismatch`) | Medium (chained with #1 it became exploitable; #1's fix closes the chain) | Blocked + regression test. |
| 5 | Cross-session ciphertext replay (session-1 ciphertext into session-2) | blocked (`authentication_failed` — AEAD + sid-bound AAD) | — | Blocked + regression test. |
| 6 | Forged/modified resumption token | blocked (`peer_not_bound_to_session`, constant-time compare) | — | Blocked + regression test. |
| 7 | Log injection (JSON boundary splice, newlines, unicode in actor/detail) | blocked — text stays one JSON string; recorded actor unchanged; chain+signatures valid | — | Blocked + regression test. |
| 8 | Type confusion (`challenge` as object/array; non-string actor/asset; `key_version` fuzz) | graceful `op_failed`, no crash, no leak | Low | **Hardened**: challenge/body coerced deterministically; fuzz suite asserts every malformed request fails closed with no content disclosure. |
| 9 | Resource exhaustion: 400 session opens, replay-memory flood, unbounded failure reports | sessions unbounded (400 accepted) | Low (DoS) | **Fixed**: session cap (256, closed sessions pruned first), replay-memory cap (1000/recipient), failure-report cap (100). |
| 10 | Detector poisoning: crafted events (10^9 ms offset, injected JSON-ish actor strings, newline session ids) | handled — flagged `order_uncertain`, strings stay opaque values | — | Regression test added. |
| 11 | `audit` op returns recorded metadata for any request_id | accepted | Info | Accepted by design: the adapter contract requires request_id lookup; responses contain decision metadata only, never protected content. |
| 12 | Unauthenticated `revoke`/`re_enroll`/`disable` in the embedded adapter | accepted | Info | Accepted by design: the adapter contract defines a trusted local caller ("actor values are trusted local inputs, not authenticated identities"). In networked mode every node action requires an IdP-issued ML-DSA token; revocations propagate as signed policy. |

## Honest limits of this hardening

- The integrity manifest and journal signatures are keyed by the service
  ML-DSA key **which itself lives on the same disk** (embedded: inside
  state; registry: in its key file). An attacker who can *read* that key
  can forge manifests/signatures. The defense detects tampering by
  attackers who write without the key (corruption, partial tampering,
  blind overwrite) and guarantees fail-closed behavior; full protection
  against a key-reading disk attacker requires hardware-backed or
  out-of-band key storage — documented as out of scope for the sandbox.
- The detector operates on provided event data; poisoned input is flagged
  as uncertain rather than silently trusted, but semantic poisoning (a
  crafted *plausible* event stream) is a data-quality problem outside the
  detector's control and is covered by the documented context model.
- Cryptography itself was not attacked (per the toolkit: the public
  validator and this self-assessment do not attempt cryptanalysis of
  ML-KEM/ML-DSA/AES-GCM; primitives come from vetted libraries).

## Round 2 - maximum-intensity campaign (cyberpunk round)

New weapon classes: rollback substitution, NaN-clock oracles,
approvals-source injection, write amplification, version downgrade,
unconfigured-state crashes. Every confirmed hit is now a permanent
regression test in `tests/test_adversarial.py`.

| # | Attack | Result before | Severity | Status after hardening |
|---|--------|--------------|----------|------------------------|
| R1 | **Rollback substitution**: replace `state.json` with an older-but-valid snapshot (integrity manifest intact) after a revocation | exploited - revoked attacker read `stolen goods` again | **High** | **Fixed**: signed-journal FLOOR gate. The journal is append-only and ML-DSA-signed; a live state whose active key version or revocation epoch sits below the verified journal floor is detected and auto-repaired by replaying verified records (`state_rollback_detected` only if reconciliation fails). Registry service got the same floor check. Also fixed an epoch-monotonicity bug this gate exposed: `recover_state` now keeps the epoch counter monotonic across revocations and re-enrolments. |
| R2 | **NaN clock poisoning**: `advance_time(seconds=NaN)` poisons every comparison (`NaN >= x` is False forever) so a revoked device is allowed indefinitely | exploited (with the test helper op) | **High** (embedded ops) | **Fixed**: non-finite time deltas rejected (`invalid_time_delta`); a non-finite `clock_offset` on disk (even with a hand-recomputed manifest) marks the state tampered -> quarantine -> verified recovery replays the journal and restores enforcement. |
| R3 | **Approvals-source injection**: `grant_role` with `approvals_path` pointing at an attacker-written file -> fake approval -> `report-reader` role granted | exploited - role granted, access widened | **High** | **Fixed**: approvals files are honored only from inside the repository root (organizer/operator policy source); anything else -> `untrusted_approvals_source`, denied, logged. |
| R4 | **Write amplification**: 5 MB `request_id` -> ~10 MB state file per op (resource exhaustion) | exploited | Medium | **Fixed**: request ids clipped to 256 chars, log details to 4000 (marked truncated). |
| R5 | **Unconfigured-state crash**: ops before `setup` hit an unsigned-entry crash in the audit path | crash (uncaught TypeError) | Low | **Fixed**: pre-setup entries are recorded unsigned + marked; `verify_log` handles them; dispatch() wraps every handler - any unexpected exception becomes a clean `op_failed` error, never a stack trace. |
| R6 | Version downgrade to an ancient committed key version | blocked (`old_key_after_cutoff`) | - | Regression test added. |
| R7 | Massive-but-plausible probe: offline proof oracle on `protected_read` | no info gain: proof verification requires the caller's own shared secret, and the same caller could just call `read` | Info | Documented. |

Round-2 honesty notes (known remaining limits):
- The state integrity manifest is an UNKEYED hash: a deliberate disk
  attacker can tamper AND recompute it. It detects blind/corrupt writes,
  not adversarial ones - the adversarial cases are covered by the signed
  journal floor (R1) and backups. A keyed manifest would need the key
  somewhere else on the same disk (circular). Out-of-band key storage is
  the real fix; documented, not claimed.
- Journal TRUNCATION (deleting trailing revocation records) lowers the
  floor: an attacker who can edit state and journal consistently can
  undo a revocation without detection. Mitigation: backups + recovery
  paths; full fix needs an external anchor for the journal head.
- Registry/node traffic is plain HTTP on loopback; TLS/mTLS is a
  production requirement, out of sandbox scope.

## Verification

`python3 -m unittest discover -s tests` - **61 tests, all passing**
(23 objective + 6 networked + 10 contract + 22 adversarial), plus the
45-step demo `all_ok=True`.
