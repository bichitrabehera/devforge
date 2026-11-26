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

## Round 3 - trust-model hardening (second-pass audit)

Scope: the embedded JSON adapter's own ops that the organizer contract
does NOT define. The contract ops (`setup`, `read`, `revoke`, `audit`,
`protected_read`) deliberately treat the local caller as trusted
("actor values are trusted local inputs") - the organizer's own validator
invokes them unauthenticated, so gating them would break the scored
contract. The networked mode is where identity is real (ML-DSA tokens).

| # | Attack (executed) | Before | Fix |
|---|-------------------|--------|-----|
| T1 | **Clock rewind** `advance_time seconds=-50` resurrects a dead old key into grace, and would un-enforce device revocations (now < enforce_at) | exploited | `advance_time` rejects negative and non-finite deltas (`clock_is_monotonic`); dead keys stay dead. Tests: `TestAdapterTrustModel::test_clock_cannot_rewind`, `test_rewinding_cannot_unenforce_revocation` |
| T2 | **Forged inline approvals** stuffed into the request + claimed admin -> `report-reader` granted | exploited | Inline `approvals` payloads are no longer honored for `grant_role`/`revoke_role`: approvals must come from a trusted file inside the repo root (organizer/operator policy). No trusted path -> empty approval set -> deny. Test: `test_inline_forged_approvals_ignored` (repro 1 now deny, no Q-REPORT leak) |
| T3 | **Pending-session hijack**: a different identity completes the half-open KEM handshake as the sender | exploited | `session_accept` is bound to the sender recorded at `session_open`; foreign sender -> `endpoint_mismatch / not_the_original_sender`. Test: `test_pending_session_cannot_be_hijacked` |
| T4 | **Foreign resumption-token minting**: `session_close` with a spoofed peer mints THAT peer's token (mallory resumed the alex<->blair session) | exploited | `session_close` only closes for the session's original recipient; a foreign peer is refused and no token is minted. Test: `test_close_cannot_mint_foreign_resumption_token` (repro 3) |

Accepted-by-design (documented trust boundary of the adapter contract):
spoofed `actor` on `read`/`protected_read`, unauthenticated
`revoke`/`setup`/`disable`/`rotate_key`/`re_enroll`, ghost actors, and the
demo helper ops (`tamper_log`, `corrupt_state`, `damage_backup`). These
are meaningful ONLY for a caller already able to run the process with our
user permissions - the threat the adapter contract delegates to the
networked mode (per-node ML-DSA token verification, policy polls, real
process isolation).

## Round 4 - networked-mode hardening (third-pass audit)

Target: the REAL processes (IdP, registry, messaging endpoint), where
identity was previously asserted only by caller-supplied strings.

| # | Attack (executed) | Before | Fix |
|---|-------------------|--------|-----|
| N1 | **IdP re-registration hijack**: anyone could re-register `user-alex` with a new device, then obtain a valid token still claiming `user-alex` | exploited | `/register` is now FIRST-WRITE-WINS: an existing identity cannot be re-registered with a different device (`identity_exists`); same-device re-registration stays idempotent. Test: `test_07` step 3. REMAINING HONEST GAP: the mock IdP still issues tokens for already-registered names without device proof-of-possession - token issuance to a registered name stands in for a real device-key challenge/response and is on the punch list. |
| N2 | **Unauthenticated registry control plane**: `POST /revoke` (and `/re_enroll`) succeeded with no token; anyone could revoke or restore any identity | exploited | `/revoke` and `/re_enroll` are now SELF-SERVICE AUTHENTICATED: the caller must present a valid, unexpired IdP ML-DSA token whose subject equals the actor (verified against the IdP's JWKS, fetched and cached). Alex's token cannot revoke blair (`not_permitted`); no token → `unauthorized`. The registry takes `--idp`; without it the routes fail closed (`idp_unconfigured`). Tests: `test_07` steps 1-2; `test_03` now runs the real authenticated flow. |
| N3 | **Messaging sender spoofing**: the endpoint accepted a caller-supplied sender at offer/establish and delivered envelopes under any claimed sender | exploited | `/session/offer` and `/session/establish` require a valid IdP token; the session binds to the token's SUBJECT. Establish with a different subject → `sender_mismatch`; envelopes whose sender differs from the session's authenticated sender → `reject sender_mismatch`. Tests: `test_07` steps 4-6; `test_05` runs the authenticated flow. |

Also verified held from round 2: detector adapter JSON, msg_id binding,
resumption ratchet, approvals path allowlist, cross-process revoke
persistence.

## Round 5 - IdP proof-of-possession (fourth-pass audit)

The mock IdP's core gap: token issuance for registered names with no
device credential, plus unauthenticated /disable and /enable.

| # | Probe (executed) | Before | Fix |
|---|------------------|--------|-----|
| I1 | Anyone reaching the IdP obtains a valid token for a REGISTERED identity | exploited | Device proof-of-possession: registration now stores the device's ML-DSA PUBLIC KEY; `/token` requires a fresh signature over canonical({identity, device, ts}) with that key (60 s replay window: stale -> `proof_stale`, wrong key -> `bad_proof`, missing -> `proof_required`). Verified: probe 1 -> `proof_required`. Tests: `test_07` step 3b. |
| I2 | `/disable` and `/enable` callable without credentials (token issuance could be toggled) | exploited | Routes REMOVED: identity disabling is a registry-policy concern (nodes enforce the policy `disabled` list); the IdP no longer exposes it. Verified: probe 2 -> 404. |
| I3 | First-claim registration lets a caller claim any unregistered name | by design, now documented | Registration requires a device ML-DSA public key; claiming a fresh name means registering YOUR OWN device key (standard open bootstrap). The operator pre-registers all legitimate identities at startup, and first-write-wins blocks later takeover of a claimed name. A closed-registration mode is future work. |

Also added: `tokens.device_proof()` / `verify_device_proof()` (src/tokens.py);
the demo and networked tests now run the full PoP flow end-to-end
(register with device key -> PoP token -> authenticated registry +
messaging operations).

## Round 6 - proof replay + token lifetime (fifth-pass audit)

| # | Finding (verified) | Fix |
|---|--------------------|-----|
| R1 | A valid device proof could be REPLAYED within its 60 s freshness window; each replay minted a fresh token | Device proofs are now SINGLE-USE: the IdP keeps a consumed-proof ledger (entries expire with the window); a replayed proof is refused with `proof_replayed` - each proof grants exactly one token. The ledger digest now covers only the SIGNED fields plus the signature, so changing unsigned fields cannot bypass it. Test: `test_07` steps 3c and 3c-2. |
| R2 | `ttl_s` was not part of the signed proof and was passed to issuance UNCAPPED: a replayed proof could mint a 24-hour token | `ttl_s` is now treated as attacker-controlled input and CAPPED server-side at `MAX_TOKEN_TTL_S = 3600` (floor 1 s, non-numeric/non-finite -> default 60). Verified: a `ttl_s=86400` request returns a token whose payload `exp - iat <= 3601`. Combined with signed-field replay tracking, no replay path yields a long-lived token. Test: `test_07` step 3d. |

Note: the TTL cap applies to every issued token including the demo's
(900 s) - within the cap. The consumed-proof ledger lives in the IdP's
RAM; a process restart clears it, but proofs also expire after 60 s, so
the replayable window after a restart is bounded by the freshness window
(documented).

## Round 7 - unsigned-field replay + future iat (sixth-pass audit)

| # | Finding (reproduced) | Fix |
|---|----------------------|-----|
| S1 | The consumed-proof digest covered the FULL request body. Replaying a used proof with `ttl_s: 120` and `clock_skew: 86400` changed the digest and minted a second token | `tokens.device_proof_core()` exposes the exact signed fields (`identity`, `device`, `ts`); `_consume_proof()` hashes those fields plus `proof`. The tweaked replay now returns `proof_replayed`. Test: `test_07` step 3c-2. |
| S2 | `clock_skew` was passed to `tokens.issue()`, putting `iat` 86,400 s in the future; `tokens.verify()` checked only `exp` | The IdP ignores client `clock_skew` entirely; `iat`/`exp` use the service's real clock. `tokens.verify()` rejects `iat > now + 60 s` with `token_not_yet_valid` for every verifier. Tests: `test_07` step 3e (IdP token has `iat ~= now`; future-dated token denied by node-a). |

Residual limitation: the consumed-proof ledger is still in RAM. A production
IdP should persist consumed-proof digests; here the residual replay window
after a restart is bounded by the 60 s proof freshness window.

## Verification

`python3 -m unittest discover -s tests` - **108 tests, all passing**,
plus `python3 demo_networked.py` with **69/69 checks** and
`all_checks_pass = true`. See `docs/full_test_suite_after.txt` and
`docs/demo_networked_output.json`.
