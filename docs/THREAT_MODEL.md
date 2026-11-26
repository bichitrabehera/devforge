# Threat Model — Track 4 prototype

## Protected assets

1. **Protected messages** (E2E encrypted between identities) — confidentiality,
   integrity, freshness (replay protection), recipient binding.
2. **Key material** — service ML-DSA signing key, ML-KEM key versions
   (current + grace), per-session ephemeral KEM secrets, session keys,
   resumption secrets.
3. **Access-control state** — owners, roles, disabled actors, revoked
   devices, revocation epochs.
4. **Audit log** — the integrity and non-repudiation of every recorded
   decision (actor, action, asset, decision, free-text detail).
5. **Backups** — integrity (only verified key material is ever restored) and
   availability after disk loss.
6. **Detection quality** — the operator's view of alerts must be
   injectable-proof and explainable.

## Attackers considered

| Attacker | Capabilities | Modelled by |
|---|---|---|
| **Malicious client** | valid credentials, tries access outside its role scope, tries to use other identities' sessions, replays/tamfers with messages, injects log text | `TestMessaging` (replay, binding, tamper), detector lateral-movement rules |
| **Insider privilege escalator** | legitimate account attempting unapproved role changes and exploiting them | detector rules `unexpected_role_change`, `review_after_role_change` |
| **Service account abuser** | valid service credentials traversing unusual service paths (valid credentials, wrong path) | detector `lateral_movement` (burst of unknown edges) |
| **Network attacker** | drops, reorders, replays, modifies messages in transit | delivery under loss/reordering + AEAD authentication |
| **Local file attacker** | can read/modify the state file, journal, backups | atomic writes, signed journal-free state, signed backups, tamper-evident log |
| **Compromised long-term key (later)** | attacker obtains a party's long-term ML-DSA/ML-KEM key **after** sessions completed | forward secrecy via ephemeral session KEM keys, zeroized before/after |
| **Stolen device** | device with its keys is lost/stolen | device revocation with per-node propagation; owner re-enrolment |

## Assumptions

- The host running the service is not compromised during operation (the
  process's own memory is trusted while it runs); we protect against
  on-disk tampering, not live memory disclosure.
- The organizer's `approvals.json` is an authentic authorization source.
- The service's ML-DSA private key is generated on first `setup` and never
  leaves the process; **it is not journaled** — recovering from total disk
  loss requires a previously created signed backup.
- The simulated clock and two-node delays are a faithful stand-in for real
  propagation; events carry monotonic true time modulo documented offsets.
- Backup storage is access-controlled; backups are signed but not
  encrypted at rest.

## Limits (honest boundaries)

- Both messaging endpoints live in one process — a real deployment splits
  them; the crypto design does not depend on this.
- Resumption secrets persist until the next resume; exposure of a session's
  *resumption* secret breaks that session's future resumption (documented),
  but never its past messages.
- The detector's service graph and role scopes are static, documented
  constants; new legitimate edges must be added to the model (fail-closed:
  unknown edges raise alerts or annotations, not silence).
- The audit log is unbounded in state; segment sealing/archival is future work.
- No protection against DoS or traffic analysis; out of scope for the
  sandbox.

## What is explicitly out of scope

Attacks against other teams or shared services, DoS, and any AI/ML-based
detection (rules only, by design).
