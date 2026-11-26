"""Track 4 "Trust, but verify" - source package.

Modules:
    state      - persistence (atomic writes + durable journal), simulated clock
    crypto     - vetted-library primitives (ML-KEM-768, ML-DSA-65, HKDF, AES-GCM)
    audit      - hash-chained, ML-DSA-signed, injection-proof audit log
    access     - identity / access-control decisions
    keys       - key rotation (cutoff + grace), multi-node revocation, re-enrolment
    recovery   - crash recovery via journal replay; signed backup/restore
    messaging  - E2E sessions: forward secrecy, replay/reorder/loss, resumption
    detector   - deterministic rule-based anomaly & lateral-movement detection
    dispatch   - op registry -> single entry point dispatch(request)
    demo       - scripted end-to-end demonstration
"""

__version__ = "2.0.0"
