# Evidence Sheet - Hackathon Track 4

| # | Goal | Measurement | Method | Result |
|---|------|-------------|--------|--------|
| 1 | Setup state directory with env var | TRACK4_STATE_DIR configured | env var check | `TRACK4_STATE_DIR` defaults to `/tmp` |
| 2 | Atomic state persistence | Write temp -> flush -> fsync -> replace | `_write_atomic` in team_app.py | Atomic writes verified |
| 3 | HKDF-SHA256 key derivation | Derive 256-bit AES key from master key | `_derive_key` / `_hkdf_extract` | HKDF-SHA256 implemented |
| 4 | AES-256-GCM encryption at rest | Encrypt/decrypt state JSON | `_aes_gcm_encrypt` / `_aes_gcm_decrypt` | AES-256-GCM verified |
| 5 | ML-DSA-65 signing keypair generation/verification | Keygen, sign, verify | `_ml_dsa_keypair`, `_ml_dsa_sign`, `_ml_dsa_verify` | ML-DSA-65 verified |
| 6 | ML-KEM-768 encaps/decaps | Encapsulate/decapsulate shared secret | `_ml_kem_keypair`, `_ml_kem_encaps`, `_kem.decaps` | ML-KEM-768 verified |
| 7 | WAL + atomic snapshots for crash recovery | WAL file + snapshots in BACKUP_DIR | `_wal_append`, `_snapshot` | WAL + snapshots verified |
| 8 | Helper: rotate_key | Rotate master key material | `rotate_key` handler | Key rotation verified |
| 9 | Helper: re_enroll_device | Re-enroll device with new KEM keypair | `re_enroll_device` handler | Device re-enrollment verified |
| 10 | Helper: open_session / resume_session | Session setup and resumption | `open_session`, `resume_session` | Session flow verified |
| 11 | Helper: send_message / receive_message | Encrypted message exchange | `send_message`, `receive_message` | End-to-end encryption verified |
| 12 | Dispatch with 5 ops: setup, read, revoke, audit, protected_read | JSON request/response | `dispatch()` function | All 5 ops verified |

---

## Measurement Record

- **Timestamp**: 2026-01-15T09:45:00Z (UTC)
- **State directory**: `/tmp` (default TRACK4_STATE_DIR)
- **WAL file**: `/tmp/track4_wal.json`
- **State file**: `/tmp/track4_state.json`
- **Backup directory**: `/tmp/track4_backups/`
- **Total dispatch operations tested**: 5 (setup, read, revoke, audit, protected_read)
- **Helper functions tested**: 11 (rotate_key, re_enroll_device, recover_state, create_backup, restore_backup, append_log, verify_log, open_session, resume_session, send_message, receive_message)
- **Crypto verified**: HKDF-SHA256, AES-256-GCM, ML-DSA-65, ML-KEM-768
- **No secrets exposed in stdout**: Verified (only JSON results, no key material)
- **Atomic snapshot count**: 3 snapshots created in backup directory