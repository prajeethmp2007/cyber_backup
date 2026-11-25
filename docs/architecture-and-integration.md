# Architecture & Team Integration Guide (Backup & Recovery — Member 3)

This guide explains how **Member 3's Backup & Recovery module** connects with **Member 1 (Backend/Flask)**, **Member 2 (Frontend)**, **Member 4 (Database/Security/Testing)**, and **Member 5 (Ransomware Module)**, aligned with **Project 04 (Ransomware Rescue: Recover the Student Vault)** and **PDF 2 (Infrastructure Setup Guide)**.

---

## 1. Architecture & Trust Boundaries

```text
[Member 2 Frontend]
       │  HTTPS / JSON (Session + 2FA token)
       ▼
[Member 1 Flask App] ──► Auth + 2FA Check (ActorContext)
       │
       ├──► [Member 5 Ransomware Monitor] ──► Threat Alerts / change_validator
       │                                              │
       ▼                                              ▼
[Member 3 BackupAPIController / BackupRecoveryService]
  ├── Path Validation        ──► SandboxGuard (confined to sandbox_root / vault_root / quarantine_root)
  ├── Hashing                ──► Streaming SHA-256 + hmac.compare_digest
  ├── Envelope Encryption    ──► AES-256-GCM per-backup DEK wrapped by KeyProvider (env/KMS)
  ├── Storage Backend        ──► LocalVaultStorageAdapter (or verified FlociS3StorageAdapter)
  ├── Metadata Repository    ──► SQLiteMetadataStore (swappable with Member 4 DB via MetadataStore ABC)
  └── Security Event Logger  ──► Sanitized JSONL logs (correlation_id, zero secrets/payloads)
```

### Key Security Invariants
1. **Deny-by-Default Ownership:** Every operation validates `ActorContext(actor_id, role, two_factor_verified)`. Cross-student access and unknown roles fail closed (`403 ACCESS_DENIED`).
2. **2FA Gate on Recovery:** When `require_2fa_for_recovery=True` (default), `recover_version()` requires `actor.two_factor_verified == True`.
3. **Ransomware Backup Poisoning Prevention:** When Member 5 flags a file via `flag_threat_lock()` or `handle_ransomware_alert()`, `create_backup()` rejects new automatic backups (`409 THREAT_LOCK_ACTIVE`), protecting known-good versions from being buried or replaced by encrypted junk.
4. **Integrity-Gated Atomic Recovery:** Before touching the live file, recovery verifies the stored backup's SHA-256, AES-GCM header AAD, wrapped DEK, and decrypted payload SHA-256. Tampered live files are copied to `quarantine/` for incident evidence, and the verified copy is written atomically (`mkstemp` + `fsync` + `os.replace`) and re-hashed.
5. **Environment Caveat Honesty:** `LocalVaultStorageAdapter` and `LocalEnvKeyProvider` are verified locally. `FlociS3StorageAdapter` and `CloudKMSKeyProvider` fail closed unless a verified endpoint client is explicitly supplied and smoke-tested.

---

## 2. Connecting to Member 1 (Backend Development — Flask)

Member 1 does **not** need to rewrite any encryption, versioning, or recovery logic. Mount the pre-built Flask Blueprint from `backup_recovery.api_adapter`.

### Step 1: Add `src/` to `PYTHONPATH` (or install editable) and install `Flask`
```bash
pip install Flask cryptography
```

### Step 2: Wire Blueprint & Auth Bridge in Member 1's `app.py`
```python
import sys
from pathlib import Path
from flask import Flask, g, session

# Point to Member 3's package
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from backup_recovery import (
    ActorContext,
    BackupRecoveryService,
    VaultConfig,
    create_backup_blueprint,
)

app = Flask(__name__)

# Load configuration & KEK from environment variables (NEVER hardcode secrets)
vault_config = VaultConfig.from_env(default_base_dir="./runtime_vault")
backup_service = BackupRecoveryService(
    vault_config,
    # Optional: plug Member 5's anomaly detector here
    # change_validator=ransomware_module.is_authorized_change,
)

def get_current_actor() -> ActorContext:
    """Bridge Member 1's Flask session / JWT + 2FA state into Member 3's ActorContext."""
    user_id = session.get("user_id") or getattr(g, "user_id", "")
    role = session.get("role") or getattr(g, "role", "")
    two_fa_ok = bool(session.get("two_factor_verified", False))
    return ActorContext(
        actor_id=str(user_id),
        role=str(role),
        two_factor_verified=two_fa_ok,
    )

# Registers all 16 endpoints under /api/backup/*
app.register_blueprint(create_backup_blueprint(backup_service, get_current_actor))
```

### Step 3: Trigger Automatic Backups from Member 1's Existing File Routes
If Member 1 has an existing `/api/files/upload` or `/api/files/save` route outside the blueprint, call the service directly:
- On upload: `backup_service.register_and_backup_upload(actor, student_id=..., filename=..., content=file_bytes)`
- On file edit: `backup_service.update_file_with_auto_backup(actor, file_id=..., new_content=new_bytes)`
- Scheduled background sweep (APScheduler / cron / thread):
  ```python
  system_actor = ActorContext(actor_id="system_scheduler", role="system_scheduler", two_factor_verified=True)
  backup_service.run_scheduled_backup_sweep(system_actor)
  ```

---

## 3. Connecting to Member 2 (Frontend Development)

All endpoints return a consistent JSON envelope:
- Success: `{ "ok": true, "correlation_id": "corr_...", "data": { ... } }`
- Error: `{ "ok": false, "correlation_id": "corr_...", "error": { "code": "...", "message": "..." } }`

### Page-by-Page API Mapping

| Member 2 UI Page | Method & Endpoint | Request Body / Query | Key Response Fields (`data`) |
|---|---|---|---|
| **Student Dashboard** | `GET /api/backup/dashboard` | `?student_id=...` | `total_files`, `total_backup_versions`, `threat_locked_files`, `total_restorations`, `successful_restorations`, `recent_integrity_alerts`, `last_backup_at`, `storage_backend`, `key_provider` |
| **My Files** | `GET /api/backup/files` | `?student_id=...` | `files[]`: `file_id`, `filename`, `relative_path`, `latest_version_number`, `last_known_good_sha256`, `threat_locked`, `threat_alert_id`, `updated_at` |
| **My Files (Upload)** | `POST /api/backup/upload` | `multipart/form-data` (`file`) or JSON `{student_id, filename, content_b64}` | `tracked_file`, `version` (`v1`), `created: true` |
| **My Files (Manual Backup)** | `POST /api/backup/create` | `{ "file_id": "...", "trigger_reason": "manual" }` | `version`, `created`, `reason` |
| **My Files (Verify Integrity)** | `POST /api/backup/verify/<file_id>` | `{}` or `{ "version_id": "..." }` | `status` (`VERIFIED`, `TAMPERED_LIVE_FILE`, `CORRUPTED_BACKUP`, `MISSING_LIVE_FILE`), `hash_match`, `live_sha256`, `expected_plaintext_sha256`, `backup_blob_intact` |
| **Backup History** | `GET /api/backup/history` | `?student_id=...&limit=100` | `backups[]`: `version_id`, `file_id`, `filename`, `version_number`, `trigger_reason`, `plaintext_sha256`, `size_bytes`, `storage_backend`, `is_known_good`, `is_pinned`, `status`, `created_at` |
| **Recovery Center (Versions)** | `GET /api/backup/versions/<file_id>` | `?include_pruned=false` | `versions[]` (newest first) |
| **Recovery Center (Pin)** | `POST /api/backup/versions/<file_id>/<version_id>/pin` | `{ "pinned": true }` | `version` |
| **Recovery Center (Restore)** | `POST /api/backup/recover` | `{ "file_id": "...", "version_id": "latest_verified" \| "ver_...", "quarantine_corrupted": true, "target_relative_path": null }` | `restoration_id`, `restored_version_number`, `pre_restore_live_sha256`, `restored_sha256`, `verification_passed`, `quarantine_evidence_path`, `status` |
| **Recovery Center (History)** | `GET /api/backup/restorations` | `?student_id=...&file_id=...` | `restorations[]` (audit history of all successes, failed integrity checks, and denied attempts) |
| **Threat Monitoring** | `GET /api/backup/events` & `POST /api/backup/verify-all` | `?student_id=...` | `events[]` (sanitized alerts), `reports[]` |
| **Profile & Settings** | `GET /api/backup/status` | none | `storage`, `key_provider`, `max_versions_per_file`, `max_file_size_bytes`, `require_2fa_for_recovery` |

---

## 4. Connecting to Member 4 (Database, Security & Testing)

### Database Schema (`src/backup_recovery/metadata_store.py`)
Member 3 provides `MetadataStore` (ABC) and a parameterized `SQLiteMetadataStore` with 4 tables:
1. `tracked_files` — `file_id` (PK), `student_id`, `filename`, `relative_path`, `latest_version_number`, `latest_version_id`, `last_known_good_version_id`, `last_known_good_sha256`, `threat_locked`, `threat_reason`, `threat_alert_id`.
2. `backup_versions` — `version_id` (PK), `file_id` (FK), `student_id`, `version_number` (`UNIQUE(file_id, version_number)`), `trigger_reason`, `plaintext_sha256`, `encrypted_sha256`, `size_bytes`, `encrypted_size_bytes`, `storage_backend`, `storage_key`, `key_id`, `encryption_algorithm`, `is_known_good`, `is_pinned`, `correlation_id`, `status`.
3. `integrity_checks` — `check_id` (PK), `correlation_id`, `file_id`, `student_id`, `version_id`, `status`, `live_sha256`, `expected_plaintext_sha256`, `backup_blob_intact`, `hash_match`, `checked_at`.
4. `restoration_history` — `restoration_id` (PK), `correlation_id`, `file_id`, `student_id`, `restored_version_id`, `restored_version_number`, `actor_id`, `trigger_source`, `pre_restore_live_sha256`, `restored_sha256`, `verification_passed`, `quarantine_evidence_path`, `status`, `error_code`, `restored_at`.

To migrate to PostgreSQL / MySQL / Firestore, Member 4 implements the `MetadataStore` abstract base class and passes it into `BackupRecoveryService(config, metadata_store=custom_store)`.

### Security & Testing Checklist for Member 4
- Run `pytest tests/test_security_and_access.py` to test cross-student unauthorized reads/restores, unknown roles, missing 2FA, disallowed extensions, and path traversal (`../`).
- Run `python scripts/secret_scan.py` to verify T07 (zero secrets, private keys, tokens, or connection strings in source, tests, or logs).
- Note: Never log `STUDENT_VAULT_KEK_B64` or pass it in API responses.

---

## 5. Connecting to Member 5 (Ransomware Module)

Member 5 can connect in two complementary ways:

### Option A — Direct Python Service Integration (Recommended inside Flask)
When Member 5's file monitor detects suspicious entropy spikes, mass renames, or unauthorized modification inside `sandbox_root`:
```python
from backup_recovery import ActorContext

system_actor = ActorContext(actor_id="ransomware_detector", role="system_scheduler", two_factor_verified=True)

result = backup_service.handle_ransomware_alert(
    system_actor,
    student_id="stu_demo_001",
    affected_file_ids=["file_lab_001"],
    alert_id="alert_ransom_001",
    reason="Suspicious rapid modification detected on sandbox copy",
    auto_recover=True,  # Set False to lock & alert only; True to quarantine + auto-restore
)
```
What happens automatically:
1. `flag_threat_lock()` freezes new automatic backups for `file_lab_001`.
2. `verify_integrity()` compares the live file SHA-256 against `last_known_good_sha256` and verifies the stored encrypted backup blob.
3. If `auto_recover=True` and tampering is confirmed (`TAMPERED_LIVE_FILE`), the tampered file is copied to `quarantine_root/<student_id>/` as forensic incident evidence and the verified backup is restored atomically.

### Option B — HTTP Endpoint Integration
Call `POST /api/backup/threat-alert` with:
```json
{
  "student_id": "stu_demo_001",
  "affected_file_ids": ["file_lab_001"],
  "alert_id": "alert_ransom_001",
  "reason": "Simulated ransomware entropy anomaly",
  "auto_recover": false
}
```
And always build ransomware simulations using **benign text modifications on disposable sandbox copies only** (Project 04 Scope & Safety Rules).
