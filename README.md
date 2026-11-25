# Student Vault — Backup & Recovery Module (Member 3)

**Project Reference:** MindMatrix Project 04 (*Ransomware Rescue — Recover the Student Vault*) & *Infrastructure Setup Guide* (PDF 2).  
**Scope:** Defensive backup creation, multi-versioning, encrypted storage, SHA-256 + AEAD integrity verification, verified recovery, and restoration audit history for synthetic student vault files.

---

## 1. Workspace Structure (Infrastructure Setup Guide Sec. 5)

```text
cyber_backup_project/
├── README.md
├── requirements.txt
├── docs/
│   ├── architecture-and-integration.md   # How Members 1, 2, 4, and 5 connect
│   ├── project04-baseline-vs-remediated.md
│   └── changelog.md
├── src/
│   └── backup_recovery/                  # Core Member 3 Python package
│       ├── config.py
│       ├── crypto.py                     # AES-256-GCM envelope encryption + AAD binding
│       ├── exceptions.py                 # Safe non-leaking domain exceptions
│       ├── hashing.py                    # Streaming SHA-256 + constant-time compare
│       ├── key_management.py             # KeyProvider ABC, LocalEnvKeyProvider, CloudKMSKeyProvider
│       ├── metadata_store.py             # Parameterized SQLite MetadataStore + ABC
│       ├── models.py                     # Shared DTOs & ActorContext
│       ├── path_guard.py                 # Sandbox & traversal confinement (T04)
│       ├── security_logging.py           # Sanitized JSONL security event logger (T05/T07)
│       ├── storage_backends.py           # StorageBackend ABC, LocalVaultStorageAdapter, FlociS3StorageAdapter
│       ├── service.py                    # BackupRecoveryService
│       ├── api_adapter.py                # BackupAPIController + Flask Blueprint factory
│       └── baseline_demo.py              # Safe unprotected baseline demo (Task B)
├── scripts/
│   ├── setup_check.py                    # First-run verification -> evidence/setup-check.txt
│   ├── run_project04_evidence.py         # Runs Baseline + T01..T08 -> evidence/
│   └── secret_scan.py                    # T07 source/log secret leakage scanner
├── tests/                                # Pytest unit, security, API, and matrix suites
├── evidence/                             # Sanitized verification artifacts
└── report/
    └── backup-recovery-assessment-notes.md
```

---

## 2. Quickstart & First-Run Verification

1. Install required dependencies (core requires `cryptography` and `pytest`; Member 1's backend also uses `Flask`):
   ```bash
   pip install -r requirements.txt
   ```
2. Run first-run environment verification (PDF 2 Sec. 6):
   ```bash
   python scripts/setup_check.py
   ```
3. Run the automated test suite:
   ```bash
   pytest -v
   ```
4. Generate Project 04 baseline + `T01`–`T08` sanitized evidence:
   ```bash
   python scripts/run_project04_evidence.py
   python scripts/secret_scan.py
   ```

---

## 3. Secret & Key Configuration (Local Sandbox vs Cloud/Floci)

Never commit encryption keys, `.env` files, or credentials to Git or logs.  
When running the service in Member 1's Flask backend, generate an ephemeral/local 256-bit Key Encryption Key (KEK) in your shell session before starting Flask:

```powershell
# PowerShell (local sandbox session only)
$env:STUDENT_VAULT_KEK_B64 = python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
$env:VAULT_BASE_DIR = ".\runtime_vault"
```

### Environment Caveat
- **Verified locally:** `LocalVaultStorageAdapter` (isolated encrypted blob storage with atomic writes) and `LocalEnvKeyProvider` (AES-256-GCM DEK wrapping from `STUDENT_VAULT_KEK_B64`) + `SQLiteMetadataStore` + `SecurityEventLogger`.
- **Unverified / Adapter-only:** `FlociS3StorageAdapter` and `CloudKMSKeyProvider` fail closed until a live Floci/Cloud Storage/KMS endpoint client is injected and verified with a smoke test (`verified=True`).

---

## 4. Team Integration

See [docs/architecture-and-integration.md](docs/architecture-and-integration.md) for full integration instructions, REST API contracts, DB schema, and security hooks for **Member 1 (Flask Backend)**, **Member 2 (Frontend)**, **Member 4 (Database/Security)**, and **Member 5 (Ransomware Module)**.
