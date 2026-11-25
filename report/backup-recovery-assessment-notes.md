# Security Assessment Notes — Backup & Recovery Module (Member 3)

*(Contribution to the team's Project 04 Security Assessment Report, Sec. 9)*

## 1. Purpose & Protected Assets
- **Assets Protected:** Synthetic student vault files (`sandbox_root`), immutable encrypted multi-version backup artifacts (`vault_root`), forensic quarantine copies (`quarantine_root`), metadata/restoration records (`SQLiteMetadataStore`), and key wrapping operations (`KeyProvider`).
- **Trust Boundaries:**
  1. Untrusted caller input / file upload → Server-side `ValidationError` & `SandboxGuard` enforcement.
  2. Live student sandbox files (susceptible to simulated ransomware modification) ↔ Isolated encrypted vault blobs (`SVBK1` AES-256-GCM envelope with AAD binding).
  3. Application runtime ↔ Key Encryption Key (`STUDENT_VAULT_KEK_B64` in environment memory; never persisted in DB or logs).

## 2. Key Controls Implemented
1. **Automatic & Multi-Version Encrypted Backups:** Every upload and authorized edit produces an immutable AES-256-GCM encrypted snapshot with a unique 256-bit DEK wrapped by the active `KeyProvider`.
2. **Ransomware-Aware Threat Lock:** Suspicious alerts from Member 5 lock automatic backups (`ThreatLockError`) so encrypted/corrupted live files cannot overwrite clean backup history.
3. **Cryptographic Integrity Verification:** Constant-time SHA-256 verification across both the live sandbox file and stored ciphertext envelope (detecting both simulated ransomware changes and backup blob corruption).
4. **Integrity-Gated Recovery & Restoration Audit History:** Recovery validates backup integrity *before* touching live files, isolates corrupted live files to `quarantine/` as incident evidence, writes restored files atomically, verifies the post-restore SHA-256, and records every success, integrity failure, and denied access attempt.
5. **Safe Logging & Error Handling:** Structured JSONL events with `correlation_id`, active key/token/payload redaction, and sanitized HTTP 500 error responses.

## 3. Limitations & Environment Caveat
- **Verified Operations:** Local filesystem vault adapter (`LocalVaultStorageAdapter`), local environment KEK wrapping (`LocalEnvKeyProvider`), local SQLite metadata store (`SQLiteMetadataStore`), and JSONL logging (`SecurityEventLogger`).
- **Unverified Cloud Operations:** `FlociS3StorageAdapter` and `CloudKMSKeyProvider` are implemented behind explicit interfaces that **fail closed** until a live Floci / GCP Cloud Storage / Cloud KMS endpoint in the lab workspace is verified with a smoke test.
- **Residual Risks:**
  - In a local single-host sandbox, OS-level processes running under the same OS user could theoretically access `vault_root` unless separated by OS user permissions or remote object storage with IAM write-once/versioning policies.
  - A KEK passed via environment variable protects data at rest on disk/object storage, whereas production deployments should delegate KEK custody to Cloud KMS / HSM with IAM separation.

## 4. Release Recommendation (Member 3 Module)
- **Recommendation:** **Release for local/lab sandbox demonstration with documented conditions** — valid once integrated with Member 1's Flask authentication/2FA session bridge, Member 4's role tests, and Member 5's ransomware simulation alerts, and provided cloud adapters remain labelled local until verified in Floci/GCP.
