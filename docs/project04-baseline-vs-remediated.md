# Project 04 — Baseline Assessment vs. Remediated Controls

## 1. Workflow Flow (Project 04 Sec. 3)

`Synthetic input/event → Validate → Apply security control → Store/process safely → Verify outcome → Record evidence`

## 2. Task B — Baseline Findings (Before Controls)

Running `backup_recovery.baseline_demo.run_unprotected_baseline_demo()` demonstrates what happens in a student portal without Backup & Recovery controls:
- **F01 (High):** No pre-modification SHA-256 digest is recorded; simulated ransomware-style alteration goes undetected.
- **F02 (High):** No isolated encrypted multi-version backup exists; original student document cannot be recovered after modification.
- **F03 (Medium):** No restoration or integrity audit trail exists for incident investigation.

## 3. Task C–E — Remediated Controls & Required Test Matrix (T01–T08)

| Test ID | Project 04 Requirement | Implemented Control | Evidence File (`evidence/`) |
|---|---|---|---|
| **T01** | Original file hash is recorded before modification | `register_and_backup_upload` + `update_file_with_auto_backup` record `plaintext_sha256` and `encrypted_sha256` in SQLite metadata & JSONL logs | `T01-original-hash-recorded.json` |
| **T02** | Benign change causes integrity comparison to fail | `verify_integrity` detects SHA-256 mismatch (`TAMPERED_LIVE_FILE`) while confirming stored encrypted blob integrity | `T02-integrity-mismatch-detected.json` |
| **T03** | Recovery copy matches the known-good hash | `recover_version` verifies encrypted package (AES-256-GCM + AAD), quarantines tampered file, writes atomically, re-hashes disk output (`SUCCESS`) | `T03-recovery-hash-verified.json` |
| **T04** | Only designated test data is changed | `SandboxGuard` confines paths to student sandbox and blocks `../` traversal; sibling file SHA-256 remains unchanged | `T04-sandbox-isolation-verified.json` |
| **T05** | Logs document detection and recovery | `SecurityEventLogger` logs structured `BACKUP_CREATED`, `INTEGRITY_ALERT`, `FILE_RECOVERED` with `correlation_id` | `T05-security-logs.jsonl`, `T05-log-verification.json` |
| **T06** | Trigger a controlled unexpected error | `BackupAPIController` catches unexpected exceptions and returns HTTP 500 `INTERNAL_ERROR` + `correlation_id` without leaking internals | `T06-controlled-error-safe-response.json` |
| **T07** | Inspect source, output and logs for sensitive data | `scripts/secret_scan.py` scans `src/`, `tests/`, `evidence/`, `docs/`, `report/` with 0 findings | `T07-sensitive-data-scan.json` |
| **T08** | Repeat the complete test set | Reproducible via `pytest -v` and `python scripts/run_project04_evidence.py` with Environment Caveat documented | `T08-test-matrix-summary.json` |
