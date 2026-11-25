"""Reproducible end-to-end Project 04 (Ransomware Rescue) evidence generator.

Executes:
1. Task B: Safe Baseline (unprotected) assessment.
2. Task C–E: Remediated Student Vault workflow covering Required Test Matrix T01–T08.
Saves sanitized evidence artifacts in `evidence/` without committing secrets or live keys.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from backup_recovery.api_adapter import BackupAPIController  # noqa: E402
from backup_recovery.baseline_demo import run_unprotected_baseline_demo  # noqa: E402
from backup_recovery.config import VaultConfig  # noqa: E402
from backup_recovery.exceptions import SandboxViolationError  # noqa: E402
from backup_recovery.hashing import sha256_file  # noqa: E402
from backup_recovery.key_management import LocalEnvKeyProvider  # noqa: E402
from backup_recovery.models import ActorContext, IntegrityStatus, RestorationStatus  # noqa: E402
from backup_recovery.service import BackupRecoveryService  # noqa: E402
from scripts.secret_scan import scan_directories  # noqa: E402


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generate_all_evidence(evidence_dir: Path | None = None) -> dict[str, Any]:
    out_dir = (evidence_dir or (ROOT / "evidence")).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="sv_project04_") as tmp:
        tmp_path = Path(tmp)

        # 1. Baseline (before remediation controls)
        baseline_result = run_unprotected_baseline_demo(tmp_path / "baseline")
        _write_json(out_dir / "baseline-unprotected-run.json", baseline_result)

        # 2. Remediated Student Vault setup (ephemeral in-memory KEK; zero secrets on disk)
        cfg = VaultConfig.from_base_dir(tmp_path / "remediated")
        kek = LocalEnvKeyProvider.ephemeral()
        svc = BackupRecoveryService(cfg, key_provider=kek)
        controller = BackupAPIController(svc)

        student = ActorContext(actor_id="stu_demo_001", role="student", two_factor_verified=True)

        # Create primary disposable file + untouched sibling file (for T04 isolation proof)
        primary_bytes = b"SYNTHETIC_STUDENT_VAULT|student=stu_demo_001|doc=lab_report_v1|status=clean\n"
        sibling_bytes = b"SYNTHETIC_SIBLING_DOC|student=stu_demo_001|doc=notes|untouched=true\n"

        primary_res = svc.register_and_backup_upload(
            student,
            student_id="stu_demo_001",
            filename="lab_report.txt",
            content=primary_bytes,
            file_id="file_lab_001",
            correlation_id="corr-t01-upload",
        )
        sibling_res = svc.register_and_backup_upload(
            student,
            student_id="stu_demo_001",
            filename="sibling_notes.txt",
            content=sibling_bytes,
            file_id="file_sib_002",
            correlation_id="corr-t04-sibling",
        )
        sibling_path = svc.guard.resolve_sandbox_path("stu_demo_001", "sibling_notes.txt")
        sibling_sha_before = sha256_file(sibling_path)

        # Create v2 via authorized update (multi-version demonstration)
        v2_bytes = b"SYNTHETIC_STUDENT_VAULT|student=stu_demo_001|doc=lab_report_v2|status=clean\n"
        v2_res = svc.update_file_with_auto_backup(
            student,
            file_id="file_lab_001",
            new_content=v2_bytes,
            correlation_id="corr-t01-v2",
        )

        # T01 evidence: Original hash recorded before modification
        t01 = {
            "test_id": "T01",
            "description": "Original file SHA-256 hash recorded before modification in encrypted vault.",
            "file_id": "file_lab_001",
            "v1_id": primary_res.version.version_id,
            "v1_plaintext_sha256": primary_res.version.plaintext_sha256,
            "v2_id": v2_res.version.version_id,
            "v2_plaintext_sha256": v2_res.version.plaintext_sha256,
            "v2_encrypted_sha256": v2_res.version.encrypted_sha256,
            "storage_backend": v2_res.version.storage_backend,
            "passed": bool(v2_res.version.plaintext_sha256 and v2_res.version.encrypted_sha256),
        }
        _write_json(out_dir / "T01-original-hash-recorded.json", t01)

        # T02: Benign modification on disposable live copy -> integrity check fails
        live_path = svc.guard.resolve_sandbox_path("stu_demo_001", "lab_report.txt")
        live_path.write_text(
            "SIMULATED_RANSOMWARE_BENIGN_EDIT|file_modified_outside_vault=true\n",
            encoding="utf-8",
        )
        tamper_report = svc.verify_integrity(
            student, file_id="file_lab_001", correlation_id="corr-t02-verify"
        )
        t02 = {
            "test_id": "T02",
            "description": "Benign modification causes SHA-256 integrity comparison to fail.",
            "report": tamper_report.to_dict(),
            "passed": (
                tamper_report.status == IntegrityStatus.TAMPERED_LIVE_FILE
                and not tamper_report.hash_match
                and tamper_report.backup_blob_intact
            ),
        }
        _write_json(out_dir / "T02-integrity-mismatch-detected.json", t02)

        # T03: Recovery copy matches known-good hash
        recovery = svc.recover_version(
            student,
            file_id="file_lab_001",
            version_id="latest_verified",
            quarantine_corrupted=True,
            trigger_source="ransomware_recovery",
            correlation_id="corr-t03-recover",
        )
        post_verify = svc.verify_integrity(
            student, file_id="file_lab_001", correlation_id="corr-t03-reverify"
        )
        t03 = {
            "test_id": "T03",
            "description": "Recovered file matches known-good SHA-256 hash and preserves quarantine copy.",
            "restoration_record": recovery.to_dict(),
            "post_recovery_verification": post_verify.to_dict(),
            "passed": (
                recovery.status == RestorationStatus.SUCCESS
                and recovery.verification_passed
                and recovery.restored_sha256 == v2_res.version.plaintext_sha256
                and post_verify.status == IntegrityStatus.VERIFIED
            ),
        }
        _write_json(out_dir / "T03-recovery-hash-verified.json", t03)

        # T04: Only designated test data is changed (sibling untouched + traversal blocked)
        sibling_sha_after = sha256_file(sibling_path)
        traversal_blocked = False
        try:
            svc.recover_version(
                student,
                file_id="file_lab_001",
                target_relative_path="../../outside_sandbox.txt",
                correlation_id="corr-t04-traversal",
            )
        except SandboxViolationError:
            traversal_blocked = True

        t04 = {
            "test_id": "T04",
            "description": "Only designated sandbox file was modified/recovered; sibling untouched and traversal blocked.",
            "sibling_file_id": sibling_res.tracked_file.file_id,
            "sibling_sha256_before": sibling_sha_before,
            "sibling_sha256_after": sibling_sha_after,
            "sibling_unchanged": sibling_sha_before == sibling_sha_after,
            "path_traversal_blocked": traversal_blocked,
            "passed": (sibling_sha_before == sibling_sha_after) and traversal_blocked,
        }
        _write_json(out_dir / "T04-sandbox-isolation-verified.json", t04)

        # T05: Logs document detection and recovery without secrets/payloads
        events = svc.logger.read_events(limit=50)
        (out_dir / "T05-security-logs.jsonl").write_text(
            "\n".join(json.dumps(e, sort_keys=True) for e in reversed(events)) + "\n",
            encoding="utf-8",
        )
        event_types = {e["event_type"] for e in events}
        t05 = {
            "test_id": "T05",
            "description": "Structured logs record backup, detection, and recovery with correlation IDs.",
            "event_count": len(events),
            "event_types": sorted(event_types),
            "passed": {"BACKUP_CREATED", "INTEGRITY_ALERT", "FILE_RECOVERED"}.issubset(event_types),
        }
        _write_json(out_dir / "T05-log-verification.json", t05)

        # T06: Trigger a controlled unexpected error -> safe response + useful event logged
        orig_get = svc.metadata.get_tracked_file
        try:
            def _boom(_: str) -> Any:
                raise RuntimeError("Simulated internal storage adapter exception: detail omitted from response")

            svc.metadata.get_tracked_file = _boom  # type: ignore[method-assign]
            err_status, err_body = controller.handle_verify_integrity(
                student, file_id="file_lab_001", correlation_id="corr-t06-error"
            )
        finally:
            svc.metadata.get_tracked_file = orig_get  # type: ignore[method-assign]

        err_events = [
            e for e in svc.logger.read_events(limit=10) if e["correlation_id"] == "corr-t06-error"
        ]
        t06 = {
            "test_id": "T06",
            "description": "Controlled unexpected error returns safe sanitized HTTP 500 and logs safe event.",
            "http_status": err_status,
            "response_body": err_body,
            "logged_event": err_events[0] if err_events else None,
            "passed": (
                err_status == 500
                and err_body["error"]["code"] == "INTERNAL_ERROR"
                and "RuntimeError" not in json.dumps(err_body)
                and "Simulated internal storage" not in json.dumps(err_body)
                and len(err_events) == 1
                and err_events[0]["details"].get("exception_class") == "RuntimeError"
            ),
        }
        _write_json(out_dir / "T06-controlled-error-safe-response.json", t06)

        svc.close()

    # T07: Scan source, tests, docs, report, and evidence for sensitive data
    scan_res = scan_directories(
        [ROOT / "src", ROOT / "tests", out_dir, ROOT / "docs", ROOT / "report"],
        exclude_files={ROOT / "scripts" / "secret_scan.py", ROOT / "scripts" / "run_project04_evidence.py"},
    )
    _write_json(out_dir / "T07-sensitive-data-scan.json", scan_res)

    # T08: Matrix summary
    matrix = {
        "project": "Project 04 - Ransomware Rescue (Recover the Student Vault)",
        "module_owner": "Member 3 - Backup & Recovery",
        "environment_caveat": (
            "Verified with local_vault_adapter + local_env_kek_adapter (ephemeral test KEK). "
            "Cloud Storage / Cloud KMS / Floci endpoints are abstracted behind explicitly labelled "
            "adapters and are not claimed as cloud-verified without a live sandbox smoke test."
        ),
        "tests": {
            "T01": t01["passed"],
            "T02": t02["passed"],
            "T03": t03["passed"],
            "T04": t04["passed"],
            "T05": t05["passed"],
            "T06": t06["passed"],
            "T07": scan_res["clean"],
            "T08": all(
                [t01["passed"], t02["passed"], t03["passed"], t04["passed"], t05["passed"], t06["passed"], scan_res["clean"]]
            ),
        },
    }
    _write_json(out_dir / "T08-test-matrix-summary.json", matrix)
    return matrix


def main() -> int:
    summary = generate_all_evidence()
    print(json.dumps(summary, indent=2))
    return 0 if summary["tests"]["T08"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
