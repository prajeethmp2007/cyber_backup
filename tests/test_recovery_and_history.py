"""Tests for integrity verification, version recovery, quarantine preservation, and restoration history."""

from __future__ import annotations

import pytest

from backup_recovery.exceptions import IntegrityVerificationError
from backup_recovery.hashing import sha256_bytes
from backup_recovery.models import IntegrityStatus, RestorationStatus


def test_recover_previous_specific_version_and_restoration_history(vault_service, student_actor):
    v1_bytes = b"Version 1 clean original document"
    v2_bytes = b"Version 2 clean edited document"

    r1 = vault_service.register_and_backup_upload(
        student_actor,
        student_id="stu_demo_001",
        filename="report.txt",
        content=v1_bytes,
        file_id="file_rpt",
    )
    r2 = vault_service.update_file_with_auto_backup(
        student_actor,
        file_id="file_rpt",
        new_content=v2_bytes,
    )

    # Simulate ransomware modifying live file
    live_path = vault_service.guard.resolve_sandbox_path("stu_demo_001", "report.txt")
    live_path.write_bytes(b"CORRUPTED_BY_SIMULATED_RANSOMWARE")

    # Verify detects live file tampering while backup remains intact
    chk = vault_service.verify_integrity(student_actor, file_id="file_rpt")
    assert chk.status == IntegrityStatus.TAMPERED_LIVE_FILE
    assert chk.backup_blob_intact is True
    assert chk.hash_match is False

    # Recover specifically v1 (rollback to an earlier version)
    rec = vault_service.recover_version(
        student_actor,
        file_id="file_rpt",
        version_id=r1.version.version_id,
        quarantine_corrupted=True,
        trigger_source="rollback",
    )
    assert rec.status == RestorationStatus.SUCCESS
    assert rec.verification_passed is True
    assert rec.restored_version_number == 1
    assert rec.restored_sha256 == sha256_bytes(v1_bytes)
    assert live_path.read_bytes() == v1_bytes
    assert rec.quarantine_evidence_path is not None
    quarantine_file = vault_service.config.quarantine_root / rec.quarantine_evidence_path
    assert quarantine_file.read_bytes() == b"CORRUPTED_BY_SIMULATED_RANSOMWARE"

    # Now restore v2 (latest) as a separate recovered copy without touching live v1
    rec_copy = vault_service.recover_version(
        student_actor,
        file_id="file_rpt",
        version_id=r2.version.version_id,
        target_relative_path="report_v2_recovered.txt",
        quarantine_corrupted=False,
    )
    assert rec_copy.status == RestorationStatus.SUCCESS
    copy_path = vault_service.guard.resolve_sandbox_path("stu_demo_001", "report_v2_recovered.txt")
    assert copy_path.read_bytes() == v2_bytes
    assert live_path.read_bytes() == v1_bytes

    # Restoration history contains both entries ordered newest first
    history = vault_service.get_restoration_history(student_actor, student_id="stu_demo_001", file_id="file_rpt")
    assert len(history) == 2
    assert history[0].restored_version_number == 2
    assert history[1].restored_version_number == 1


def test_corrupted_latest_backup_fails_safe_and_falls_back_on_latest_verified(vault_service, student_actor):
    r1 = vault_service.register_and_backup_upload(
        student_actor,
        student_id="stu_demo_001",
        filename="slides.txt",
        content=b"Good v1 content",
        file_id="file_slides",
    )
    r2 = vault_service.update_file_with_auto_backup(
        student_actor,
        file_id="file_slides",
        new_content=b"Good v2 content",
    )

    # Tamper directly with v2 encrypted blob on disk
    blob_v2 = vault_service.guard.resolve_vault_key(r2.version.storage_key)
    raw = bytearray(blob_v2.read_bytes())
    raw[-5] ^= 0xAA
    blob_v2.write_bytes(bytes(raw))

    # Corrupt live file too
    live_path = vault_service.guard.resolve_sandbox_path("stu_demo_001", "slides.txt")
    live_path.write_bytes(b"Tampered live content")

    # Explicit request for corrupted v2 MUST fail without overwriting live file
    with pytest.raises(IntegrityVerificationError):
        vault_service.recover_version(
            student_actor,
            file_id="file_slides",
            version_id=r2.version.version_id,
        )
    assert live_path.read_bytes() == b"Tampered live content"

    # Requesting "latest_verified" automatically skips corrupted v2 and recovers intact v1
    fallback_rec = vault_service.recover_version(
        student_actor,
        file_id="file_slides",
        version_id="latest_verified",
    )
    assert fallback_rec.status == RestorationStatus.SUCCESS
    assert fallback_rec.restored_version_id == r1.version.version_id
    assert live_path.read_bytes() == b"Good v1 content"

    history = vault_service.get_restoration_history(student_actor, student_id="stu_demo_001")
    statuses = [h.status for h in history]
    assert RestorationStatus.FAILED_INTEGRITY in statuses
    assert RestorationStatus.SUCCESS in statuses


def test_handle_ransomware_alert_with_auto_recover(vault_service, student_actor, system_actor):
    original = b"SYNTHETIC_EXAM_PREP_NOTES"
    vault_service.register_and_backup_upload(
        student_actor,
        student_id="stu_demo_001",
        filename="exam_notes.txt",
        content=original,
        file_id="file_exam",
    )
    live_path = vault_service.guard.resolve_sandbox_path("stu_demo_001", "exam_notes.txt")
    live_path.write_bytes(b"LOCKED_BY_RANSOM_SIM")

    res = vault_service.handle_ransomware_alert(
        system_actor,
        student_id="stu_demo_001",
        affected_file_ids=["file_exam"],
        alert_id="alert_auto_01",
        reason="Simulated mass modification",
        auto_recover=True,
    )
    assert len(res["restorations"]) == 1
    assert res["restorations"][0]["status"] == "SUCCESS"
    assert live_path.read_bytes() == original
    tracked = vault_service.metadata.get_tracked_file("file_exam")
    assert tracked is not None and tracked.threat_locked is False
