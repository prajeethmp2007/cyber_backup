"""Tests for automatic backup creation, multiple file versions, retention, and storage."""

from __future__ import annotations

import pytest

from backup_recovery.config import VaultConfig
from backup_recovery.exceptions import StorageBackendError, ThreatLockError
from backup_recovery.hashing import sha256_bytes
from backup_recovery.key_management import LocalEnvKeyProvider
from backup_recovery.models import BackupTrigger
from backup_recovery.service import BackupRecoveryService
from backup_recovery.storage_backends import FlociS3StorageAdapter


def test_auto_upload_and_multi_version_updates(vault_service, student_actor):
    res1 = vault_service.register_and_backup_upload(
        student_actor,
        student_id="stu_demo_001",
        filename="thesis_draft.md",
        content=b"# Draft v1\nInitial research notes.\n",
        file_id="file_thesis",
    )
    assert res1.created
    assert res1.version.version_number == 1
    assert res1.version.trigger_reason == BackupTrigger.AUTO_UPLOAD.value
    assert res1.version.is_pinned is True

    # Authorized modification triggers pre-check & post-modify snapshot v2
    res2 = vault_service.update_file_with_auto_backup(
        student_actor,
        file_id="file_thesis",
        new_content=b"# Draft v2\nAdded experimental results.\n",
    )
    assert res2.created
    assert res2.version.version_number == 2
    assert res2.version.trigger_reason == BackupTrigger.AUTO_POST_MODIFY.value

    # Duplicate scheduled backup on unchanged file deduplicates cleanly
    res_dup = vault_service.create_backup(
        student_actor,
        file_id="file_thesis",
        trigger_reason=BackupTrigger.AUTO_SCHEDULED.value,
        force=False,
    )
    assert not res_dup.created
    assert res_dup.reason == "unchanged_content_deduplicated"
    assert res_dup.version.version_id == res2.version.version_id

    versions = vault_service.list_file_versions(student_actor, file_id="file_thesis")
    assert [v.version_number for v in versions] == [2, 1]


def test_scheduled_sweep_and_retention_preserves_pinned_and_latest(tmp_path, student_actor, system_actor):
    cfg = VaultConfig.from_base_dir(tmp_path / "ret_vault", max_versions_per_file=3)
    svc = BackupRecoveryService(cfg, key_provider=LocalEnvKeyProvider.ephemeral())
    try:
        svc.register_and_backup_upload(
            student_actor,
            student_id="stu_demo_001",
            filename="notes.txt",
            content=b"version 1",
            file_id="file_notes",
        )
        # Create v2..v5 (v1 is pinned at upload; max_versions_per_file=3)
        for idx in range(2, 6):
            svc.update_file_with_auto_backup(
                student_actor,
                file_id="file_notes",
                new_content=f"version {idx}".encode("utf-8"),
            )

        active = svc.list_file_versions(student_actor, file_id="file_notes", include_pruned=False)
        active_nums = {v.version_number for v in active}
        # Pinned v1 + newest versions remain active; older unpinned v2/v3 pruned
        assert 1 in active_nums
        assert 5 in active_nums
        assert len(active) == 3

        # Modify live file externally and run scheduled sweep
        live_path = svc.guard.resolve_sandbox_path("stu_demo_001", "notes.txt")
        live_path.write_bytes(b"version 6 external authorized edit")
        sweep = svc.run_scheduled_backup_sweep(system_actor, student_id="stu_demo_001")
        assert sweep.scanned_files == 1
        assert sweep.backups_created == 1

        # Second sweep sees unchanged file -> skipped
        sweep2 = svc.run_scheduled_backup_sweep(system_actor, student_id="stu_demo_001")
        assert sweep2.unchanged_skipped == 1
        assert sweep2.backups_created == 0
    finally:
        svc.close()


def test_ransomware_threat_lock_blocks_auto_backup_overwrite(vault_service, student_actor, system_actor):
    v1 = vault_service.register_and_backup_upload(
        student_actor,
        student_id="stu_demo_001",
        filename="project_data.csv",
        content=b"id,score\n1,95\n",
        file_id="file_csv",
    )

    # Simulate ransomware tampering live file + Member 5 triggering threat alert
    live_path = vault_service.guard.resolve_sandbox_path("stu_demo_001", "project_data.csv")
    live_path.write_bytes(b"ENCRYPTED_RANSOM_GARBAGE_BYTES")

    alert_res = vault_service.handle_ransomware_alert(
        system_actor,
        student_id="stu_demo_001",
        affected_file_ids=["file_csv"],
        alert_id="alert_ransom_01",
        reason="Rapid entropy increase detected by Member 5",
        auto_recover=False,
    )
    assert alert_res["integrity_reports"][0]["status"] == "TAMPERED_LIVE_FILE"

    # Attempted automatic backup MUST be blocked so clean v1 is not polluted
    with pytest.raises(ThreatLockError):
        vault_service.create_backup(
            system_actor,
            file_id="file_csv",
            trigger_reason=BackupTrigger.AUTO_SCHEDULED.value,
        )

    # Last known good hash remains untouched v1
    tracked = vault_service.metadata.get_tracked_file("file_csv")
    assert tracked is not None
    assert tracked.last_known_good_sha256 == sha256_bytes(b"id,score\n1,95\n")
    assert tracked.last_known_good_version_id == v1.version.version_id


def test_unverified_floci_adapter_fails_closed():
    floci = FlociS3StorageAdapter(bucket_name="student-vault-demo", endpoint_url="http://localhost:4566")
    assert not floci.is_cloud_verified
    with pytest.raises(StorageBackendError):
        floci.put_object("stu_demo_001/test.svbk", b"encrypted")
