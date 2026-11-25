"""Tests for JSON API controller contracts (Member 1 & Member 2 integration)."""

from __future__ import annotations

import base64
import json

from backup_recovery.api_adapter import BackupAPIController


def test_api_controller_full_lifecycle_and_controlled_error(
    vault_service, student_actor, other_student_actor
):
    ctrl = BackupAPIController(vault_service)

    status_code, status_body = ctrl.handle_status()
    assert status_code == 200
    assert status_body["ok"] is True
    assert status_body["data"]["storage"]["backend"] == "local_vault_adapter"
    assert status_body["data"]["storage"]["cloud_verified"] is False

    # Upload via base64 JSON payload
    raw_content = b"API uploaded synthetic assignment\n"
    code, up_body = ctrl.handle_upload(
        student_actor,
        payload={
            "student_id": "stu_demo_001",
            "filename": "assignment.txt",
            "file_id": "file_api_1",
            "content_b64": base64.b64encode(raw_content).decode("ascii"),
        },
    )
    assert code == 201
    assert up_body["data"]["version"]["version_number"] == 1

    # Dashboard summary for Student Dashboard page
    code, dash = ctrl.handle_dashboard(student_actor, student_id="stu_demo_001")
    assert code == 200
    assert dash["data"]["total_files"] == 1
    assert dash["data"]["total_backup_versions"] == 1

    # Cross-student API request returns 403 JSON error
    code, denied = ctrl.handle_list_versions(other_student_actor, file_id="file_api_1")
    assert code == 403
    assert denied["ok"] is False
    assert denied["error"]["code"] == "ACCESS_DENIED"

    # Controlled unexpected error (T06): safe 500 with correlation_id, no stack trace
    orig_get = vault_service.metadata.get_tracked_file
    try:
        vault_service.metadata.get_tracked_file = lambda _: (_ for _ in ()).throw(RuntimeError("internal fault"))  # type: ignore[method-assign]
        err_code, err_body = ctrl.handle_verify_integrity(
            student_actor, file_id="file_api_1", correlation_id="corr-api-t06"
        )
    finally:
        vault_service.metadata.get_tracked_file = orig_get  # type: ignore[method-assign]

    assert err_code == 500
    assert err_body["correlation_id"] == "corr-api-t06"
    assert err_body["error"]["code"] == "INTERNAL_ERROR"
    assert "internal fault" not in json.dumps(err_body)
