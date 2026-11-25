"""Security tests: RBAC ownership, 2FA step-up, path traversal, and log redaction."""

from __future__ import annotations

import json

import pytest

from backup_recovery.exceptions import AccessDeniedError, SandboxViolationError, ValidationError
from backup_recovery.models import ActorContext
from backup_recovery.security_logging import sanitize_value


def test_cross_student_access_denied_and_unknown_role_fail_closed(
    vault_service, student_actor, other_student_actor
):
    vault_service.register_and_backup_upload(
        student_actor,
        student_id="stu_demo_001",
        filename="private.txt",
        content=b"Student 1 private synthetic notes",
        file_id="file_priv",
    )

    # Other student cannot list versions, verify, backup, or recover
    with pytest.raises(AccessDeniedError):
        vault_service.list_file_versions(other_student_actor, file_id="file_priv")

    with pytest.raises(AccessDeniedError):
        vault_service.verify_integrity(other_student_actor, file_id="file_priv")

    with pytest.raises(AccessDeniedError):
        vault_service.recover_version(other_student_actor, file_id="file_priv")

    # Unknown role fails closed
    rogue = ActorContext(actor_id="stu_demo_001", role="guest_rogue", two_factor_verified=True)
    with pytest.raises(AccessDeniedError):
        vault_service.list_student_files(rogue, student_id="stu_demo_001")

    # Missing 2FA blocks recovery
    no_2fa = ActorContext(actor_id="stu_demo_001", role="student", two_factor_verified=False)
    with pytest.raises(AccessDeniedError):
        vault_service.recover_version(no_2fa, file_id="file_priv")

    # Denied events recorded in security log without leaking payloads
    events = vault_service.logger.read_events(event_type="ACCESS_DENIED")
    assert len(events) >= 4
    serialized = json.dumps(events)
    assert "Student 1 private synthetic notes" not in serialized


def test_sandbox_traversal_and_disallowed_extensions_blocked(vault_service, student_actor):
    with pytest.raises(ValidationError):
        vault_service.register_and_backup_upload(
            student_actor,
            student_id="stu_demo_001",
            filename="malware_payload.exe",
            content=b"MZ",
        )

    with pytest.raises(SandboxViolationError):
        vault_service.register_and_backup_upload(
            student_actor,
            student_id="stu_demo_001",
            filename="escape.txt",
            relative_path="../stu_demo_002/escape.txt",
            content=b"escape attempt",
        )


def test_security_logger_redacts_secrets_and_tokens():
    sample = {
        "kek": "super-sensitive-key-bytes",
        "password": "my-secret-password",
        "plaintext": "raw-file-content-must-not-log",
        "plaintext_sha256": "a" * 64,
        "key_id": "local-kek-v1",
        "nested": {"bearer_header": "Bearer " + "AbCdEf1234567890" * 2},
    }
    cleaned = sanitize_value(sample)
    assert cleaned["kek"] == "[REDACTED]"
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["plaintext"] == "[REDACTED]"
    assert cleaned["plaintext_sha256"] == "a" * 64
    assert cleaned["key_id"] == "local-kek-v1"
    assert cleaned["nested"]["bearer_header"] == "[REDACTED_SENSITIVE_PATTERN]"
