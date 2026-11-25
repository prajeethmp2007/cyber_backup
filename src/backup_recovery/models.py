"""Data models and DTOs for the Student Vault Backup & Recovery module.

These models define the shared contract across Member 1 (Backend), Member 2 (Frontend),
Member 4 (Database & Access Control), and Member 5 (Ransomware Detection).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp with microsecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class BackupTrigger(str, Enum):
    """Reason a backup version was created."""

    AUTO_UPLOAD = "auto_upload"
    AUTO_PRE_MODIFY = "auto_pre_modify"
    AUTO_POST_MODIFY = "auto_post_modify"
    AUTO_SCHEDULED = "auto_scheduled"
    MANUAL = "manual"
    PRE_QUARANTINE_CHECK = "pre_quarantine_check"


class IntegrityStatus(str, Enum):
    """Result of verifying a live file and/or its backup snapshot."""

    VERIFIED = "VERIFIED"
    TAMPERED_LIVE_FILE = "TAMPERED_LIVE_FILE"
    CORRUPTED_BACKUP = "CORRUPTED_BACKUP"
    MISSING_LIVE_FILE = "MISSING_LIVE_FILE"
    NO_BACKUP = "NO_BACKUP"
    ERROR = "ERROR"


class RestorationStatus(str, Enum):
    """Outcome of a file version restoration attempt."""

    SUCCESS = "SUCCESS"
    FAILED_INTEGRITY = "FAILED_INTEGRITY"
    DENIED = "DENIED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ActorContext:
    """Authenticated caller identity passed by Member 1 / Member 4 middleware."""

    actor_id: str
    role: str = "student"  # "student", "faculty", "admin", "system_scheduler"
    two_factor_verified: bool = True

    def is_admin(self) -> bool:
        return self.role == "admin"

    def is_system(self) -> bool:
        return self.role == "system_scheduler"


@dataclass
class TrackedFile:
    """Logical student file registered in the Student Vault."""

    file_id: str
    student_id: str
    filename: str
    relative_path: str
    mime_type: str = "application/octet-stream"
    latest_version_number: int = 0
    latest_version_id: str | None = None
    last_known_good_version_id: str | None = None
    last_known_good_sha256: str | None = None
    threat_locked: bool = False
    threat_reason: str | None = None
    threat_alert_id: str | None = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BackupVersion:
    """Immutable metadata record for one encrypted version of a student file."""

    version_id: str
    file_id: str
    student_id: str
    filename: str
    version_number: int
    trigger_reason: str
    plaintext_sha256: str
    encrypted_sha256: str
    size_bytes: int
    encrypted_size_bytes: int
    storage_backend: str
    storage_key: str
    key_id: str
    encryption_algorithm: str = "AES-256-GCM"
    is_known_good: bool = True
    is_pinned: bool = False
    deduplicated_from_version_id: str | None = None
    correlation_id: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    status: str = "ACTIVE"  # ACTIVE, CORRUPTED, PRUNED

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IntegrityReport:
    """Structured result of integrity verification (live file and/or stored backup)."""

    check_id: str
    correlation_id: str
    file_id: str
    student_id: str
    version_id: str | None
    version_number: int | None
    status: IntegrityStatus
    live_file_exists: bool
    live_sha256: str | None
    expected_plaintext_sha256: str | None
    backup_blob_intact: bool
    expected_encrypted_sha256: str | None
    observed_encrypted_sha256: str | None
    hash_match: bool
    details: str
    checked_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class RestorationRecord:
    """Audit record for a version recovery attempt (Restoration History)."""

    restoration_id: str
    correlation_id: str
    file_id: str
    student_id: str
    filename: str
    restored_version_id: str | None
    restored_version_number: int | None
    actor_id: str
    trigger_source: str  # "manual_recovery", "ransomware_recovery", "rollback"
    pre_restore_live_sha256: str | None
    restored_sha256: str | None
    expected_known_good_sha256: str | None
    verification_passed: bool
    quarantine_evidence_path: str | None
    status: RestorationStatus
    error_code: str | None = None
    notes: str = ""
    restored_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class AutoBackupSweepResult:
    """Summary returned by automatic scheduled backup sweeps."""

    correlation_id: str
    scanned_files: int
    backups_created: int
    unchanged_skipped: int
    threat_skipped: int
    drift_detected_files: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    completed_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
