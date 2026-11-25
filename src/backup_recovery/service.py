"""Core Backup & Recovery service for Student Vault (Member 3 + Project 04).

Covers all 6 Member 3 deliverables:
1. Automatic backup creation (on upload, pre-modify, post-modify, scheduled sweep).
2. Multiple file versions (monotonic version numbers, pinning, retention pruning).
3. Backup storage (local encrypted vault adapter + optional cloud/Floci adapter).
4. Backup integrity verification (SHA-256 + AES-256-GCM AEAD tag & AAD validation).
5. Recovery of previous versions (integrity-gated restore, quarantine evidence copy, post-restore hash proof).
6. Restoration history (persistent audit trail + structured security logging).
"""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .config import VaultConfig
from .crypto import decrypt_backup_payload, encrypt_backup_payload
from .exceptions import (
    AccessDeniedError,
    BackupRecoveryError,
    IntegrityVerificationError,
    ResourceNotFoundError,
    ThreatLockError,
    ValidationError,
)
from .hashing import constant_time_hash_equals, sha256_bytes, sha256_file
from .key_management import KeyProvider, LocalEnvKeyProvider
from .metadata_store import MetadataStore, SQLiteMetadataStore
from .models import (
    ActorContext,
    AutoBackupSweepResult,
    BackupTrigger,
    BackupVersion,
    IntegrityReport,
    IntegrityStatus,
    RestorationRecord,
    RestorationStatus,
    TrackedFile,
    utc_now_iso,
)
from .path_guard import SandboxGuard, validate_identifier
from .security_logging import SecurityEventLogger
from .storage_backends import LocalVaultStorageAdapter, StorageBackend

ALLOWED_ROLES = {"student", "faculty", "admin", "system_scheduler"}


def new_id(prefix: str) -> str:
    """Generate a compact collision-resistant synthetic identifier."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


@dataclass(frozen=True)
class BackupCreationResult:
    """Outcome returned when creating or skipping an automatic/manual backup."""

    tracked_file: TrackedFile
    version: BackupVersion
    created: bool
    reason: str
    correlation_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tracked_file": self.tracked_file.to_dict(),
            "version": self.version.to_dict(),
            "created": self.created,
            "reason": self.reason,
            "correlation_id": self.correlation_id,
        }


class BackupRecoveryService:
    """Senior-engineered defensive Backup & Recovery orchestrator."""

    def __init__(
        self,
        config: VaultConfig,
        *,
        key_provider: KeyProvider | None = None,
        storage_backend: StorageBackend | None = None,
        metadata_store: MetadataStore | None = None,
        security_logger: SecurityEventLogger | None = None,
        require_2fa_for_recovery: bool = True,
        change_validator: Callable[[TrackedFile, Path, str], bool] | None = None,
    ) -> None:
        self.config = config
        self.config.ensure_directories()

        self.guard = SandboxGuard(
            sandbox_root=config.sandbox_root,
            vault_root=config.vault_root,
            quarantine_root=config.quarantine_root,
        )
        self.key_provider = key_provider or LocalEnvKeyProvider.from_env()
        self.storage = storage_backend or LocalVaultStorageAdapter(config.vault_root, self.guard)
        self.metadata = metadata_store or SQLiteMetadataStore(config.metadata_db_path)
        self.logger = security_logger or SecurityEventLogger(config.log_file_path)
        self.require_2fa_for_recovery = require_2fa_for_recovery
        self.change_validator = change_validator

    # ------------------------------------------------------------------
    # Authorization & Validation Helpers (Deny-by-default)
    # ------------------------------------------------------------------
    def _authorize_student_scope(
        self,
        actor: ActorContext,
        owner_student_id: str,
        *,
        action: str,
        correlation_id: str,
        file_id: str | None = None,
        allow_system: bool = False,
        require_2fa: bool = False,
    ) -> None:
        if not actor or not actor.actor_id or actor.role not in ALLOWED_ROLES:
            self.logger.log_event(
                event_type="ACCESS_DENIED",
                outcome="DENIED",
                correlation_id=correlation_id,
                actor_id=getattr(actor, "actor_id", "unknown"),
                student_id=owner_student_id,
                file_id=file_id,
                details={"action": action, "reason": "unknown_or_missing_role"},
            )
            raise AccessDeniedError("Authentication or valid role is required.", correlation_id=correlation_id)

        if actor.is_admin() or (allow_system and actor.is_system()):
            return

        if actor.role == "student" and actor.actor_id == owner_student_id:
            if require_2fa and self.require_2fa_for_recovery and not actor.two_factor_verified:
                self.logger.log_event(
                    event_type="ACCESS_DENIED",
                    outcome="DENIED",
                    correlation_id=correlation_id,
                    actor_id=actor.actor_id,
                    student_id=owner_student_id,
                    file_id=file_id,
                    details={"action": action, "reason": "two_factor_required"},
                )
                raise AccessDeniedError(
                    "Two-factor authentication verification is required for recovery.",
                    correlation_id=correlation_id,
                )
            return

        self.logger.log_event(
            event_type="ACCESS_DENIED",
            outcome="DENIED",
            correlation_id=correlation_id,
            actor_id=actor.actor_id,
            student_id=owner_student_id,
            file_id=file_id,
            details={"action": action, "reason": "cross_owner_or_role_forbidden"},
        )
        raise AccessDeniedError(
            "You do not have permission to access or modify this vault resource.",
            correlation_id=correlation_id,
        )

    def _validate_filename_and_extension(self, filename: str) -> str:
        clean = Path(filename).name.strip()
        if not clean or clean in {".", ".."} or "\x00" in clean:
            raise ValidationError("Invalid filename.")
        suffix = Path(clean).suffix.lower()
        if self.config.allowed_extensions and suffix not in self.config.allowed_extensions:
            raise ValidationError(f"Unsupported file extension '{suffix or '(none)'}'.")
        return clean

    def _validate_file_size(self, size_bytes: int) -> None:
        if size_bytes < 0 or size_bytes > self.config.max_file_size_bytes:
            raise ValidationError(
                f"File size exceeds maximum permitted limit ({self.config.max_file_size_bytes} bytes)."
            )

    @staticmethod
    def _atomic_write_bytes(target: Path, data: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_str = tempfile.mkstemp(prefix=".tmp_sandbox_", dir=str(target.parent))
        tmp_path = Path(tmp_str)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, target)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise

    # ------------------------------------------------------------------
    # 1. Automatic Backup Creation & 2. Multiple File Versions
    # ------------------------------------------------------------------
    def register_and_backup_upload(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        filename: str,
        content: bytes,
        relative_path: str | None = None,
        file_id: str | None = None,
        mime_type: str = "application/octet-stream",
        correlation_id: str | None = None,
    ) -> BackupCreationResult:
        """Store an uploaded student file inside the sandbox and create initial backup v1."""
        corr_id = correlation_id or new_id("corr")
        safe_student = validate_identifier(student_id, "student_id")
        self._authorize_student_scope(
            actor, safe_student, action="register_and_backup_upload", correlation_id=corr_id
        )

        safe_filename = self._validate_filename_and_extension(filename)
        if not isinstance(content, (bytes, bytearray)):
            raise ValidationError("File content must be raw bytes.")
        raw_bytes = bytes(content)
        self._validate_file_size(len(raw_bytes))

        rel = relative_path or safe_filename
        sandbox_path = self.guard.resolve_sandbox_path(safe_student, rel)
        self._atomic_write_bytes(sandbox_path, raw_bytes)

        assigned_file_id = validate_identifier(file_id, "file_id") if file_id else new_id("file")
        now = utc_now_iso()
        stored_rel = str(sandbox_path.relative_to((self.config.sandbox_root / safe_student).resolve())).replace("\\", "/")

        existing = self.metadata.get_tracked_file(assigned_file_id)
        if existing and existing.student_id != safe_student:
            raise AccessDeniedError("File ID is already owned by another student.", correlation_id=corr_id)

        tracked = existing or TrackedFile(
            file_id=assigned_file_id,
            student_id=safe_student,
            filename=safe_filename,
            relative_path=stored_rel,
            mime_type=mime_type,
            created_at=now,
            updated_at=now,
        )
        tracked.filename = safe_filename
        tracked.relative_path = stored_rel
        tracked.mime_type = mime_type
        tracked.updated_at = now
        self.metadata.upsert_tracked_file(tracked)

        return self._create_backup_snapshot(
            actor=actor,
            tracked=tracked,
            plaintext=raw_bytes,
            trigger_reason=BackupTrigger.AUTO_UPLOAD.value,
            correlation_id=corr_id,
            force=True,
            pin_version=(tracked.latest_version_number == 0),
        )

    def register_existing_sandbox_file(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        relative_path: str,
        file_id: str | None = None,
        mime_type: str = "application/octet-stream",
        correlation_id: str | None = None,
    ) -> BackupCreationResult:
        """Register a disposable test file already placed in the student sandbox and back it up."""
        corr_id = correlation_id or new_id("corr")
        safe_student = validate_identifier(student_id, "student_id")
        self._authorize_student_scope(
            actor, safe_student, action="register_existing_sandbox_file", correlation_id=corr_id
        )
        sandbox_path = self.guard.resolve_sandbox_path(safe_student, relative_path)
        if not sandbox_path.is_file():
            raise ResourceNotFoundError("Target file does not exist in student sandbox.", correlation_id=corr_id)

        safe_filename = self._validate_filename_and_extension(sandbox_path.name)
        raw_bytes = sandbox_path.read_bytes()
        self._validate_file_size(len(raw_bytes))

        assigned_file_id = validate_identifier(file_id, "file_id") if file_id else new_id("file")
        now = utc_now_iso()
        stored_rel = str(sandbox_path.relative_to((self.config.sandbox_root / safe_student).resolve())).replace("\\", "/")

        tracked = TrackedFile(
            file_id=assigned_file_id,
            student_id=safe_student,
            filename=safe_filename,
            relative_path=stored_rel,
            mime_type=mime_type,
            created_at=now,
            updated_at=now,
        )
        self.metadata.upsert_tracked_file(tracked)
        return self._create_backup_snapshot(
            actor=actor,
            tracked=tracked,
            plaintext=raw_bytes,
            trigger_reason=BackupTrigger.AUTO_UPLOAD.value,
            correlation_id=corr_id,
            force=True,
            pin_version=True,
        )

    def create_backup(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        trigger_reason: str = BackupTrigger.MANUAL.value,
        force: bool | None = None,
        correlation_id: str | None = None,
    ) -> BackupCreationResult:
        """Create a new encrypted version from the live sandbox file.

        If `tracked.threat_locked` is True, refuses automatic backup so ransomware-encrypted
        bytes never overwrite or pollute the clean backup chain.
        """
        corr_id = correlation_id or new_id("corr")
        safe_file_id = validate_identifier(file_id, "file_id")
        tracked = self.metadata.get_tracked_file(safe_file_id)
        if not tracked:
            raise ResourceNotFoundError("Tracked file not found.", correlation_id=corr_id)

        self._authorize_student_scope(
            actor,
            tracked.student_id,
            action="create_backup",
            correlation_id=corr_id,
            file_id=safe_file_id,
            allow_system=True,
        )

        if tracked.threat_locked:
            self.logger.log_event(
                event_type="BACKUP_BLOCKED_THREAT_LOCK",
                outcome="BLOCKED",
                correlation_id=corr_id,
                actor_id=actor.actor_id,
                student_id=tracked.student_id,
                file_id=tracked.file_id,
                details={
                    "trigger_reason": trigger_reason,
                    "threat_alert_id": tracked.threat_alert_id,
                },
            )
            raise ThreatLockError(
                "Automatic/new backups are locked for this file due to an active threat alert; "
                "restore a verified version or release the threat lock first.",
                correlation_id=corr_id,
            )

        sandbox_path = self.guard.resolve_sandbox_path(tracked.student_id, tracked.relative_path)
        if not sandbox_path.is_file():
            raise ResourceNotFoundError("Live sandbox file is missing; cannot create backup.", correlation_id=corr_id)

        raw_bytes = sandbox_path.read_bytes()
        self._validate_file_size(len(raw_bytes))

        effective_force = force if force is not None else (trigger_reason == BackupTrigger.MANUAL.value)
        return self._create_backup_snapshot(
            actor=actor,
            tracked=tracked,
            plaintext=raw_bytes,
            trigger_reason=trigger_reason,
            correlation_id=corr_id,
            force=effective_force,
            pin_version=False,
        )

    def update_file_with_auto_backup(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        new_content: bytes,
        correlation_id: str | None = None,
    ) -> BackupCreationResult:
        """Safely perform an authorized edit with pre-modify backup protection + post-modify snapshot."""
        corr_id = correlation_id or new_id("corr")
        safe_file_id = validate_identifier(file_id, "file_id")
        tracked = self.metadata.get_tracked_file(safe_file_id)
        if not tracked:
            raise ResourceNotFoundError("Tracked file not found.", correlation_id=corr_id)

        self._authorize_student_scope(
            actor,
            tracked.student_id,
            action="update_file_with_auto_backup",
            correlation_id=corr_id,
            file_id=safe_file_id,
        )
        if tracked.threat_locked:
            raise ThreatLockError(
                "File is threat-locked; authorized modifications are paused until recovery.",
                correlation_id=corr_id,
            )

        raw_new = bytes(new_content)
        self._validate_file_size(len(raw_new))

        sandbox_path = self.guard.resolve_sandbox_path(tracked.student_id, tracked.relative_path)
        # Pre-modify snapshot if live file drifted cleanly since last backup
        if sandbox_path.is_file():
            live_bytes = sandbox_path.read_bytes()
            live_sha = sha256_bytes(live_bytes)
            if tracked.last_known_good_sha256 and not constant_time_hash_equals(
                tracked.last_known_good_sha256, live_sha
            ):
                self._create_backup_snapshot(
                    actor=actor,
                    tracked=tracked,
                    plaintext=live_bytes,
                    trigger_reason=BackupTrigger.AUTO_PRE_MODIFY.value,
                    correlation_id=corr_id,
                    force=True,
                    pin_version=False,
                )

        self._atomic_write_bytes(sandbox_path, raw_new)
        return self._create_backup_snapshot(
            actor=actor,
            tracked=tracked,
            plaintext=raw_new,
            trigger_reason=BackupTrigger.AUTO_POST_MODIFY.value,
            correlation_id=corr_id,
            force=True,
            pin_version=False,
        )

    def _create_backup_snapshot(
        self,
        *,
        actor: ActorContext,
        tracked: TrackedFile,
        plaintext: bytes,
        trigger_reason: str,
        correlation_id: str,
        force: bool,
        pin_version: bool,
    ) -> BackupCreationResult:
        plaintext_sha = sha256_bytes(plaintext)

        # Deduplicate unchanged automatic backups if latest active backup has identical hash & exists
        if (
            not force
            and self.config.deduplicate_unchanged_auto
            and tracked.latest_version_id
        ):
            latest = self.metadata.get_backup_version(tracked.latest_version_id)
            if (
                latest
                and latest.status == "ACTIVE"
                and constant_time_hash_equals(latest.plaintext_sha256, plaintext_sha)
                and self.storage.exists(latest.storage_key)
            ):
                self.logger.log_event(
                    event_type="BACKUP_SKIPPED_UNCHANGED",
                    outcome="SKIPPED",
                    correlation_id=correlation_id,
                    actor_id=actor.actor_id,
                    student_id=tracked.student_id,
                    file_id=tracked.file_id,
                    version_id=latest.version_id,
                    details={"trigger_reason": trigger_reason, "version_number": latest.version_number},
                )
                return BackupCreationResult(
                    tracked_file=tracked,
                    version=latest,
                    created=False,
                    reason="unchanged_content_deduplicated",
                    correlation_id=correlation_id,
                )

        next_num = tracked.latest_version_number + 1
        version_id = new_id("ver")
        storage_key = f"{tracked.student_id}/{tracked.file_id}/v{next_num:04d}_{version_id}.svbk"

        package_bytes, encrypted_sha, key_id = encrypt_backup_payload(
            plaintext=plaintext,
            student_id=tracked.student_id,
            file_id=tracked.file_id,
            version_id=version_id,
            version_number=next_num,
            plaintext_sha256=plaintext_sha,
            key_provider=self.key_provider,
        )

        self.storage.put_object(storage_key, package_bytes)

        version = BackupVersion(
            version_id=version_id,
            file_id=tracked.file_id,
            student_id=tracked.student_id,
            filename=tracked.filename,
            version_number=next_num,
            trigger_reason=trigger_reason,
            plaintext_sha256=plaintext_sha,
            encrypted_sha256=encrypted_sha,
            size_bytes=len(plaintext),
            encrypted_size_bytes=len(package_bytes),
            storage_backend=self.storage.backend_name,
            storage_key=storage_key,
            key_id=key_id,
            is_known_good=True,
            is_pinned=pin_version,
            correlation_id=correlation_id,
        )
        self.metadata.add_backup_version(version)

        tracked.latest_version_number = next_num
        tracked.latest_version_id = version_id
        tracked.last_known_good_version_id = version_id
        tracked.last_known_good_sha256 = plaintext_sha
        tracked.updated_at = utc_now_iso()
        self.metadata.upsert_tracked_file(tracked)

        self._enforce_retention(tracked, correlation_id=correlation_id)

        self.logger.log_event(
            event_type="BACKUP_CREATED",
            outcome="SUCCESS",
            correlation_id=correlation_id,
            actor_id=actor.actor_id,
            student_id=tracked.student_id,
            file_id=tracked.file_id,
            version_id=version_id,
            details={
                "version_number": next_num,
                "trigger_reason": trigger_reason,
                "plaintext_sha256": plaintext_sha,
                "encrypted_sha256": encrypted_sha,
                "storage_backend": self.storage.backend_name,
                "size_bytes": len(plaintext),
            },
        )

        return BackupCreationResult(
            tracked_file=tracked,
            version=version,
            created=True,
            reason="backup_created",
            correlation_id=correlation_id,
        )

    def _enforce_retention(self, tracked: TrackedFile, *, correlation_id: str) -> int:
        """Prune oldest unpinned non-known-good-latest versions beyond `max_versions_per_file`."""
        versions = self.metadata.list_backup_versions(tracked.file_id, include_pruned=False)
        active = [v for v in versions if v.status == "ACTIVE"]
        if len(active) <= self.config.max_versions_per_file:
            return 0

        # `active` is ordered newest-first; protect latest, last_known_good, and pinned versions
        protected_ids = {
            tracked.latest_version_id,
            tracked.last_known_good_version_id,
        }
        pruned_count = 0
        # Walk from oldest to newest
        for candidate in reversed(active):
            if len(active) - pruned_count <= self.config.max_versions_per_file:
                break
            if candidate.is_pinned or candidate.version_id in protected_ids:
                continue
            self.storage.delete_object(candidate.storage_key)
            self.metadata.mark_version_status(candidate.version_id, status="PRUNED")
            pruned_count += 1
            self.logger.log_event(
                event_type="BACKUP_VERSION_PRUNED",
                outcome="SUCCESS",
                correlation_id=correlation_id,
                actor_id="system_retention",
                student_id=tracked.student_id,
                file_id=tracked.file_id,
                version_id=candidate.version_id,
                details={"version_number": candidate.version_number},
            )
        return pruned_count

    def run_scheduled_backup_sweep(
        self,
        actor: ActorContext,
        *,
        student_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AutoBackupSweepResult:
        """Automatically verify & back up tracked files for a student or across the vault."""
        corr_id = correlation_id or new_id("corr")
        if student_id:
            safe_student = validate_identifier(student_id, "student_id")
            self._authorize_student_scope(
                actor,
                safe_student,
                action="scheduled_backup_sweep",
                correlation_id=corr_id,
                allow_system=True,
            )
            files = self.metadata.list_tracked_files(safe_student)
        else:
            if not (actor.is_admin() or actor.is_system()):
                raise AccessDeniedError(
                    "Only system scheduler or admin can sweep all students.",
                    correlation_id=corr_id,
                )
            files = self.metadata.list_tracked_files(None)

        result = AutoBackupSweepResult(
            correlation_id=corr_id,
            scanned_files=len(files),
            backups_created=0,
            unchanged_skipped=0,
            threat_skipped=0,
        )

        for tracked in files:
            if tracked.threat_locked:
                result.threat_skipped += 1
                continue
            try:
                sandbox_path = self.guard.resolve_sandbox_path(tracked.student_id, tracked.relative_path)
                if not sandbox_path.is_file():
                    result.drift_detected_files.append(tracked.file_id)
                    result.errors.append({"file_id": tracked.file_id, "error": "MISSING_LIVE_FILE"})
                    continue

                live_sha = sha256_file(sandbox_path)
                if tracked.last_known_good_sha256 and constant_time_hash_equals(
                    tracked.last_known_good_sha256, live_sha
                ):
                    result.unchanged_skipped += 1
                    continue

                # Optional Member 5 anomaly detector hook before backing up changed file
                if self.change_validator and not self.change_validator(tracked, sandbox_path, live_sha):
                    self.flag_threat_lock(
                        ActorContext(actor_id="system_scheduler", role="system_scheduler"),
                        file_id=tracked.file_id,
                        reason="Scheduled sweep detected suspicious unauthorized modification.",
                        correlation_id=corr_id,
                    )
                    result.threat_skipped += 1
                    result.drift_detected_files.append(tracked.file_id)
                    continue

                creation = self.create_backup(
                    ActorContext(actor_id="system_scheduler", role="system_scheduler"),
                    file_id=tracked.file_id,
                    trigger_reason=BackupTrigger.AUTO_SCHEDULED.value,
                    force=False,
                    correlation_id=corr_id,
                )
                if creation.created:
                    result.backups_created += 1
                else:
                    result.unchanged_skipped += 1
            except BackupRecoveryError as exc:
                result.errors.append({"file_id": tracked.file_id, "error": exc.error_code})

        self.logger.log_event(
            event_type="SCHEDULED_BACKUP_SWEEP",
            outcome="SUCCESS",
            correlation_id=corr_id,
            actor_id=actor.actor_id,
            student_id=student_id,
            details={
                "scanned": result.scanned_files,
                "created": result.backups_created,
                "unchanged": result.unchanged_skipped,
                "threat_skipped": result.threat_skipped,
            },
        )
        return result

    def list_file_versions(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        include_pruned: bool = False,
        correlation_id: str | None = None,
    ) -> list[BackupVersion]:
        corr_id = correlation_id or new_id("corr")
        safe_file_id = validate_identifier(file_id, "file_id")
        tracked = self.metadata.get_tracked_file(safe_file_id)
        if not tracked:
            raise ResourceNotFoundError("Tracked file not found.", correlation_id=corr_id)
        self._authorize_student_scope(
            actor, tracked.student_id, action="list_file_versions", correlation_id=corr_id, file_id=safe_file_id
        )
        return self.metadata.list_backup_versions(safe_file_id, include_pruned=include_pruned)

    def pin_version(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        version_id: str,
        pinned: bool = True,
        correlation_id: str | None = None,
    ) -> BackupVersion:
        corr_id = correlation_id or new_id("corr")
        safe_file_id = validate_identifier(file_id, "file_id")
        safe_version_id = validate_identifier(version_id, "version_id")
        tracked = self.metadata.get_tracked_file(safe_file_id)
        if not tracked:
            raise ResourceNotFoundError("Tracked file not found.", correlation_id=corr_id)
        self._authorize_student_scope(
            actor, tracked.student_id, action="pin_version", correlation_id=corr_id, file_id=safe_file_id
        )
        ver = self.metadata.get_backup_version(safe_version_id)
        if not ver or ver.file_id != safe_file_id:
            raise ResourceNotFoundError("Backup version not found for this file.", correlation_id=corr_id)

        self.metadata.set_version_pinned(safe_version_id, pinned=pinned)
        updated = self.metadata.get_backup_version(safe_version_id)
        assert updated is not None
        self.logger.log_event(
            event_type="BACKUP_VERSION_PINNED",
            outcome="SUCCESS",
            correlation_id=corr_id,
            actor_id=actor.actor_id,
            student_id=tracked.student_id,
            file_id=safe_file_id,
            version_id=safe_version_id,
            details={"pinned": pinned},
        )
        return updated

    # ------------------------------------------------------------------
    # 4. Backup Integrity Verification (Project 04 T01 & T02)
    # ------------------------------------------------------------------
    def _verify_backup_blob(self, version: BackupVersion) -> tuple[bool, str | None, bytes | None, str]:
        """Verify stored encrypted artifact integrity without leaking secrets."""
        try:
            package = self.storage.get_object(version.storage_key)
        except ResourceNotFoundError:
            return False, None, None, "Backup artifact missing from vault storage."
        except BackupRecoveryError as exc:
            return False, None, None, exc.safe_message

        observed_enc_sha = sha256_bytes(package)
        if not constant_time_hash_equals(version.encrypted_sha256, observed_enc_sha):
            return (
                False,
                observed_enc_sha,
                None,
                "Stored encrypted backup package SHA-256 mismatch (backup tampered or corrupted).",
            )

        try:
            plaintext = decrypt_backup_payload(
                package=package,
                expected_student_id=version.student_id,
                expected_file_id=version.file_id,
                expected_version_id=version.version_id,
                expected_plaintext_sha256=version.plaintext_sha256,
                key_provider=self.key_provider,
            )
            return True, observed_enc_sha, plaintext, "Encrypted backup verified."
        except IntegrityVerificationError as exc:
            return False, observed_enc_sha, None, exc.safe_message

    def verify_integrity(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        version_id: str | None = None,
        correlation_id: str | None = None,
    ) -> IntegrityReport:
        """Verify both stored backup artifact and live sandbox file against SHA-256 hashes."""
        corr_id = correlation_id or new_id("corr")
        safe_file_id = validate_identifier(file_id, "file_id")
        tracked = self.metadata.get_tracked_file(safe_file_id)
        if not tracked:
            raise ResourceNotFoundError("Tracked file not found.", correlation_id=corr_id)

        self._authorize_student_scope(
            actor,
            tracked.student_id,
            action="verify_integrity",
            correlation_id=corr_id,
            file_id=safe_file_id,
            allow_system=True,
        )

        target_ver_id = version_id or tracked.last_known_good_version_id or tracked.latest_version_id
        if not target_ver_id:
            report = IntegrityReport(
                check_id=new_id("chk"),
                correlation_id=corr_id,
                file_id=tracked.file_id,
                student_id=tracked.student_id,
                version_id=None,
                version_number=None,
                status=IntegrityStatus.NO_BACKUP,
                live_file_exists=False,
                live_sha256=None,
                expected_plaintext_sha256=None,
                backup_blob_intact=False,
                expected_encrypted_sha256=None,
                observed_encrypted_sha256=None,
                hash_match=False,
                details="No backup version exists yet for this file.",
            )
            self.metadata.add_integrity_report(report)
            return report

        safe_ver_id = validate_identifier(target_ver_id, "version_id")
        version = self.metadata.get_backup_version(safe_ver_id)
        if not version or version.file_id != tracked.file_id:
            raise ResourceNotFoundError("Target backup version not found.", correlation_id=corr_id)

        blob_ok, observed_enc_sha, _, blob_msg = self._verify_backup_blob(version)
        if not blob_ok and version.status == "ACTIVE":
            self.metadata.mark_version_status(version.version_id, status="CORRUPTED", is_known_good=False)

        sandbox_path = self.guard.resolve_sandbox_path(tracked.student_id, tracked.relative_path)
        live_exists = sandbox_path.is_file()
        live_sha = sha256_file(sandbox_path) if live_exists else None

        if not blob_ok:
            status = IntegrityStatus.CORRUPTED_BACKUP
            hash_match = False
            details = blob_msg
        elif not live_exists:
            status = IntegrityStatus.MISSING_LIVE_FILE
            hash_match = False
            details = "Backup is intact, but live sandbox file is missing (possible deletion/rename)."
        elif live_sha and constant_time_hash_equals(version.plaintext_sha256, live_sha):
            status = IntegrityStatus.VERIFIED
            hash_match = True
            details = "Live file SHA-256 and encrypted backup match known-good state."
        else:
            status = IntegrityStatus.TAMPERED_LIVE_FILE
            hash_match = False
            details = "Integrity mismatch: live file SHA-256 differs from known-good backup hash."

        report = IntegrityReport(
            check_id=new_id("chk"),
            correlation_id=corr_id,
            file_id=tracked.file_id,
            student_id=tracked.student_id,
            version_id=version.version_id,
            version_number=version.version_number,
            status=status,
            live_file_exists=live_exists,
            live_sha256=live_sha,
            expected_plaintext_sha256=version.plaintext_sha256,
            backup_blob_intact=blob_ok,
            expected_encrypted_sha256=version.encrypted_sha256,
            observed_encrypted_sha256=observed_enc_sha,
            hash_match=hash_match,
            details=details,
        )
        self.metadata.add_integrity_report(report)

        self.logger.log_event(
            event_type="INTEGRITY_VERIFIED" if status == IntegrityStatus.VERIFIED else "INTEGRITY_ALERT",
            outcome="VERIFIED" if status == IntegrityStatus.VERIFIED else status.value,
            correlation_id=corr_id,
            actor_id=actor.actor_id,
            student_id=tracked.student_id,
            file_id=tracked.file_id,
            version_id=version.version_id,
            details={
                "status": status.value,
                "hash_match": hash_match,
                "backup_blob_intact": blob_ok,
                "expected_plaintext_sha256": version.plaintext_sha256,
                "live_sha256": live_sha,
            },
        )
        return report

    def verify_all_files(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        correlation_id: str | None = None,
    ) -> list[IntegrityReport]:
        """Verify integrity of every tracked file belonging to a student."""
        corr_id = correlation_id or new_id("corr")
        safe_student = validate_identifier(student_id, "student_id")
        self._authorize_student_scope(
            actor, safe_student, action="verify_all_files", correlation_id=corr_id, allow_system=True
        )
        files = self.metadata.list_tracked_files(safe_student)
        return [
            self.verify_integrity(actor, file_id=f.file_id, correlation_id=corr_id)
            for f in files
        ]

    # ------------------------------------------------------------------
    # 5. Recovery of Previous Versions & 6. Restoration History (Project 04 T03)
    # ------------------------------------------------------------------
    def _select_recoverable_version(
        self,
        tracked: TrackedFile,
        requested_version_id: str | None,
    ) -> tuple[BackupVersion, bytes]:
        """Select and verify the backup payload BEFORE mutating live sandbox data."""
        if requested_version_id and requested_version_id != "latest_verified":
            safe_ver_id = validate_identifier(requested_version_id, "version_id")
            version = self.metadata.get_backup_version(safe_ver_id)
            if not version or version.file_id != tracked.file_id or version.status == "PRUNED":
                raise ResourceNotFoundError("Requested backup version is unavailable.")
            ok, _, plaintext, msg = self._verify_backup_blob(version)
            if not ok or plaintext is None:
                self.metadata.mark_version_status(version.version_id, status="CORRUPTED", is_known_good=False)
                raise IntegrityVerificationError(f"Selected backup version failed verification: {msg}")
            return version, plaintext

        versions = self.metadata.list_backup_versions(tracked.file_id, include_pruned=False)
        for candidate in versions:
            if candidate.status != "ACTIVE" or not candidate.is_known_good:
                continue
            ok, _, plaintext, _ = self._verify_backup_blob(candidate)
            if ok and plaintext is not None:
                return candidate, plaintext
            self.metadata.mark_version_status(candidate.version_id, status="CORRUPTED", is_known_good=False)

        raise IntegrityVerificationError("No intact verified backup version is available for recovery.")

    def recover_version(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        version_id: str | None = None,
        target_relative_path: str | None = None,
        quarantine_corrupted: bool = True,
        trigger_source: str = "manual_recovery",
        clear_threat_lock: bool = True,
        correlation_id: str | None = None,
    ) -> RestorationRecord:
        """Recover a verified previous version to the sandbox and record restoration history."""
        corr_id = correlation_id or new_id("corr")
        safe_file_id = validate_identifier(file_id, "file_id")
        tracked = self.metadata.get_tracked_file(safe_file_id)
        if not tracked:
            raise ResourceNotFoundError("Tracked file not found.", correlation_id=corr_id)

        try:
            self._authorize_student_scope(
                actor,
                tracked.student_id,
                action="recover_version",
                correlation_id=corr_id,
                file_id=safe_file_id,
                allow_system=True,
                require_2fa=True,
            )
        except AccessDeniedError as exc:
            denied_rec = RestorationRecord(
                restoration_id=new_id("rst"),
                correlation_id=corr_id,
                file_id=tracked.file_id,
                student_id=tracked.student_id,
                filename=tracked.filename,
                restored_version_id=version_id,
                restored_version_number=None,
                actor_id=actor.actor_id,
                trigger_source=trigger_source,
                pre_restore_live_sha256=None,
                restored_sha256=None,
                expected_known_good_sha256=None,
                verification_passed=False,
                quarantine_evidence_path=None,
                status=RestorationStatus.DENIED,
                error_code=exc.error_code,
                notes="Access denied for restoration request.",
            )
            self.metadata.add_restoration_record(denied_rec)
            raise

        dest_rel = target_relative_path or tracked.relative_path
        dest_path = self.guard.resolve_sandbox_path(tracked.student_id, dest_rel)

        live_path = self.guard.resolve_sandbox_path(tracked.student_id, tracked.relative_path)
        pre_restore_sha = sha256_file(live_path) if live_path.is_file() else None

        try:
            chosen_version, plaintext = self._select_recoverable_version(tracked, version_id)
        except BackupRecoveryError as exc:
            failed_rec = RestorationRecord(
                restoration_id=new_id("rst"),
                correlation_id=corr_id,
                file_id=tracked.file_id,
                student_id=tracked.student_id,
                filename=tracked.filename,
                restored_version_id=version_id,
                restored_version_number=None,
                actor_id=actor.actor_id,
                trigger_source=trigger_source,
                pre_restore_live_sha256=pre_restore_sha,
                restored_sha256=None,
                expected_known_good_sha256=tracked.last_known_good_sha256,
                verification_passed=False,
                quarantine_evidence_path=None,
                status=RestorationStatus.FAILED_INTEGRITY,
                error_code=exc.error_code,
                notes=exc.safe_message,
            )
            self.metadata.add_restoration_record(failed_rec)
            self.logger.log_event(
                event_type="RECOVERY_FAILED",
                outcome="FAILED_INTEGRITY",
                correlation_id=corr_id,
                actor_id=actor.actor_id,
                student_id=tracked.student_id,
                file_id=tracked.file_id,
                version_id=version_id,
                details={"error_code": exc.error_code},
            )
            raise

        # Preserve tampered/corrupted live copy in quarantine before overwriting (incident evidence)
        quarantine_rel: str | None = None
        if (
            quarantine_corrupted
            and live_path.is_file()
            and pre_restore_sha is not None
            and not constant_time_hash_equals(chosen_version.plaintext_sha256, pre_restore_sha)
        ):
            q_name = f"{corr_id}_{tracked.filename}.quarantined"
            q_path = self.guard.resolve_quarantine_path(tracked.student_id, q_name)
            shutil.copy2(live_path, q_path)
            quarantine_rel = str(q_path.relative_to(self.config.quarantine_root)).replace("\\", "/")

        # Write restored bytes atomically and verify final disk file SHA-256
        self._atomic_write_bytes(dest_path, plaintext)
        restored_sha = sha256_file(dest_path)
        verified = constant_time_hash_equals(chosen_version.plaintext_sha256, restored_sha)

        if not verified:
            raise IntegrityVerificationError(
                "Post-restore disk verification failed SHA-256 check.",
                correlation_id=corr_id,
            )

        # Update tracked file state if restored to primary path
        if dest_path == live_path:
            tracked.last_known_good_version_id = chosen_version.version_id
            tracked.last_known_good_sha256 = chosen_version.plaintext_sha256
            if clear_threat_lock:
                tracked.threat_locked = False
                tracked.threat_reason = None
                tracked.threat_alert_id = None
            tracked.updated_at = utc_now_iso()
            self.metadata.upsert_tracked_file(tracked)

        record = RestorationRecord(
            restoration_id=new_id("rst"),
            correlation_id=corr_id,
            file_id=tracked.file_id,
            student_id=tracked.student_id,
            filename=tracked.filename,
            restored_version_id=chosen_version.version_id,
            restored_version_number=chosen_version.version_number,
            actor_id=actor.actor_id,
            trigger_source=trigger_source,
            pre_restore_live_sha256=pre_restore_sha,
            restored_sha256=restored_sha,
            expected_known_good_sha256=chosen_version.plaintext_sha256,
            verification_passed=verified,
            quarantine_evidence_path=quarantine_rel,
            status=RestorationStatus.SUCCESS,
            notes=f"Restored v{chosen_version.version_number} to '{dest_rel}' and verified SHA-256.",
        )
        self.metadata.add_restoration_record(record)

        self.logger.log_event(
            event_type="FILE_RECOVERED",
            outcome="SUCCESS",
            correlation_id=corr_id,
            actor_id=actor.actor_id,
            student_id=tracked.student_id,
            file_id=tracked.file_id,
            version_id=chosen_version.version_id,
            details={
                "restoration_id": record.restoration_id,
                "version_number": chosen_version.version_number,
                "pre_restore_live_sha256": pre_restore_sha,
                "restored_sha256": restored_sha,
                "verification_passed": verified,
                "quarantined": quarantine_rel is not None,
            },
        )
        return record

    # ------------------------------------------------------------------
    # History, Dashboard & Member 5 Ransomware Integration Hooks
    # ------------------------------------------------------------------
    def get_backup_history(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        limit: int = 100,
        correlation_id: str | None = None,
    ) -> list[BackupVersion]:
        corr_id = correlation_id or new_id("corr")
        safe_student = validate_identifier(student_id, "student_id")
        self._authorize_student_scope(
            actor, safe_student, action="get_backup_history", correlation_id=corr_id
        )
        return self.metadata.list_student_backup_history(safe_student, limit=limit)

    def get_restoration_history(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        file_id: str | None = None,
        limit: int = 100,
        correlation_id: str | None = None,
    ) -> list[RestorationRecord]:
        corr_id = correlation_id or new_id("corr")
        safe_student = validate_identifier(student_id, "student_id")
        self._authorize_student_scope(
            actor, safe_student, action="get_restoration_history", correlation_id=corr_id, file_id=file_id
        )
        safe_file = validate_identifier(file_id, "file_id") if file_id else None
        return self.metadata.list_restoration_history(safe_student, file_id=safe_file, limit=limit)

    def list_student_files(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        correlation_id: str | None = None,
    ) -> list[TrackedFile]:
        corr_id = correlation_id or new_id("corr")
        safe_student = validate_identifier(student_id, "student_id")
        self._authorize_student_scope(
            actor, safe_student, action="list_student_files", correlation_id=corr_id
        )
        return self.metadata.list_tracked_files(safe_student)

    def get_dashboard_summary(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Return aggregated backup/integrity/recovery metrics for Member 2's Student Dashboard."""
        corr_id = correlation_id or new_id("corr")
        safe_student = validate_identifier(student_id, "student_id")
        self._authorize_student_scope(
            actor, safe_student, action="get_dashboard_summary", correlation_id=corr_id
        )
        files = self.metadata.list_tracked_files(safe_student)
        backups = self.metadata.list_student_backup_history(safe_student, limit=500)
        restorations = self.metadata.list_restoration_history(safe_student, limit=100)
        reports = self.metadata.list_integrity_reports(safe_student, limit=100)

        active_versions = [b for b in backups if b.status == "ACTIVE"]
        threat_locked_files = [f for f in files if f.threat_locked]
        return {
            "student_id": safe_student,
            "total_files": len(files),
            "total_backup_versions": len(active_versions),
            "threat_locked_files": len(threat_locked_files),
            "total_restorations": len(restorations),
            "successful_restorations": sum(1 for r in restorations if r.status == RestorationStatus.SUCCESS),
            "recent_integrity_alerts": sum(
                1 for r in reports if r.status in {IntegrityStatus.TAMPERED_LIVE_FILE, IntegrityStatus.CORRUPTED_BACKUP}
            ),
            "last_backup_at": active_versions[0].created_at if active_versions else None,
            "storage_backend": self.storage.health_check(),
            "key_provider": self.key_provider.health_check(),
        }

    def flag_threat_lock(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        reason: str,
        alert_id: str | None = None,
        correlation_id: str | None = None,
    ) -> TrackedFile:
        """Lock new auto-backups on a file when Member 5 detects suspicious ransomware activity."""
        corr_id = correlation_id or new_id("corr")
        safe_file_id = validate_identifier(file_id, "file_id")
        tracked = self.metadata.get_tracked_file(safe_file_id)
        if not tracked:
            raise ResourceNotFoundError("Tracked file not found.", correlation_id=corr_id)
        self._authorize_student_scope(
            actor,
            tracked.student_id,
            action="flag_threat_lock",
            correlation_id=corr_id,
            file_id=safe_file_id,
            allow_system=True,
        )
        self.metadata.set_threat_lock(
            safe_file_id,
            locked=True,
            reason=reason[:256],
            alert_id=alert_id or new_id("alert"),
        )
        updated = self.metadata.get_tracked_file(safe_file_id)
        assert updated is not None
        self.logger.log_event(
            event_type="THREAT_LOCK_ENABLED",
            outcome="LOCKED",
            correlation_id=corr_id,
            actor_id=actor.actor_id,
            student_id=tracked.student_id,
            file_id=safe_file_id,
            details={"alert_id": updated.threat_alert_id, "reason": updated.threat_reason},
        )
        return updated

    def release_threat_lock(
        self,
        actor: ActorContext,
        *,
        file_id: str,
        correlation_id: str | None = None,
    ) -> TrackedFile:
        corr_id = correlation_id or new_id("corr")
        safe_file_id = validate_identifier(file_id, "file_id")
        tracked = self.metadata.get_tracked_file(safe_file_id)
        if not tracked:
            raise ResourceNotFoundError("Tracked file not found.", correlation_id=corr_id)
        self._authorize_student_scope(
            actor,
            tracked.student_id,
            action="release_threat_lock",
            correlation_id=corr_id,
            file_id=safe_file_id,
            allow_system=True,
        )
        self.metadata.set_threat_lock(safe_file_id, locked=False, reason=None, alert_id=None)
        updated = self.metadata.get_tracked_file(safe_file_id)
        assert updated is not None
        self.logger.log_event(
            event_type="THREAT_LOCK_RELEASED",
            outcome="UNLOCKED",
            correlation_id=corr_id,
            actor_id=actor.actor_id,
            student_id=tracked.student_id,
            file_id=safe_file_id,
        )
        return updated

    def handle_ransomware_alert(
        self,
        actor: ActorContext,
        *,
        student_id: str,
        affected_file_ids: list[str],
        alert_id: str,
        reason: str,
        auto_recover: bool = False,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Integration entrypoint for Member 5 (Ransomware Module).

        1. Locks auto-backups for every affected file so clean snapshots remain safe.
        2. Runs SHA-256 & encrypted blob integrity verification on each affected file.
        3. Optionally quarantines tampered copies and restores verified known-good versions.
        """
        corr_id = correlation_id or new_id("corr")
        safe_student = validate_identifier(student_id, "student_id")
        self._authorize_student_scope(
            actor,
            safe_student,
            action="handle_ransomware_alert",
            correlation_id=corr_id,
            allow_system=True,
        )

        integrity_reports: list[dict[str, Any]] = []
        restorations: list[dict[str, Any]] = []

        for fid in affected_file_ids:
            locked = self.flag_threat_lock(
                actor, file_id=fid, reason=reason, alert_id=alert_id, correlation_id=corr_id
            )
            report = self.verify_integrity(actor, file_id=locked.file_id, correlation_id=corr_id)
            integrity_reports.append(report.to_dict())

            if auto_recover and report.status in {
                IntegrityStatus.TAMPERED_LIVE_FILE,
                IntegrityStatus.MISSING_LIVE_FILE,
            }:
                rec = self.recover_version(
                    actor,
                    file_id=locked.file_id,
                    version_id="latest_verified",
                    quarantine_corrupted=True,
                    trigger_source="ransomware_auto_recovery",
                    clear_threat_lock=True,
                    correlation_id=corr_id,
                )
                restorations.append(rec.to_dict())

        return {
            "correlation_id": corr_id,
            "alert_id": alert_id,
            "student_id": safe_student,
            "affected_count": len(affected_file_ids),
            "integrity_reports": integrity_reports,
            "restorations": restorations,
        }

    def get_system_readiness(self) -> dict[str, Any]:
        """Return adapter readiness & environment caveat details (never exposes secrets)."""
        return {
            "storage": self.storage.health_check(),
            "key_provider": self.key_provider.health_check(),
            "max_versions_per_file": self.config.max_versions_per_file,
            "max_file_size_bytes": self.config.max_file_size_bytes,
            "require_2fa_for_recovery": self.require_2fa_for_recovery,
            "sandbox_isolated": True,
        }

    def close(self) -> None:
        if isinstance(self.metadata, SQLiteMetadataStore):
            self.metadata.close()
