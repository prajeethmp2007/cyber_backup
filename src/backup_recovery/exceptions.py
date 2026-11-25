"""Core domain exceptions for the Backup & Recovery module.

All exceptions carry safe, non-sensitive error codes and sanitized user messages
so API callers never leak cryptographic key material, file contents, or stack traces
(Project 04 T06 & T07).
"""

from __future__ import annotations


class BackupRecoveryError(Exception):
    """Base exception for all backup and recovery errors."""

    error_code: str = "BACKUP_ERROR"
    http_status: int = 500

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        http_status: int | None = None,
        correlation_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.safe_message = message
        if error_code is not None:
            self.error_code = error_code
        if http_status is not None:
            self.http_status = http_status
        self.correlation_id = correlation_id


class ValidationError(BackupRecoveryError):
    """Raised when caller inputs fail server-side validation."""

    error_code = "VALIDATION_ERROR"
    http_status = 400


class SandboxViolationError(BackupRecoveryError):
    """Raised when a path escapes the designated sandbox or vault root (T04)."""

    error_code = "SANDBOX_VIOLATION"
    http_status = 403


class AccessDeniedError(BackupRecoveryError):
    """Raised on unauthorized cross-student or unauthenticated access (deny-by-default)."""

    error_code = "ACCESS_DENIED"
    http_status = 403


class ResourceNotFoundError(BackupRecoveryError):
    """Raised when a requested file, backup version, or workspace resource does not exist."""

    error_code = "NOT_FOUND"
    http_status = 404


class ThreatLockError(BackupRecoveryError):
    """Raised when auto-backup is blocked because the file is flagged for suspected ransomware."""

    error_code = "THREAT_LOCK_ACTIVE"
    http_status = 409


class IntegrityVerificationError(BackupRecoveryError):
    """Raised when a backup blob or restored copy fails SHA-256 or AEAD verification."""

    error_code = "INTEGRITY_CHECK_FAILED"
    http_status = 422


class KeyManagementError(BackupRecoveryError):
    """Raised when encryption/decryption keys are missing, invalid, or misconfigured."""

    error_code = "KEY_MANAGEMENT_ERROR"
    http_status = 500


class StorageBackendError(BackupRecoveryError):
    """Raised when the backup storage backend fails a read/write/delete operation."""

    error_code = "STORAGE_BACKEND_ERROR"
    http_status = 503
