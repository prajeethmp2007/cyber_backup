"""Student Vault Backup & Recovery Module (Member 3 / Project 04)."""

from .api_adapter import BackupAPIController, create_backup_blueprint
from .config import VaultConfig
from .exceptions import (
    AccessDeniedError,
    BackupRecoveryError,
    IntegrityVerificationError,
    KeyManagementError,
    ResourceNotFoundError,
    SandboxViolationError,
    StorageBackendError,
    ThreatLockError,
    ValidationError,
)
from .key_management import CloudKMSKeyProvider, KeyProvider, LocalEnvKeyProvider
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
)
from .service import BackupCreationResult, BackupRecoveryService
from .storage_backends import FlociS3StorageAdapter, LocalVaultStorageAdapter, StorageBackend

__all__ = [
    "AccessDeniedError",
    "ActorContext",
    "AutoBackupSweepResult",
    "BackupAPIController",
    "BackupCreationResult",
    "BackupRecoveryError",
    "BackupRecoveryService",
    "BackupTrigger",
    "BackupVersion",
    "CloudKMSKeyProvider",
    "FlociS3StorageAdapter",
    "IntegrityReport",
    "IntegrityStatus",
    "IntegrityVerificationError",
    "KeyManagementError",
    "KeyProvider",
    "LocalEnvKeyProvider",
    "LocalVaultStorageAdapter",
    "MetadataStore",
    "ResourceNotFoundError",
    "RestorationRecord",
    "RestorationStatus",
    "SQLiteMetadataStore",
    "SandboxViolationError",
    "StorageBackend",
    "StorageBackendError",
    "ThreatLockError",
    "TrackedFile",
    "ValidationError",
    "VaultConfig",
    "create_backup_blueprint",
]
