"""Configuration for the Student Vault Backup & Recovery module.

Follows MindMatrix Project 04 & Infrastructure Setup Guide safety rules:
- Restricted to local sandbox directories or explicitly authorized lab endpoints.
- Never stores hardcoded secrets or encryption keys in source code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class VaultConfig:
    """Immutable configuration controlling sandbox, storage, retention, and adapters."""

    sandbox_root: Path
    vault_root: Path
    quarantine_root: Path
    metadata_db_path: Path
    log_file_path: Path
    storage_mode: str = "local_vault_adapter"
    key_provider_mode: str = "env_kek"
    max_versions_per_file: int = 20
    max_file_size_bytes: int = 50 * 1024 * 1024  # 50 MiB safe lab cap
    deduplicate_unchanged_auto: bool = True
    allowed_extensions: tuple[str, ...] = (
        ".txt",
        ".md",
        ".pdf",
        ".docx",
        ".csv",
        ".json",
        ".py",
        ".java",
        ".c",
        ".cpp",
        ".png",
        ".jpg",
        ".zip",
    )
    # Optional Floci / S3-compatible / GCP settings (explicitly unverified until smoke-tested)
    cloud_endpoint_url: str | None = None
    cloud_bucket_name: str | None = None
    kms_key_id: str | None = None
    extra_metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_versions_per_file < 1:
            raise ValueError("max_versions_per_file must be at least 1")
        if self.max_file_size_bytes < 1:
            raise ValueError("max_file_size_bytes must be positive")

    def ensure_directories(self) -> None:
        """Create required sandbox, vault, quarantine, DB parent, and log parent folders."""
        self.sandbox_root.mkdir(parents=True, exist_ok=True)
        self.vault_root.mkdir(parents=True, exist_ok=True)
        self.quarantine_root.mkdir(parents=True, exist_ok=True)
        self.metadata_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_base_dir(
        cls,
        base_dir: str | Path,
        *,
        max_versions_per_file: int = 20,
        deduplicate_unchanged_auto: bool = True,
        allowed_extensions: tuple[str, ...] | None = None,
    ) -> "VaultConfig":
        """Build a self-contained local config under a single base directory."""
        root = Path(base_dir).resolve()
        kwargs: dict[str, object] = {
            "sandbox_root": root / "sandbox",
            "vault_root": root / "vault_storage",
            "quarantine_root": root / "quarantine",
            "metadata_db_path": root / "metadata" / "vault_metadata.db",
            "log_file_path": root / "logs" / "backup_security_events.jsonl",
            "max_versions_per_file": max_versions_per_file,
            "deduplicate_unchanged_auto": deduplicate_unchanged_auto,
        }
        if allowed_extensions is not None:
            kwargs["allowed_extensions"] = allowed_extensions
        return cls(**kwargs)  # type: ignore[arg-type]

    @classmethod
    def from_env(cls, default_base_dir: str | Path = "./runtime_vault") -> "VaultConfig":
        """Load configuration from environment variables with safe localhost defaults."""
        base = Path(os.environ.get("VAULT_BASE_DIR", str(default_base_dir))).resolve()
        return cls(
            sandbox_root=Path(
                os.environ.get("VAULT_SANDBOX_ROOT", str(base / "sandbox"))
            ).resolve(),
            vault_root=Path(
                os.environ.get("VAULT_STORAGE_ROOT", str(base / "vault_storage"))
            ).resolve(),
            quarantine_root=Path(
                os.environ.get("VAULT_QUARANTINE_ROOT", str(base / "quarantine"))
            ).resolve(),
            metadata_db_path=Path(
                os.environ.get("VAULT_METADATA_DB", str(base / "metadata" / "vault_metadata.db"))
            ).resolve(),
            log_file_path=Path(
                os.environ.get("VAULT_SECURITY_LOG", str(base / "logs" / "backup_security_events.jsonl"))
            ).resolve(),
            storage_mode=os.environ.get("VAULT_STORAGE_MODE", "local_vault_adapter"),
            key_provider_mode=os.environ.get("VAULT_KEY_PROVIDER_MODE", "env_kek"),
            max_versions_per_file=int(os.environ.get("VAULT_MAX_VERSIONS", "20")),
            max_file_size_bytes=int(
                os.environ.get("VAULT_MAX_FILE_BYTES", str(50 * 1024 * 1024))
            ),
            cloud_endpoint_url=os.environ.get("VAULT_CLOUD_ENDPOINT"),
            cloud_bucket_name=os.environ.get("VAULT_CLOUD_BUCKET"),
            kms_key_id=os.environ.get("VAULT_KMS_KEY_ID"),
        )
