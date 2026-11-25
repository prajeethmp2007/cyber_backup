"""Backup storage backends with atomic writes and explicit local/cloud boundary labeling."""

from __future__ import annotations

import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from .exceptions import ResourceNotFoundError, StorageBackendError
from .path_guard import SandboxGuard


class StorageBackend(ABC):
    """Abstract object storage interface for encrypted backup blobs."""

    backend_name: str
    is_cloud_verified: bool = False

    @abstractmethod
    def put_object(self, storage_key: str, data: bytes) -> None:
        """Persist encrypted backup bytes under `storage_key`."""

    @abstractmethod
    def get_object(self, storage_key: str) -> bytes:
        """Retrieve encrypted backup bytes for `storage_key`."""

    @abstractmethod
    def delete_object(self, storage_key: str) -> None:
        """Delete an object (e.g., during retention pruning)."""

    @abstractmethod
    def exists(self, storage_key: str) -> bool:
        """Return True if the object exists in storage."""

    def health_check(self) -> dict[str, object]:
        return {
            "backend": self.backend_name,
            "cloud_verified": self.is_cloud_verified,
        }


class LocalVaultStorageAdapter(StorageBackend):
    """Clearly labelled local encrypted vault storage adapter.

    Stores encrypted backup blobs strictly inside `vault_root` using atomic
    temporary-write + fsync + replace semantics.
    """

    backend_name = "local_vault_adapter"
    is_cloud_verified = False

    def __init__(self, vault_root: Path, sandbox_guard: SandboxGuard) -> None:
        self.vault_root = vault_root.resolve()
        self.vault_root.mkdir(parents=True, exist_ok=True)
        self.guard = sandbox_guard

    def put_object(self, storage_key: str, data: bytes) -> None:
        target = self.guard.resolve_vault_key(storage_key)
        target.parent.mkdir(parents=True, exist_ok=True)

        fd, tmp_path_str = tempfile.mkstemp(
            prefix=".tmp_vault_",
            dir=str(target.parent),
        )
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, target)
            if os.name == "posix":
                os.chmod(target, 0o600)
        except OSError as exc:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise StorageBackendError("Failed writing encrypted backup object to vault storage.") from exc

    def get_object(self, storage_key: str) -> bytes:
        target = self.guard.resolve_vault_key(storage_key)
        if not target.exists():
            raise ResourceNotFoundError("Requested backup artifact was not found in vault storage.")
        try:
            return target.read_bytes()
        except OSError as exc:
            raise StorageBackendError("Failed reading backup artifact from vault storage.") from exc

    def delete_object(self, storage_key: str) -> None:
        target = self.guard.resolve_vault_key(storage_key)
        try:
            target.unlink(missing_ok=True)
        except OSError as exc:
            raise StorageBackendError("Failed deleting pruned backup artifact.") from exc

    def exists(self, storage_key: str) -> bool:
        target = self.guard.resolve_vault_key(storage_key)
        return target.exists()


class FlociS3StorageAdapter(StorageBackend):
    """Explicitly labelled Floci / S3-compatible / GCS storage adapter stub.

    Follows MindMatrix Environment Caveat: unless an endpoint client is injected
    and verified via a smoke test, all operations fail closed rather than claiming
    unverified cloud integration.
    """

    backend_name = "floci_cloud_storage_adapter"

    def __init__(
        self,
        *,
        bucket_name: str,
        endpoint_url: str | None = None,
        client: object | None = None,
        verified: bool = False,
    ) -> None:
        if not bucket_name:
            raise StorageBackendError("bucket_name is required for FlociS3StorageAdapter.")
        self.bucket_name = bucket_name
        self.endpoint_url = endpoint_url
        self._client = client
        self.is_cloud_verified = bool(verified and client is not None)

    def _require_verified(self) -> object:
        if not self.is_cloud_verified or self._client is None:
            raise StorageBackendError(
                "Cloud/Floci object storage operation is unverified in this environment; "
                "use LocalVaultStorageAdapter or complete smoke verification first."
            )
        return self._client

    def put_object(self, storage_key: str, data: bytes) -> None:
        client = self._require_verified()
        client.put_object(Bucket=self.bucket_name, Key=storage_key, Body=data)  # type: ignore[attr-defined]

    def get_object(self, storage_key: str) -> bytes:
        client = self._require_verified()
        resp = client.get_object(Bucket=self.bucket_name, Key=storage_key)  # type: ignore[attr-defined]
        return bytes(resp["Body"].read())

    def delete_object(self, storage_key: str) -> None:
        client = self._require_verified()
        client.delete_object(Bucket=self.bucket_name, Key=storage_key)  # type: ignore[attr-defined]

    def exists(self, storage_key: str) -> bool:
        client = self._require_verified()
        try:
            client.head_object(Bucket=self.bucket_name, Key=storage_key)  # type: ignore[attr-defined]
            return True
        except Exception:
            return False
