"""Key Management abstraction for envelope encryption (Project 04 Cloud KMS / Local Adapter).

Implements:
- `KeyProvider` interface for wrapping/unwrapping per-backup 256-bit Data Encryption Keys (DEKs).
- `LocalEnvKeyProvider`: reads a 32-byte base64 KEK from `STUDENT_VAULT_KEK_B64` (never hardcoded).
- `CloudKMSKeyProvider`: explicitly labelled adapter for Cloud KMS / Floci KMS that refuses
  unverified claims when no reachable/verified KMS operation exists (Project 04 Environment Caveat).
"""

from __future__ import annotations

import base64
import json
import os
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import KeyManagementError

ENV_KEK_VAR = "STUDENT_VAULT_KEK_B64"


class KeyProvider(ABC):
    """Abstract Key Encryption Key (KEK) provider."""

    provider_name: str
    is_cloud_verified: bool = False

    @property
    @abstractmethod
    def active_key_id(self) -> str:
        """Identifier for the active wrapping key (non-secret metadata)."""

    @abstractmethod
    def wrap_dek(self, dek: bytes, context: dict[str, str]) -> tuple[str, bytes]:
        """Wrap a 32-byte DEK using canonical context AAD. Returns (key_id, wrapped_bytes)."""

    @abstractmethod
    def unwrap_dek(self, wrapped_dek: bytes, key_id: str, context: dict[str, str]) -> bytes:
        """Unwrap a previously wrapped DEK after verifying context AAD."""

    def health_check(self) -> dict[str, object]:
        """Report provider status without exposing any key bytes."""
        return {
            "provider": self.provider_name,
            "active_key_id": self.active_key_id,
            "cloud_verified": self.is_cloud_verified,
        }


def _canonical_context_aad(context: dict[str, str]) -> bytes:
    """Serialize wrapping context deterministically for AEAD AAD binding."""
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode("utf-8")


class LocalEnvKeyProvider(KeyProvider):
    """Clearly labelled local KEK wrapping adapter using AES-256-GCM.

    Reads the 256-bit KEK from environment variable `STUDENT_VAULT_KEK_B64` (or in-memory
    ephemeral bytes for tests). Never logs, persists, or hardcodes key material.
    """

    provider_name = "local_env_kek_adapter"
    is_cloud_verified = False

    def __init__(self, kek_bytes: bytes, key_id: str = "local-kek-v1") -> None:
        if len(kek_bytes) != 32:
            raise KeyManagementError("KEK must be exactly 32 bytes (256 bits).")
        self._kek = bytes(kek_bytes)
        self._key_id = key_id

    @property
    def active_key_id(self) -> str:
        return self._key_id

    @classmethod
    def from_env(cls, env_var: str = ENV_KEK_VAR, key_id: str = "local-kek-v1") -> "LocalEnvKeyProvider":
        """Load base64-encoded 32-byte KEK from environment variable; fail closed if absent."""
        raw_b64 = os.environ.get(env_var, "").strip()
        if not raw_b64:
            raise KeyManagementError(
                f"Missing required environment key variable {env_var}. Configure it securely before starting."
            )
        try:
            decoded = base64.b64decode(raw_b64, validate=True)
        except Exception as exc:
            raise KeyManagementError(f"Invalid base64 key material in {env_var}.") from exc
        return cls(decoded, key_id=key_id)

    @classmethod
    def ephemeral(cls, key_id: str = "local-ephemeral-kek-v1") -> "LocalEnvKeyProvider":
        """Create an in-memory random KEK for isolated automated testing or single-run demos."""
        return cls(os.urandom(32), key_id=key_id)

    def wrap_dek(self, dek: bytes, context: dict[str, str]) -> tuple[str, bytes]:
        if len(dek) != 32:
            raise KeyManagementError("DEK must be exactly 32 bytes.")
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._kek)
        aad = _canonical_context_aad(context)
        wrapped = aesgcm.encrypt(nonce, dek, aad)
        return self._key_id, nonce + wrapped

    def unwrap_dek(self, wrapped_dek: bytes, key_id: str, context: dict[str, str]) -> bytes:
        if key_id != self._key_id:
            raise KeyManagementError("Unknown or mismatched key_id for local KEK unwrap.")
        if len(wrapped_dek) < 13:
            raise KeyManagementError("Malformed wrapped DEK payload.")
        nonce = wrapped_dek[:12]
        ct = wrapped_dek[12:]
        aesgcm = AESGCM(self._kek)
        aad = _canonical_context_aad(context)
        try:
            return aesgcm.decrypt(nonce, ct, aad)
        except InvalidTag as exc:
            raise KeyManagementError("DEK unwrap failed authentication check.") from exc


class CloudKMSKeyProvider(KeyProvider):
    """Explicitly labelled Cloud/Floci KMS adapter placeholder.

    Honors MindMatrix Environment Caveat: unless a concrete SDK client & smoke-test
    verification are supplied, operations fail closed rather than faking cloud integration.
    """

    provider_name = "cloud_kms_adapter"

    def __init__(self, kms_key_id: str, client: object | None = None, verified: bool = False) -> None:
        if not kms_key_id:
            raise KeyManagementError("kms_key_id is required for CloudKMSKeyProvider.")
        self._kms_key_id = kms_key_id
        self._client = client
        self.is_cloud_verified = bool(verified and client is not None)

    @property
    def active_key_id(self) -> str:
        return self._kms_key_id

    def wrap_dek(self, dek: bytes, context: dict[str, str]) -> tuple[str, bytes]:
        if not self.is_cloud_verified or self._client is None:
            raise KeyManagementError(
                "Cloud/Floci KMS operation is unverified in this environment; use LocalEnvKeyProvider."
            )
        # Expecting a verified adapter client exposing encrypt(key_id, plaintext, aad)
        wrapped = self._client.encrypt(self._kms_key_id, dek, _canonical_context_aad(context))  # type: ignore[attr-defined]
        return self._kms_key_id, wrapped

    def unwrap_dek(self, wrapped_dek: bytes, key_id: str, context: dict[str, str]) -> bytes:
        if not self.is_cloud_verified or self._client is None:
            raise KeyManagementError(
                "Cloud/Floci KMS operation is unverified in this environment; use LocalEnvKeyProvider."
            )
        return self._client.decrypt(key_id, wrapped_dek, _canonical_context_aad(context))  # type: ignore[attr-defined]
