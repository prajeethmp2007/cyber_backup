"""Authenticated envelope encryption for Student Vault backups (AES-256-GCM).

Binary envelope format (`SVBK1`):
- 5 bytes: magic `b"SVBK1"`
- 4 bytes: big-endian uint32 header length
- N bytes: canonical UTF-8 JSON header containing non-secret metadata + wrapped DEK
- 12 bytes: AES-256-GCM random nonce
- remaining bytes: AES-256-GCM ciphertext + 16-byte authentication tag

The canonical header JSON is passed as AES-GCM Additional Authenticated Data (AAD),
so any tampering with metadata, wrapped DEK, version_id, or ciphertext is immediately detected.
"""

from __future__ import annotations

import base64
import json
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import IntegrityVerificationError, KeyManagementError
from .hashing import constant_time_hash_equals, sha256_bytes
from .key_management import KeyProvider

MAGIC = b"SVBK1"


@dataclass(frozen=True)
class EnvelopeHeader:
    """Canonical non-secret envelope metadata bound to ciphertext via AAD."""

    format_version: int
    student_id: str
    file_id: str
    version_id: str
    version_number: int
    plaintext_sha256: str
    plaintext_size: int
    key_id: str
    wrapped_dek_b64: str
    algorithm: str = "AES-256-GCM"

    def to_canonical_bytes(self) -> bytes:
        payload = {
            "algorithm": self.algorithm,
            "file_id": self.file_id,
            "format_version": self.format_version,
            "key_id": self.key_id,
            "plaintext_sha256": self.plaintext_sha256,
            "plaintext_size": self.plaintext_size,
            "student_id": self.student_id,
            "version_id": self.version_id,
            "version_number": self.version_number,
            "wrapped_dek_b64": self.wrapped_dek_b64,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "EnvelopeHeader":
        try:
            obj = json.loads(raw.decode("utf-8"))
            return cls(
                format_version=int(obj["format_version"]),
                student_id=str(obj["student_id"]),
                file_id=str(obj["file_id"]),
                version_id=str(obj["version_id"]),
                version_number=int(obj["version_number"]),
                plaintext_sha256=str(obj["plaintext_sha256"]),
                plaintext_size=int(obj["plaintext_size"]),
                key_id=str(obj["key_id"]),
                wrapped_dek_b64=str(obj["wrapped_dek_b64"]),
                algorithm=str(obj.get("algorithm", "AES-256-GCM")),
            )
        except Exception as exc:
            raise IntegrityVerificationError("Corrupted or invalid backup envelope header.") from exc


def encrypt_backup_payload(
    *,
    plaintext: bytes,
    student_id: str,
    file_id: str,
    version_id: str,
    version_number: int,
    plaintext_sha256: str,
    key_provider: KeyProvider,
) -> tuple[bytes, str, str]:
    """Encrypt plaintext bytes using a fresh per-backup DEK wrapped by `key_provider`.

    Returns `(encrypted_package_bytes, encrypted_sha256, key_id)`.
    """
    dek = os.urandom(32)
    wrap_ctx = {
        "student_id": student_id,
        "file_id": file_id,
        "version_id": version_id,
        "version_number": str(version_number),
    }
    key_id, wrapped_dek = key_provider.wrap_dek(dek, wrap_ctx)

    header = EnvelopeHeader(
        format_version=1,
        student_id=student_id,
        file_id=file_id,
        version_id=version_id,
        version_number=version_number,
        plaintext_sha256=plaintext_sha256,
        plaintext_size=len(plaintext),
        key_id=key_id,
        wrapped_dek_b64=base64.b64encode(wrapped_dek).decode("ascii"),
    )
    header_bytes = header.to_canonical_bytes()
    nonce = os.urandom(12)

    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, header_bytes)

    package = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + nonce + ciphertext
    return package, sha256_bytes(package), key_id


def decrypt_backup_payload(
    *,
    package: bytes,
    expected_student_id: str,
    expected_file_id: str,
    expected_version_id: str,
    expected_plaintext_sha256: str,
    key_provider: KeyProvider,
) -> bytes:
    """Verify envelope format, unwrap DEK, decrypt payload, and verify SHA-256 digest."""
    if len(package) < len(MAGIC) + 4 + 12 + 16 or not package.startswith(MAGIC):
        raise IntegrityVerificationError("Backup artifact failed magic/length envelope validation.")

    offset = len(MAGIC)
    (header_len,) = struct.unpack(">I", package[offset : offset + 4])
    offset += 4
    if header_len <= 0 or offset + header_len + 12 + 16 > len(package):
        raise IntegrityVerificationError("Backup artifact header length is out of bounds.")

    header_bytes = package[offset : offset + header_len]
    offset += header_len
    header = EnvelopeHeader.from_bytes(header_bytes)

    # Binding check against expected metadata
    if (
        header.student_id != expected_student_id
        or header.file_id != expected_file_id
        or header.version_id != expected_version_id
    ):
        raise IntegrityVerificationError("Backup envelope ownership/version binding mismatch.")

    if not constant_time_hash_equals(expected_plaintext_sha256, header.plaintext_sha256):
        raise IntegrityVerificationError("Backup envelope plaintext hash metadata mismatch.")

    nonce = package[offset : offset + 12]
    ciphertext = package[offset + 12 :]

    try:
        wrapped_dek = base64.b64decode(header.wrapped_dek_b64, validate=True)
    except Exception as exc:
        raise IntegrityVerificationError("Malformed wrapped DEK encoding in backup header.") from exc

    wrap_ctx = {
        "student_id": header.student_id,
        "file_id": header.file_id,
        "version_id": header.version_id,
        "version_number": str(header.version_number),
    }
    try:
        dek = key_provider.unwrap_dek(wrapped_dek, header.key_id, wrap_ctx)
    except KeyManagementError as exc:
        raise IntegrityVerificationError(f"Backup key unwrap failed: {exc.safe_message}") from exc

    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, header_bytes)
    except InvalidTag as exc:
        raise IntegrityVerificationError(
            "Backup artifact failed AES-256-GCM authentication tag verification (tampered or corrupted)."
        ) from exc

    observed_sha = sha256_bytes(plaintext)
    if not constant_time_hash_equals(expected_plaintext_sha256, observed_sha):
        raise IntegrityVerificationError(
            "Decrypted backup bytes do not match recorded SHA-256 digest."
        )

    return plaintext
