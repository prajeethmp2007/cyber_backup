"""Tests for SHA-256 hashing, AES-256-GCM envelope encryption, and key wrapping."""

from __future__ import annotations

import base64

import pytest

from backup_recovery.crypto import decrypt_backup_payload, encrypt_backup_payload
from backup_recovery.exceptions import IntegrityVerificationError, KeyManagementError
from backup_recovery.hashing import constant_time_hash_equals, sha256_bytes, sha256_file
from backup_recovery.key_management import CloudKMSKeyProvider, LocalEnvKeyProvider


def test_sha256_helpers_and_constant_time_comparison(tmp_path):
    payload = b"synthetic student assignment bytes\n"
    f = tmp_path / "sample.txt"
    f.write_bytes(payload)

    digest_bytes = sha256_bytes(payload)
    digest_file = sha256_file(f)

    assert digest_bytes == digest_file
    assert constant_time_hash_equals(digest_bytes, digest_file.upper())
    assert not constant_time_hash_equals(digest_bytes, "0" * 64)


def test_envelope_encrypt_decrypt_roundtrip_and_tamper_detection():
    kek = LocalEnvKeyProvider.ephemeral()
    plaintext = b"CONFIDENTIAL_SYNTHETIC_LAB_NOTES|v1"
    digest = sha256_bytes(plaintext)

    package, enc_sha, key_id = encrypt_backup_payload(
        plaintext=plaintext,
        student_id="stu_demo_001",
        file_id="file_001",
        version_id="ver_001",
        version_number=1,
        plaintext_sha256=digest,
        key_provider=kek,
    )
    assert enc_sha == sha256_bytes(package)
    assert key_id == kek.active_key_id
    assert plaintext not in package

    recovered = decrypt_backup_payload(
        package=package,
        expected_student_id="stu_demo_001",
        expected_file_id="file_001",
        expected_version_id="ver_001",
        expected_plaintext_sha256=digest,
        key_provider=kek,
    )
    assert recovered == plaintext

    # Flip last byte (GCM tag / ciphertext) -> must fail verification
    tampered = package[:-1] + bytes([package[-1] ^ 0xFF])
    with pytest.raises(IntegrityVerificationError):
        decrypt_backup_payload(
            package=tampered,
            expected_student_id="stu_demo_001",
            expected_file_id="file_001",
            expected_version_id="ver_001",
            expected_plaintext_sha256=digest,
            key_provider=kek,
        )

    # Cross-student / cross-file substitution attempt -> must fail binding check
    with pytest.raises(IntegrityVerificationError):
        decrypt_backup_payload(
            package=package,
            expected_student_id="stu_demo_002",
            expected_file_id="file_001",
            expected_version_id="ver_001",
            expected_plaintext_sha256=digest,
            key_provider=kek,
        )


def test_env_key_provider_fail_closed_and_unverified_cloud_kms(monkeypatch):
    monkeypatch.delenv("STUDENT_VAULT_KEK_B64", raising=False)
    with pytest.raises(KeyManagementError):
        LocalEnvKeyProvider.from_env()

    monkeypatch.setenv("STUDENT_VAULT_KEK_B64", base64.b64encode(b"A" * 32).decode("ascii"))
    provider = LocalEnvKeyProvider.from_env()
    assert provider.active_key_id == "local-kek-v1"

    cloud_kms = CloudKMSKeyProvider(kms_key_id="projects/demo/locations/global/keyRings/r/cryptoKeys/k")
    assert not cloud_kms.is_cloud_verified
    with pytest.raises(KeyManagementError):
        cloud_kms.wrap_dek(b"B" * 32, {"student_id": "stu_demo_001"})
