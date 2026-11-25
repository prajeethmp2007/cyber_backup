"""Cryptographic hashing helpers for integrity verification (SHA-256)."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

CHUNK_SIZE = 65536


def sha256_bytes(data: bytes) -> str:
    """Compute lowercase hexadecimal SHA-256 digest of in-memory bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Compute lowercase hexadecimal SHA-256 digest of a file using streaming reads."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def constant_time_hash_equals(expected_hex: str, observed_hex: str) -> bool:
    """Compare two hex digests in constant time."""
    if not expected_hex or not observed_hex:
        return False
    return hmac.compare_digest(expected_hex.lower(), observed_hex.lower())
