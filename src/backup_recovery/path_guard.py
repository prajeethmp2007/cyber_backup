"""Sandbox confinement and identifier validation (Project 04 T04).

Prevents path traversal, symlink escapes, and accidental or malicious modification
of files outside designated sandbox, vault, and quarantine directories.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .exceptions import SandboxViolationError, ValidationError

SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_identifier(value: str, field_name: str) -> str:
    """Validate synthetic student, file, or version identifiers against strict allow-list."""
    if not isinstance(value, str) or not SAFE_ID_PATTERN.match(value):
        raise ValidationError(
            f"Invalid {field_name}: must be 1-64 alphanumeric, dot, underscore, or hyphen chars."
        )
    if ".." in value:
        raise ValidationError(f"Invalid {field_name}: path traversal tokens are not allowed.")
    return value


class SandboxGuard:
    """Confines filesystem paths strictly inside configured root directories."""

    def __init__(self, sandbox_root: Path, vault_root: Path, quarantine_root: Path) -> None:
        self.sandbox_root = sandbox_root.resolve()
        self.vault_root = vault_root.resolve()
        self.quarantine_root = quarantine_root.resolve()

    @staticmethod
    def _ensure_within_root(candidate: Path, root: Path, label: str) -> Path:
        resolved_root = root.resolve()
        # Check raw symlink segments along path before resolving target
        if os.path.isabs(str(candidate)):
            try:
                resolved_candidate = candidate.resolve()
            except OSError as exc:
                raise SandboxViolationError(f"Cannot resolve path inside {label}.") from exc
        else:
            resolved_candidate = (resolved_root / candidate).resolve()

        try:
            resolved_candidate.relative_to(resolved_root)
        except ValueError as exc:
            raise SandboxViolationError(
                f"Access blocked: target path lies outside designated {label}."
            ) from exc

        # Reject symlinks anywhere along the path inside the root to prevent symlink escape
        rel_parts = resolved_candidate.relative_to(resolved_root).parts
        probe = resolved_root
        for part in rel_parts:
            probe = probe / part
            if probe.is_symlink():
                raise SandboxViolationError(
                    f"Access blocked: symbolic links are disallowed inside {label}."
                )

        return resolved_candidate

    def resolve_sandbox_path(self, student_id: str, relative_or_sandbox_path: str | Path) -> Path:
        """Resolve a student's file path strictly inside `<sandbox_root>/<student_id>/`."""
        safe_student = validate_identifier(student_id, "student_id")
        student_sandbox = (self.sandbox_root / safe_student).resolve()
        student_sandbox.mkdir(parents=True, exist_ok=True)

        raw = str(relative_or_sandbox_path)
        if not raw or "\x00" in raw:
            raise ValidationError("File path must be a non-empty valid path.")

        candidate = Path(raw)
        if candidate.is_absolute():
            # Allow an absolute path ONLY if it is already strictly inside this student's sandbox
            return self._ensure_within_root(candidate, student_sandbox, "student sandbox")

        # Reject explicit traversal tokens early
        if any(part == ".." for part in candidate.parts):
            raise SandboxViolationError("Path traversal ('..') is blocked in sandbox paths.")

        return self._ensure_within_root(student_sandbox / candidate, student_sandbox, "student sandbox")

    def resolve_vault_key(self, storage_key: str) -> Path:
        """Resolve a vault storage key strictly inside `<vault_root>/`."""
        if not storage_key or "\x00" in storage_key or storage_key.startswith(("/", "\\")):
            raise SandboxViolationError("Invalid vault storage key.")
        candidate = Path(storage_key)
        if candidate.is_absolute() or any(part == ".." for part in candidate.parts):
            raise SandboxViolationError("Path traversal is blocked in vault storage keys.")
        return self._ensure_within_root(self.vault_root / candidate, self.vault_root, "vault storage")

    def resolve_quarantine_path(self, student_id: str, filename: str) -> Path:
        """Resolve a quarantine forensic copy path inside `<quarantine_root>/<student_id>/`."""
        safe_student = validate_identifier(student_id, "student_id")
        safe_name = Path(filename).name
        if not safe_name or safe_name in {".", ".."}:
            raise ValidationError("Invalid quarantine filename.")
        student_q = (self.quarantine_root / safe_student).resolve()
        student_q.mkdir(parents=True, exist_ok=True)
        return self._ensure_within_root(student_q / safe_name, student_q, "quarantine storage")
