"""Structured security event logger with strict secret/PII redaction.

Satisfies Project 04 Task D, T05, T06, and T07:
- Logs event_type, timestamp, outcome, correlation_id, actor_id, file_id, version_id.
- Never logs passwords, tokens, key material, connection strings, or raw file payloads.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import utc_now_iso

SENSITIVE_KEY_TOKENS = (
    "password",
    "passwd",
    "secret",
    "token",
    "key",
    "kek",
    "dek",
    "private",
    "credential",
    "authorization",
    "cookie",
    "payload",
    "plaintext",
    "ciphertext",
    "content",
    "connection_string",
    "dsn",
)

SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)(postgres|postgresql|mysql|mongodb|redis)://[^\s]+"),
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*[^\s,;]+"),
)


NON_SECRET_ALLOWED_KEYS = {
    "key_id",
    "key_provider_mode",
    "encryption_algorithm",
}


def sanitize_value(value: Any, field_name: str = "") -> Any:
    """Recursively redact sensitive keys and sensitive string patterns."""
    lowered = field_name.lower()
    if lowered and any(tok in lowered for tok in SENSITIVE_KEY_TOKENS):
        # Allow non-secret identifier metadata and SHA-256 integrity digests
        if lowered not in NON_SECRET_ALLOWED_KEYS and not lowered.endswith("_sha256"):
            return "[REDACTED]"

    if isinstance(value, dict):
        return {str(k): sanitize_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(item, field_name) for item in value]
    if isinstance(value, str):
        for pat in SENSITIVE_VALUE_PATTERNS:
            if pat.search(value):
                return "[REDACTED_SENSITIVE_PATTERN]"
        return value[:512]
    return value


class SecurityEventLogger:
    """Writes sanitized structured JSONL security events for audit & investigation."""

    def __init__(self, log_file_path: Path) -> None:
        self.log_file_path = log_file_path
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        *,
        event_type: str,
        outcome: str,
        correlation_id: str,
        actor_id: str | None = None,
        student_id: str | None = None,
        file_id: str | None = None,
        version_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append one sanitized security event record to the JSONL log."""
        event: dict[str, Any] = {
            "timestamp": utc_now_iso(),
            "event_type": event_type,
            "outcome": outcome,
            "correlation_id": correlation_id,
            "actor_id": actor_id or "anonymous",
            "student_id": student_id,
            "file_id": file_id,
            "version_id": version_id,
            "details": sanitize_value(details or {}),
        }
        line = json.dumps(event, sort_keys=True, separators=(",", ":"))
        with self.log_file_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        return event

    def read_events(self, *, limit: int = 100, event_type: str | None = None) -> list[dict[str, Any]]:
        """Read recent logged security events in reverse chronological order."""
        if not self.log_file_path.exists():
            return []
        events: list[dict[str, Any]] = []
        with self.log_file_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                record = json.loads(raw_line)
                if event_type and record.get("event_type") != event_type:
                    continue
                events.append(record)
        events.reverse()
        return events[:limit]
