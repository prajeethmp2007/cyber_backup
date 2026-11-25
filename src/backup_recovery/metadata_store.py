"""Metadata repository abstraction and parameterized SQLite implementation.

Designed for clean integration with Member 4 (Database, Security & Testing).
All SQL queries use strict positional `?` placeholders (no string interpolation).
"""

from __future__ import annotations

import sqlite3
import threading
from abc import ABC, abstractmethod
from pathlib import Path

from .models import (
    BackupVersion,
    IntegrityReport,
    IntegrityStatus,
    RestorationRecord,
    RestorationStatus,
    TrackedFile,
    utc_now_iso,
)


class MetadataStore(ABC):
    """Repository interface for files, backup versions, integrity checks, and restoration history."""

    @abstractmethod
    def upsert_tracked_file(self, record: TrackedFile) -> None: ...

    @abstractmethod
    def get_tracked_file(self, file_id: str) -> TrackedFile | None: ...

    @abstractmethod
    def list_tracked_files(self, student_id: str | None = None) -> list[TrackedFile]: ...

    @abstractmethod
    def set_threat_lock(
        self,
        file_id: str,
        *,
        locked: bool,
        reason: str | None = None,
        alert_id: str | None = None,
    ) -> None: ...

    @abstractmethod
    def add_backup_version(self, version: BackupVersion) -> None: ...

    @abstractmethod
    def get_backup_version(self, version_id: str) -> BackupVersion | None: ...

    @abstractmethod
    def list_backup_versions(
        self, file_id: str, *, include_pruned: bool = False
    ) -> list[BackupVersion]: ...

    @abstractmethod
    def list_student_backup_history(
        self, student_id: str, *, limit: int = 100
    ) -> list[BackupVersion]: ...

    @abstractmethod
    def mark_version_status(
        self,
        version_id: str,
        *,
        status: str,
        is_known_good: bool | None = None,
    ) -> None: ...

    @abstractmethod
    def set_version_pinned(self, version_id: str, *, pinned: bool) -> None: ...

    @abstractmethod
    def add_integrity_report(self, report: IntegrityReport) -> None: ...

    @abstractmethod
    def list_integrity_reports(
        self, student_id: str, *, file_id: str | None = None, limit: int = 100
    ) -> list[IntegrityReport]: ...

    @abstractmethod
    def add_restoration_record(self, record: RestorationRecord) -> None: ...

    @abstractmethod
    def list_restoration_history(
        self, student_id: str, *, file_id: str | None = None, limit: int = 100
    ) -> list[RestorationRecord]: ...


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tracked_files (
    file_id TEXT PRIMARY KEY,
    student_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    latest_version_number INTEGER NOT NULL DEFAULT 0,
    latest_version_id TEXT,
    last_known_good_version_id TEXT,
    last_known_good_sha256 TEXT,
    threat_locked INTEGER NOT NULL DEFAULT 0,
    threat_reason TEXT,
    threat_alert_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tracked_files_student
    ON tracked_files(student_id);

CREATE TABLE IF NOT EXISTS backup_versions (
    version_id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    student_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    version_number INTEGER NOT NULL,
    trigger_reason TEXT NOT NULL,
    plaintext_sha256 TEXT NOT NULL,
    encrypted_sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    encrypted_size_bytes INTEGER NOT NULL,
    storage_backend TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    key_id TEXT NOT NULL,
    encryption_algorithm TEXT NOT NULL,
    is_known_good INTEGER NOT NULL DEFAULT 1,
    is_pinned INTEGER NOT NULL DEFAULT 0,
    deduplicated_from_version_id TEXT,
    correlation_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    FOREIGN KEY(file_id) REFERENCES tracked_files(file_id) ON DELETE CASCADE,
    UNIQUE(file_id, version_number)
);

CREATE INDEX IF NOT EXISTS idx_backup_versions_file
    ON backup_versions(file_id, version_number DESC);

CREATE INDEX IF NOT EXISTS idx_backup_versions_student
    ON backup_versions(student_id, created_at DESC);

CREATE TABLE IF NOT EXISTS integrity_checks (
    check_id TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    file_id TEXT NOT NULL,
    student_id TEXT NOT NULL,
    version_id TEXT,
    version_number INTEGER,
    status TEXT NOT NULL,
    live_file_exists INTEGER NOT NULL,
    live_sha256 TEXT,
    expected_plaintext_sha256 TEXT,
    backup_blob_intact INTEGER NOT NULL,
    expected_encrypted_sha256 TEXT,
    observed_encrypted_sha256 TEXT,
    hash_match INTEGER NOT NULL,
    details TEXT NOT NULL,
    checked_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_integrity_checks_student
    ON integrity_checks(student_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS restoration_history (
    restoration_id TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    file_id TEXT NOT NULL,
    student_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    restored_version_id TEXT,
    restored_version_number INTEGER,
    actor_id TEXT NOT NULL,
    trigger_source TEXT NOT NULL,
    pre_restore_live_sha256 TEXT,
    restored_sha256 TEXT,
    expected_known_good_sha256 TEXT,
    verification_passed INTEGER NOT NULL,
    quarantine_evidence_path TEXT,
    status TEXT NOT NULL,
    error_code TEXT,
    notes TEXT NOT NULL,
    restored_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_restoration_history_student
    ON restoration_history(student_id, restored_at DESC);
"""


class SQLiteMetadataStore(MetadataStore):
    """Thread-safe parameterized SQLite implementation of `MetadataStore`."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path.resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.executescript(SCHEMA_SQL)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def _row_to_tracked_file(row: sqlite3.Row) -> TrackedFile:
        return TrackedFile(
            file_id=row["file_id"],
            student_id=row["student_id"],
            filename=row["filename"],
            relative_path=row["relative_path"],
            mime_type=row["mime_type"],
            latest_version_number=row["latest_version_number"],
            latest_version_id=row["latest_version_id"],
            last_known_good_version_id=row["last_known_good_version_id"],
            last_known_good_sha256=row["last_known_good_sha256"],
            threat_locked=bool(row["threat_locked"]),
            threat_reason=row["threat_reason"],
            threat_alert_id=row["threat_alert_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _row_to_backup_version(row: sqlite3.Row) -> BackupVersion:
        return BackupVersion(
            version_id=row["version_id"],
            file_id=row["file_id"],
            student_id=row["student_id"],
            filename=row["filename"],
            version_number=row["version_number"],
            trigger_reason=row["trigger_reason"],
            plaintext_sha256=row["plaintext_sha256"],
            encrypted_sha256=row["encrypted_sha256"],
            size_bytes=row["size_bytes"],
            encrypted_size_bytes=row["encrypted_size_bytes"],
            storage_backend=row["storage_backend"],
            storage_key=row["storage_key"],
            key_id=row["key_id"],
            encryption_algorithm=row["encryption_algorithm"],
            is_known_good=bool(row["is_known_good"]),
            is_pinned=bool(row["is_pinned"]),
            deduplicated_from_version_id=row["deduplicated_from_version_id"],
            correlation_id=row["correlation_id"],
            created_at=row["created_at"],
            status=row["status"],
        )

    @staticmethod
    def _row_to_integrity_report(row: sqlite3.Row) -> IntegrityReport:
        return IntegrityReport(
            check_id=row["check_id"],
            correlation_id=row["correlation_id"],
            file_id=row["file_id"],
            student_id=row["student_id"],
            version_id=row["version_id"],
            version_number=row["version_number"],
            status=IntegrityStatus(row["status"]),
            live_file_exists=bool(row["live_file_exists"]),
            live_sha256=row["live_sha256"],
            expected_plaintext_sha256=row["expected_plaintext_sha256"],
            backup_blob_intact=bool(row["backup_blob_intact"]),
            expected_encrypted_sha256=row["expected_encrypted_sha256"],
            observed_encrypted_sha256=row["observed_encrypted_sha256"],
            hash_match=bool(row["hash_match"]),
            details=row["details"],
            checked_at=row["checked_at"],
        )

    @staticmethod
    def _row_to_restoration_record(row: sqlite3.Row) -> RestorationRecord:
        return RestorationRecord(
            restoration_id=row["restoration_id"],
            correlation_id=row["correlation_id"],
            file_id=row["file_id"],
            student_id=row["student_id"],
            filename=row["filename"],
            restored_version_id=row["restored_version_id"],
            restored_version_number=row["restored_version_number"],
            actor_id=row["actor_id"],
            trigger_source=row["trigger_source"],
            pre_restore_live_sha256=row["pre_restore_live_sha256"],
            restored_sha256=row["restored_sha256"],
            expected_known_good_sha256=row["expected_known_good_sha256"],
            verification_passed=bool(row["verification_passed"]),
            quarantine_evidence_path=row["quarantine_evidence_path"],
            status=RestorationStatus(row["status"]),
            error_code=row["error_code"],
            notes=row["notes"],
            restored_at=row["restored_at"],
        )

    def upsert_tracked_file(self, record: TrackedFile) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO tracked_files (
                    file_id, student_id, filename, relative_path, mime_type,
                    latest_version_number, latest_version_id,
                    last_known_good_version_id, last_known_good_sha256,
                    threat_locked, threat_reason, threat_alert_id,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(file_id) DO UPDATE SET
                    filename = excluded.filename,
                    relative_path = excluded.relative_path,
                    mime_type = excluded.mime_type,
                    latest_version_number = excluded.latest_version_number,
                    latest_version_id = excluded.latest_version_id,
                    last_known_good_version_id = excluded.last_known_good_version_id,
                    last_known_good_sha256 = excluded.last_known_good_sha256,
                    threat_locked = excluded.threat_locked,
                    threat_reason = excluded.threat_reason,
                    threat_alert_id = excluded.threat_alert_id,
                    updated_at = excluded.updated_at
                """,
                (
                    record.file_id,
                    record.student_id,
                    record.filename,
                    record.relative_path,
                    record.mime_type,
                    record.latest_version_number,
                    record.latest_version_id,
                    record.last_known_good_version_id,
                    record.last_known_good_sha256,
                    int(record.threat_locked),
                    record.threat_reason,
                    record.threat_alert_id,
                    record.created_at,
                    record.updated_at,
                ),
            )
            self._conn.commit()

    def get_tracked_file(self, file_id: str) -> TrackedFile | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tracked_files WHERE file_id = ?",
                (file_id,),
            ).fetchone()
            return self._row_to_tracked_file(row) if row else None

    def list_tracked_files(self, student_id: str | None = None) -> list[TrackedFile]:
        with self._lock:
            if student_id is None:
                rows = self._conn.execute(
                    "SELECT * FROM tracked_files ORDER BY updated_at DESC, rowid DESC"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM tracked_files WHERE student_id = ? ORDER BY updated_at DESC, rowid DESC",
                    (student_id,),
                ).fetchall()
            return [self._row_to_tracked_file(r) for r in rows]

    def set_threat_lock(
        self,
        file_id: str,
        *,
        locked: bool,
        reason: str | None = None,
        alert_id: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE tracked_files
                SET threat_locked = ?, threat_reason = ?, threat_alert_id = ?, updated_at = ?
                WHERE file_id = ?
                """,
                (int(locked), reason, alert_id, utc_now_iso(), file_id),
            )
            self._conn.commit()

    def add_backup_version(self, version: BackupVersion) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO backup_versions (
                    version_id, file_id, student_id, filename, version_number,
                    trigger_reason, plaintext_sha256, encrypted_sha256,
                    size_bytes, encrypted_size_bytes, storage_backend,
                    storage_key, key_id, encryption_algorithm,
                    is_known_good, is_pinned, deduplicated_from_version_id,
                    correlation_id, created_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    version.version_id,
                    version.file_id,
                    version.student_id,
                    version.filename,
                    version.version_number,
                    version.trigger_reason,
                    version.plaintext_sha256,
                    version.encrypted_sha256,
                    version.size_bytes,
                    version.encrypted_size_bytes,
                    version.storage_backend,
                    version.storage_key,
                    version.key_id,
                    version.encryption_algorithm,
                    int(version.is_known_good),
                    int(version.is_pinned),
                    version.deduplicated_from_version_id,
                    version.correlation_id,
                    version.created_at,
                    version.status,
                ),
            )
            self._conn.commit()

    def get_backup_version(self, version_id: str) -> BackupVersion | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM backup_versions WHERE version_id = ?",
                (version_id,),
            ).fetchone()
            return self._row_to_backup_version(row) if row else None

    def list_backup_versions(
        self, file_id: str, *, include_pruned: bool = False
    ) -> list[BackupVersion]:
        with self._lock:
            if include_pruned:
                rows = self._conn.execute(
                    "SELECT * FROM backup_versions WHERE file_id = ? ORDER BY version_number DESC",
                    (file_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT * FROM backup_versions
                    WHERE file_id = ? AND status != 'PRUNED'
                    ORDER BY version_number DESC
                    """,
                    (file_id,),
                ).fetchall()
            return [self._row_to_backup_version(r) for r in rows]

    def list_student_backup_history(
        self, student_id: str, *, limit: int = 100
    ) -> list[BackupVersion]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM backup_versions
                WHERE student_id = ?
                ORDER BY created_at DESC, version_number DESC, rowid DESC
                LIMIT ?
                """,
                (student_id, limit),
            ).fetchall()
            return [self._row_to_backup_version(r) for r in rows]

    def mark_version_status(
        self,
        version_id: str,
        *,
        status: str,
        is_known_good: bool | None = None,
    ) -> None:
        with self._lock:
            if is_known_good is None:
                self._conn.execute(
                    "UPDATE backup_versions SET status = ? WHERE version_id = ?",
                    (status, version_id),
                )
            else:
                self._conn.execute(
                    "UPDATE backup_versions SET status = ?, is_known_good = ? WHERE version_id = ?",
                    (status, int(is_known_good), version_id),
                )
            self._conn.commit()

    def set_version_pinned(self, version_id: str, *, pinned: bool) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE backup_versions SET is_pinned = ? WHERE version_id = ?",
                (int(pinned), version_id),
            )
            self._conn.commit()

    def add_integrity_report(self, report: IntegrityReport) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO integrity_checks (
                    check_id, correlation_id, file_id, student_id,
                    version_id, version_number, status,
                    live_file_exists, live_sha256, expected_plaintext_sha256,
                    backup_blob_intact, expected_encrypted_sha256, observed_encrypted_sha256,
                    hash_match, details, checked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.check_id,
                    report.correlation_id,
                    report.file_id,
                    report.student_id,
                    report.version_id,
                    report.version_number,
                    report.status.value,
                    int(report.live_file_exists),
                    report.live_sha256,
                    report.expected_plaintext_sha256,
                    int(report.backup_blob_intact),
                    report.expected_encrypted_sha256,
                    report.observed_encrypted_sha256,
                    int(report.hash_match),
                    report.details,
                    report.checked_at,
                ),
            )
            self._conn.commit()

    def list_integrity_reports(
        self, student_id: str, *, file_id: str | None = None, limit: int = 100
    ) -> list[IntegrityReport]:
        with self._lock:
            if file_id:
                rows = self._conn.execute(
                    """
                    SELECT * FROM integrity_checks
                    WHERE student_id = ? AND file_id = ?
                    ORDER BY checked_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (student_id, file_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT * FROM integrity_checks
                    WHERE student_id = ?
                    ORDER BY checked_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (student_id, limit),
                ).fetchall()
            return [self._row_to_integrity_report(r) for r in rows]

    def add_restoration_record(self, record: RestorationRecord) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO restoration_history (
                    restoration_id, correlation_id, file_id, student_id, filename,
                    restored_version_id, restored_version_number, actor_id, trigger_source,
                    pre_restore_live_sha256, restored_sha256, expected_known_good_sha256,
                    verification_passed, quarantine_evidence_path, status, error_code,
                    notes, restored_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.restoration_id,
                    record.correlation_id,
                    record.file_id,
                    record.student_id,
                    record.filename,
                    record.restored_version_id,
                    record.restored_version_number,
                    record.actor_id,
                    record.trigger_source,
                    record.pre_restore_live_sha256,
                    record.restored_sha256,
                    record.expected_known_good_sha256,
                    int(record.verification_passed),
                    record.quarantine_evidence_path,
                    record.status.value,
                    record.error_code,
                    record.notes,
                    record.restored_at,
                ),
            )
            self._conn.commit()

    def list_restoration_history(
        self, student_id: str, *, file_id: str | None = None, limit: int = 100
    ) -> list[RestorationRecord]:
        with self._lock:
            if file_id:
                rows = self._conn.execute(
                    """
                    SELECT * FROM restoration_history
                    WHERE student_id = ? AND file_id = ?
                    ORDER BY restored_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (student_id, file_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT * FROM restoration_history
                    WHERE student_id = ?
                    ORDER BY restored_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (student_id, limit),
                ).fetchall()
            return [self._row_to_restoration_record(r) for r in rows]
