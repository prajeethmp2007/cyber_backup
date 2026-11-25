"""Shared pytest fixtures for the Backup & Recovery test suite."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from backup_recovery.config import VaultConfig  # noqa: E402
from backup_recovery.key_management import LocalEnvKeyProvider  # noqa: E402
from backup_recovery.models import ActorContext  # noqa: E402
from backup_recovery.service import BackupRecoveryService  # noqa: E402


@pytest.fixture()
def vault_service(tmp_path: Path) -> Iterator[BackupRecoveryService]:
    cfg = VaultConfig.from_base_dir(tmp_path / "vault_env", max_versions_per_file=5)
    kek = LocalEnvKeyProvider.ephemeral()
    svc = BackupRecoveryService(cfg, key_provider=kek)
    yield svc
    svc.close()


@pytest.fixture()
def student_actor() -> ActorContext:
    return ActorContext(actor_id="stu_demo_001", role="student", two_factor_verified=True)


@pytest.fixture()
def other_student_actor() -> ActorContext:
    return ActorContext(actor_id="stu_demo_002", role="student", two_factor_verified=True)


@pytest.fixture()
def system_actor() -> ActorContext:
    return ActorContext(actor_id="system_scheduler", role="system_scheduler", two_factor_verified=True)
