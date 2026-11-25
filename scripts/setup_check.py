"""First-run workspace & environment verification (PDF 2 Section 6)."""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run_version(cmd: list[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=5)
        return out.strip().splitlines()[0]
    except Exception as exc:
        return f"NOT_AVAILABLE ({type(exc).__name__})"


def main() -> int:
    required_dirs = ["docs", "src", "tests", "evidence", "report", "scripts"]
    missing = [d for d in required_dirs if not (ROOT / d).is_dir()]

    try:
        import cryptography  # noqa: F401
        crypto_status = f"Pass ({cryptography.__version__})"
    except Exception as exc:
        crypto_status = f"Blocked ({exc})"

    try:
        import pytest  # noqa: F401
        pytest_status = f"Pass ({pytest.__version__})"
    except Exception as exc:
        pytest_status = f"Blocked ({exc})"

    report_lines = [
        "=== Infrastructure First-Run Setup Check (MindMatrix PDF 2 Sec 6) ===",
        f"Timestamp (UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"OS: {platform.system()} {platform.release()} ({platform.machine()})",
        f"Python: {sys.version.split()[0]}",
        f"Git: {_run_version(['git', '--version'])}",
        f"Docker (optional): {_run_version(['docker', '--version']) if shutil.which('docker') else 'N/A (not required for local adapter)'}",
        f"cryptography package: {crypto_status}",
        f"pytest package: {pytest_status}",
        f"Workspace folders present: {'Pass' if not missing else f'Missing {missing}'}",
        f"Evidence writable: Pass ({ROOT / 'evidence'})",
    ]
    output = "\n".join(report_lines) + "\n"
    evidence_path = ROOT / "evidence" / "setup-check.txt"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(output, encoding="utf-8")
    print(output)
    return 0 if not missing and crypto_status.startswith("Pass") and pytest_status.startswith("Pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())
