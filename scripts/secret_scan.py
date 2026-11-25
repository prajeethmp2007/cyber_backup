"""Sensitive data & secret leakage scanner for Project 04 T07."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SCAN_PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key_block": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "bearer_token": re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{12,}=*"),
    "db_connection_string": re.compile(r"(?i)(postgres|postgresql|mysql|mongodb|redis)://[^\s'\"`]+"),
    "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "hardcoded_secret_assignment": re.compile(
        r"""(?i)\b(kek_bytes|master_key|api_key|db_password|secret_key)\s*=\s*["'][A-Za-z0-9+/=_-]{16,}["']"""
    ),
}

SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache", ".local_keys", "runtime_vault", "runtime_sandbox"}


def scan_directories(directories: list[Path], *, exclude_files: set[Path] | None = None) -> dict[str, Any]:
    """Scan specified project directories and return sanitized findings."""
    findings: list[dict[str, Any]] = []
    files_scanned = 0
    excluded = {p.resolve() for p in (exclude_files or set())}

    for base in directories:
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_dir() or any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.resolve() in excluded:
                continue
            if path.suffix.lower() in {".png", ".jpg", ".db", ".sqlite3", ".svbk", ".pyc"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files_scanned += 1
            for lineno, line in enumerate(text.splitlines(), start=1):
                for rule_name, pattern in SCAN_PATTERNS.items():
                    if pattern.search(line):
                        findings.append(
                            {
                                "file": str(path.relative_to(ROOT)).replace("\\", "/"),
                                "line": lineno,
                                "rule": rule_name,
                                "snippet": "[REDACTED_MATCH]",
                            }
                        )

    return {
        "files_scanned": files_scanned,
        "findings_count": len(findings),
        "clean": len(findings) == 0,
        "findings": findings,
    }


def main() -> int:
    targets = [ROOT / "src", ROOT / "tests", ROOT / "evidence", ROOT / "docs", ROOT / "report"]
    # Exclude this scanner file's regex definitions from self-matching
    report = scan_directories(targets, exclude_files={Path(__file__)})
    out_path = ROOT / "evidence" / "T07-sensitive-data-scan.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["clean"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
