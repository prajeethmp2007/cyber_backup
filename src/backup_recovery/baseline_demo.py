"""Baseline (unprotected) workflow demonstration for Project 04 Task B.

Demonstrates safely why an unprotected student vault fails under a simulated
ransomware-style benign modification incident when no SHA-256 baseline,
encrypted versioning, or sandbox-isolated recovery controls are present.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .hashing import sha256_file


def run_unprotected_baseline_demo(work_dir: Path) -> dict[str, Any]:
    """Run a safe, self-contained baseline failure demonstration inside `work_dir`."""
    demo_dir = work_dir.resolve()
    demo_dir.mkdir(parents=True, exist_ok=True)
    doc_path = demo_dir / "synthetic_transcript_copy.txt"

    original_text = "SYNTHETIC_STUDENT_RECORD|id=stu_demo_001|course=CS401|grade=A\n"
    doc_path.write_text(original_text, encoding="utf-8")

    # Baseline lacks stored hash registry, encrypted backups, and restoration history
    observed_before = sha256_file(doc_path)

    # Simulate harmless ransomware-style modification on the disposable copy
    tampered_text = "SIMULATED_RANSOM_LOCKED|note=Your test copy was modified cleanly.\n"
    doc_path.write_text(tampered_text, encoding="utf-8")
    observed_after = sha256_file(doc_path)

    return {
        "phase": "baseline_unprotected",
        "target_file": doc_path.name,
        "original_sha256_observed_externally": observed_before,
        "post_incident_sha256": observed_after,
        "stored_hash_baseline_available": False,
        "encrypted_backup_available": False,
        "automatic_detection_triggered": False,
        "recovery_possible": False,
        "restoration_audit_log_present": False,
        "risk_summary": (
            "Without pre-recorded SHA-256 hashes, encrypted versioned vault storage, "
            "and verified recovery, simulated modification goes undetected and data is unrecoverable."
        ),
    }
