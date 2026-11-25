"""Automated verification of MindMatrix Project 04 Required Test Matrix (T01-T08)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scripts.run_project04_evidence import generate_all_evidence  # noqa: E402


def test_project04_required_matrix_t01_through_t08(tmp_path):
    summary = generate_all_evidence(evidence_dir=tmp_path / "evidence")
    tests = summary["tests"]
    for tid in ("T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08"):
        assert tests[tid] is True, f"Project 04 required test {tid} failed: {summary}"
