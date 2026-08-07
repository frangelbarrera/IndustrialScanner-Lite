"""Snapshot tests for HTML report builders.

These tests verify that the HTML output of the 4 builders (build_modbus_index,
build_s7_index, build_dnp3_index, build_global_index) is deterministic and
matches a saved baseline. If the HTML format changes intentionally, run:
    UPDATE_SNAPSHOTS=1 pytest tests/test_html_snapshots.py
to regenerate the baselines.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO_ROOT = Path("/home/z/my-project/repos/IndustrialScanner-Lite")
SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
SNAPSHOT_DIR.mkdir(exist_ok=True)

UPDATE_SNAPSHOTS = os.environ.get("UPDATE_SNAPSHOTS", "0") == "1"

# Fixed timestamp for deterministic snapshot comparison.
FIXED_NOW = "2025-01-01 00:00:00Z"


def _compare_or_update(snapshot_path: Path, actual: str) -> None:
    """Compare actual output to saved snapshot, or update if UPDATE_SNAPSHOTS=1."""
    if UPDATE_SNAPSHOTS:
        snapshot_path.write_text(actual, encoding="utf-8")
        pytest.skip(f"Snapshot updated: {snapshot_path.name}")
    elif not snapshot_path.exists():
        snapshot_path.write_text(actual, encoding="utf-8")
        pytest.skip(f"Snapshot created: {snapshot_path.name}")
    else:
        expected = snapshot_path.read_text(encoding="utf-8")
        assert actual == expected, (
            f"HTML output changed from snapshot.\n"
            f"Snapshot: {snapshot_path}\n"
            f"Actual length: {len(actual)}\n"
            f"Expected length: {len(expected)}\n"
            f"Run with UPDATE_SNAPSHOTS=1 to update."
        )


# ---------------------------------------------------------------------------
# Modbus index snapshot
# ---------------------------------------------------------------------------
class TestModbusIndexSnapshot:
    def test_empty_reports(self, tmp_path):
        """build_modbus_index with no reports should produce stable HTML."""
        import build_modbus_index as mod

        html = mod.build_index([], now_override=FIXED_NOW)
        snapshot_path = SNAPSHOT_DIR / "modbus_index_empty.html"
        _compare_or_update(snapshot_path, html)

    def test_with_one_report(self, tmp_path):
        """build_modbus_index with one report should produce stable HTML."""
        import build_modbus_index as mod

        reports = [
            {
                "json": "test.json",
                "html": "test.html",
                "meta": {"generated_at": "2025-01-01T00:00:00Z", "pcap_file": "test.pcap"},
                "summary": {"total_packets": 10, "modbus_packets": 8, "suspect_functions": 0},
            }
        ]
        html = mod.build_index(reports, now_override=FIXED_NOW)
        snapshot_path = SNAPSHOT_DIR / "modbus_index_one_report.html"
        _compare_or_update(snapshot_path, html)


# ---------------------------------------------------------------------------
# S7 index snapshot
# ---------------------------------------------------------------------------
class TestS7IndexSnapshot:
    def test_empty_reports(self, tmp_path):
        import build_s7_index as s7

        html = s7.build_index([], now_override=FIXED_NOW)
        snapshot_path = SNAPSHOT_DIR / "s7_index_empty.html"
        _compare_or_update(snapshot_path, html)


# ---------------------------------------------------------------------------
# DNP3 index snapshot
# ---------------------------------------------------------------------------
class TestDnp3IndexSnapshot:
    def test_empty_reports(self, tmp_path):
        import build_dnp3_index as dnp3

        html = dnp3.build_index([], now_override=FIXED_NOW)
        snapshot_path = SNAPSHOT_DIR / "dnp3_index_empty.html"
        _compare_or_update(snapshot_path, html)


# ---------------------------------------------------------------------------
# Global index snapshot
# ---------------------------------------------------------------------------
class TestGlobalIndexSnapshot:
    def test_empty_results(self, tmp_path):
        import build_global_index as g

        html = g.build_index(
            {"Modbus": (0, 0, 0), "S7Comm": (0, 0, 0), "DNP3": (0, 0, 0)},
            now_override=FIXED_NOW,
        )
        snapshot_path = SNAPSHOT_DIR / "global_index_empty.html"
        _compare_or_update(snapshot_path, html)

    def test_with_results(self, tmp_path):
        import build_global_index as g

        html = g.build_index(
            {
                "Modbus": (5, 100, 0),
                "S7Comm": (10, 500, 3),
                "DNP3": (8, 200, 1),
            },
            now_override=FIXED_NOW,
        )
        snapshot_path = SNAPSHOT_DIR / "global_index_with_data.html"
        _compare_or_update(snapshot_path, html)
