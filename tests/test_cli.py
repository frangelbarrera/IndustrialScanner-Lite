"""Tests for the unified CLI entry point."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from ics_scanner.cli import cli

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestCliBasics:
    def test_help_lists_commands(self, runner: CliRunner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        for cmd in ("modbus", "s7", "dnp3"):
            assert cmd in result.output

    def test_version(self, runner: CliRunner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0


class TestModbusCommand:
    def test_public_target_refused_without_flag(self, runner: CliRunner):
        result = runner.invoke(cli, ["modbus", "--targets", "8.8.8.8"])
        assert result.exit_code == 2
        assert "No safe targets" in result.output

    def test_private_unreachable_target_reports_failure(self, runner: CliRunner, tmp_path: Path):
        result = runner.invoke(
            cli,
            [
                "modbus",
                "--targets",
                "127.0.0.1",
                "--port",
                "65020",
                "--timeout",
                "0.2",
                "--json-out",
                str(tmp_path / "m.json"),
                "--html-out",
                str(tmp_path / "m.html"),
            ],
        )
        assert result.exit_code == 0
        assert (tmp_path / "m.json").exists()
        assert (tmp_path / "m.html").exists()


class TestS7Command:
    def test_analyze_stop_pcap(self, runner: CliRunner, tmp_path: Path):
        pcap = REPO_ROOT / "pcaps" / "s7" / "step7_s300_stop.pcapng"
        if not pcap.exists():
            pytest.skip(f"PCAP not present: {pcap}")
        result = runner.invoke(
            cli,
            [
                "s7",
                "--pcap",
                str(pcap),
                "--json-out",
                str(tmp_path / "s.json"),
                "--html-out",
                str(tmp_path / "s.html"),
            ],
        )
        assert result.exit_code == 0
        assert (tmp_path / "s.json").exists()
        assert (tmp_path / "s.html").exists()


class TestDnp3Command:
    def test_analyze_read_pcap(self, runner: CliRunner, tmp_path: Path):
        pcap = REPO_ROOT / "pcaps" / "dnp3" / "read_and_response.pcap"
        if not pcap.exists():
            pytest.skip(f"PCAP not present: {pcap}")
        result = runner.invoke(
            cli,
            [
                "dnp3",
                "--pcap",
                str(pcap),
                "--json-out",
                str(tmp_path / "d.json"),
                "--html-out",
                str(tmp_path / "d.html"),
            ],
        )
        assert result.exit_code == 0
        assert (tmp_path / "d.json").exists()
        assert (tmp_path / "d.html").exists()
