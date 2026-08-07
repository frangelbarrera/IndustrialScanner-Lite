"""Tests for s7_comm_analyzer.s7_analyze.

Uses real (anonymized) PCAP files from pcaps/s7/ plus a synthetic minimal
PCAP generated on the fly to test analyze_pcap, write_json_report, and
write_html_report.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap

from s7_comm_analyzer.parsers import (
    FUNC_READ_VAR,
    FUNC_STOP,
    FUNC_WRITE_VAR,
    ROSCTR_JOB,
    S7_PROTOCOL_ID,
)
from s7_comm_analyzer.s7_analyze import (
    analyze_pcap,
    main,
    write_html_report,
    write_json_report,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _build_s7_packet(src="10.0.0.1", dst="10.0.0.2", func=FUNC_READ_VAR):
    """Build a single S7 packet as a scapy Packet."""
    payload = (
        bytes([S7_PROTOCOL_ID, ROSCTR_JOB])
        + b"\x00\x00"
        + b"\x00\x00"  # pdu_ref
        + b"\x00\x02"  # param_len
        + b"\x00\x00"  # data_len
        + bytes([func, 0x00])
    )
    return Ether() / IP(src=src, dst=dst) / TCP(dport=102) / Raw(load=payload)


def _build_pcap_file(path: Path, packets: list):
    """Write a list of packets to a PCAP file."""
    wrpcap(str(path), packets)


# ---------------------------------------------------------------------------
# analyze_pcap tests
# ---------------------------------------------------------------------------
class TestAnalyzePcap:
    def test_analyzes_synthetic_pcap(self, tmp_path):
        """analyze_pcap should extract S7 packets from a synthetic PCAP."""
        pcap_path = tmp_path / "test.pcapng"
        pkts = [
            _build_s7_packet(func=FUNC_READ_VAR),
            _build_s7_packet(func=FUNC_WRITE_VAR),
            _build_s7_packet(func=FUNC_STOP),
        ]
        _build_pcap_file(pcap_path, pkts)

        result = analyze_pcap(str(pcap_path))
        assert "meta" in result
        assert "results" in result
        assert "summary" in result
        assert result["summary"]["total_packets"] == 3
        assert result["summary"]["s7_packets"] == 3
        # WriteVar and Stop are suspect; ReadVar is not
        assert result["summary"]["suspect_functions"] == 2
        # Hosts should be the two IPs
        assert "10.0.0.1" in result["summary"]["unique_hosts"]
        assert "10.0.0.2" in result["summary"]["unique_hosts"]

    def test_handles_non_s7_traffic(self, tmp_path):
        """Non-S7 packets should not appear in results but should be counted."""
        pcap_path = tmp_path / "non_s7.pcapng"
        # An IP packet without TCP/102 and without S7 magic
        non_s7_pkt = (
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(dport=80)
            / Raw(load=b"GET / HTTP/1.1")
        )
        s7_pkt = _build_s7_packet()
        _build_pcap_file(pcap_path, [non_s7_pkt, s7_pkt])

        result = analyze_pcap(str(pcap_path))
        assert result["summary"]["total_packets"] == 2
        assert result["summary"]["s7_packets"] == 1

    def test_empty_pcap(self, tmp_path):
        """An empty PCAP should produce zero results."""
        pcap_path = tmp_path / "empty.pcapng"
        _build_pcap_file(pcap_path, [])
        result = analyze_pcap(str(pcap_path))
        assert result["summary"]["total_packets"] == 0
        assert result["summary"]["s7_packets"] == 0
        assert result["results"] == []

    def test_real_pcap_file(self):
        """Test against a real (anonymized) PCAP from the repo.

        The step7_s300_stop.pcapng file contains S7Comm traffic wrapped in
        TPKT/COTP framing. After the TPKT/COTP unwrapping fix in parsers.py,
        the analyzer should detect S7 packets.
        """
        pcap_path = REPO_ROOT / "pcaps" / "s7" / "step7_s300_stop.pcapng"
        if not pcap_path.exists():
            pytest.skip(f"Test PCAP not found: {pcap_path}")
        result = analyze_pcap(str(pcap_path))
        assert result["summary"]["total_packets"] > 0
        # After TPKT/COTP unwrapping, S7 packets should be detected.
        # The stop.pcapng contains 2 S7 packets (request + response).
        assert result["summary"]["s7_packets"] > 0


# ---------------------------------------------------------------------------
# write_json_report tests
# ---------------------------------------------------------------------------
class TestWriteJsonReport:
    def test_writes_valid_json(self, tmp_path):
        data = {"meta": {}, "results": [], "summary": {}}
        out = tmp_path / "report.json"
        result = write_json_report(data, out)
        assert result == out
        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded == data

    def test_creates_parent_dir(self, tmp_path):
        data = {"results": []}
        out = tmp_path / "subdir" / "report.json"
        write_json_report(data, out)
        assert out.exists()


# ---------------------------------------------------------------------------
# write_html_report tests
# ---------------------------------------------------------------------------
class TestWriteHtmlReport:
    def test_writes_html_with_autoescape(self, tmp_path):
        """HTML report should escape untrusted PCAP-derived content."""
        malicious = "<script>alert(1)</script>"
        data = {
            "meta": {"generated_at": "2025-01-01", "pcap_file": malicious},
            "results": [
                {
                    "src": malicious,
                    "dst": malicious,
                    "function_code": "ReadVar",
                    "length": 10,
                    "hints": [malicious],
                    "rosctr": "Job",
                    "pdu_ref": 0,
                }
            ],
            "summary": {
                "total_packets": 1,
                "s7_packets": 1,
                "suspect_functions": 0,
                "unique_hosts": [malicious],
            },
        }
        template_dir = REPO_ROOT / "reports" / "templates"
        out = tmp_path / "report.html"
        if template_dir.exists():
            write_html_report(data, out)
            content = out.read_text()
            # The malicious script tag should be escaped
            assert "<script>alert(1)</script>" not in content


# ---------------------------------------------------------------------------
# main tests
# ---------------------------------------------------------------------------
class TestMain:
    def test_main_no_pcap_dir(self, tmp_path, monkeypatch, caplog):
        """main should log an error when the PCAP dir does not exist."""
        # Patch PCAP_DIR to a non-existent path
        import s7_comm_analyzer.s7_analyze as mod

        monkeypatch.setattr(mod, "PCAP_DIR", tmp_path / "nonexistent")
        monkeypatch.setattr(mod, "OUT_DIR", tmp_path / "out")

        # Should not raise
        main()
        # No reports should be generated
        assert not (tmp_path / "out").exists() or not list((tmp_path / "out").iterdir())

    def test_main_processes_pcaps(self, tmp_path, monkeypatch):
        """main should process all PCAPs in PCAP_DIR."""
        pcap_dir = tmp_path / "pcaps"
        out_dir = tmp_path / "out"
        pcap_dir.mkdir()
        out_dir.mkdir()

        # Create a synthetic PCAP
        pcap_path = pcap_dir / "test.pcapng"
        pkts = [_build_s7_packet(func=FUNC_READ_VAR)]
        _build_pcap_file(pcap_path, pkts)

        import s7_comm_analyzer.s7_analyze as mod

        monkeypatch.setattr(mod, "PCAP_DIR", pcap_dir)
        monkeypatch.setattr(mod, "OUT_DIR", out_dir)

        main()
        json_out = out_dir / "test.json"
        html_out = out_dir / "test.html"
        assert json_out.exists()
        assert html_out.exists()
