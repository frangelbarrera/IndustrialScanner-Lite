"""Regression tests for TPKT/COTP-framed S7 traffic classification.

Real S7Comm traffic on TCP/102 always carries TPKT (RFC 1006) + COTP framing
in front of the S7 PDU, and programming commands (password reads, SZL
queries, LED control) travel inside Userdata frames with a nested header.
These tests pin classification behaviour against both synthetic framed frames
and the real PCAP corpus shipped in the repo, so a framing or offset
regression cannot reach the wire pipeline unnoticed.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, Raw

from s7_comm_analyzer.parsers import (
    FUNC_DOWNLOAD_BLOCK,
    FUNC_READ_VAR,
    FUNC_SETUP_COMM,
    FUNC_STOP,
    FUNC_WRITE_VAR,
    ROSCTR_JOB,
    S7_PROTOCOL_ID,
    parse_s7_packet,
)
from s7_comm_analyzer.s7_analyze import analyze_pcap

REPO_ROOT = Path(__file__).resolve().parents[1]
S7_PCAP_DIR = REPO_ROOT / "pcaps" / "s7"


def _s7_pdu(rosctr: int, func: int, data: bytes = b"") -> bytes:
    param = bytes([func, 0x00])
    return (
        bytes([S7_PROTOCOL_ID, rosctr])
        + b"\x00\x00"
        + b"\x00\x01"
        + len(param).to_bytes(2, "big")
        + len(data).to_bytes(2, "big")
        + param
        + data
    )


def _tpkt_cotp(pdu: bytes) -> bytes:
    """Standard on-the-wire framing: TPKT header + COTP DT class 0."""
    return b"\x03\x00" + (7 + len(pdu)).to_bytes(2, "big") + b"\x02\xf0\x80" + pdu


def _s7pkt(payload: bytes):
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=102) / Raw(load=payload)


class TestFramedClassification:
    """TPKT/COTP framing must not change the classified function."""

    @pytest.mark.parametrize(
        ("func", "expected"),
        [
            (FUNC_READ_VAR, "ReadVar"),
            (FUNC_WRITE_VAR, "WriteVar"),
            (FUNC_STOP, "Stop"),
            (FUNC_SETUP_COMM, "SetupComm"),
            (FUNC_DOWNLOAD_BLOCK, "DownloadBlock"),
        ],
    )
    def test_framed_frame_classifies_like_raw(self, func, expected):
        pdu = _s7_pdu(ROSCTR_JOB, func)
        raw = parse_s7_packet(_s7pkt(pdu))
        framed = parse_s7_packet(_s7pkt(_tpkt_cotp(pdu)))

        assert raw is not None
        assert raw["function_code"] == expected
        assert framed is not None
        assert framed["function_code"] == expected


class TestGoldenRealPcaps:
    """Golden classification over the real capture corpus."""

    def _functions(self, name: str) -> Counter:
        path = S7_PCAP_DIR / name
        if not path.exists():
            pytest.skip(f"PCAP not present: {path}")
        result = analyze_pcap(str(path))
        return Counter(r["function_code"] for r in result["results"])

    def test_step7_stop_detects_stop(self):
        assert self._functions("step7_s300_stop.pcapng")["Stop"] >= 1

    def test_snap7_stop_detects_stop(self):
        assert self._functions("snap7_s300_stop.pcapng")["Stop"] >= 1

    def test_wincc_read_write_detects_both(self):
        functions = self._functions("wincc_s300_setup-alarm-read-write.pcapng")
        assert functions["ReadVar"] >= 1
        assert functions["WriteVar"] >= 1

    def test_auth_password_detects_password(self):
        assert self._functions("step7_s300_AuthPassword.pcapng")["Password"] >= 1

    def test_copy_ram_to_rom_detected(self):
        assert self._functions("step7_s300_copyRamToRom.pcapng")["CopyRamToRom"] >= 1

    def test_firmware_update_detects_downloads(self):
        functions = self._functions("tia_s300_updateFirmware.pcapng")
        assert functions["DownloadBlock"] >= 1000

    def test_stop_report_marks_suspects(self):
        path = S7_PCAP_DIR / "step7_s300_stop.pcapng"
        if not path.exists():
            pytest.skip(f"PCAP not present: {path}")
        result = analyze_pcap(str(path))
        assert result["summary"]["suspect_functions"] >= 1
