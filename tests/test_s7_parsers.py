# -*- coding: utf-8 -*-
"""Tests for the S7Comm parser heuristics."""
from __future__ import annotations

from scapy.all import IP, TCP, Raw, Ether

from s7_comm_analyzer.parsers import parse_s7_packet, _guess_function


def _s7pkt(payload: bytes):
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=102) / Raw(load=payload)


class TestGuessFunction:
    def test_empty_payload(self):
        assert _guess_function(b"") == "NonS7Payload"

    def test_non_s7_payload(self):
        assert _guess_function(b"\x00\x04") == "NonS7Payload"

    def test_readvar_marker_byte(self):
        # 0x32 is S7 header. byte[1]=0x04 → ReadVar via FUNC_MAP
        assert _guess_function(b"\x32\x04" + b"\x00" * 12) == "ReadVar"

    def test_writevar_marker_byte(self):
        assert _guess_function(b"\x32\x05" + b"\x00" * 12) == "WriteVar"

    def test_download_block_heuristic(self):
        # big payload with OB1 marker
        payload = b"\x32\x00" + b"\x00" * 200 + b"OB1"
        assert _guess_function(payload) == "DownloadBlock"


class TestParseS7Packet:
    def test_returns_none_for_non_s7(self):
        pkt = _s7pkt(b"not s7 traffic")
        assert parse_s7_packet(pkt) is None

    def test_returns_dict_for_s7(self):
        pkt = _s7pkt(b"\x32\x04" + b"\x00" * 12)
        out = parse_s7_packet(pkt)
        assert out is not None
        assert out["function_code"] == "ReadVar"
        assert out["src"] == "10.0.0.1"
        assert out["dst"] == "10.0.0.2"
