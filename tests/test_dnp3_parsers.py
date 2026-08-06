# -*- coding: utf-8 -*-
"""Tests for the DNP3 parser heuristics."""
from __future__ import annotations

from scapy.all import IP, TCP, Raw, Ether

from dnp3_monitor.parsers import parse_dnp3_packet, _classify_app_function


def _dnp3pkt(payload: bytes):
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=20000) / Raw(load=payload)


class TestClassifyAppFunction:
    def test_short_payload(self):
        assert _classify_app_function(b"") == "UnknownDNP3"

    def test_read(self):
        assert _classify_app_function(b"READ\x00\x00\x00\x00") == "Read"

    def test_operate(self):
        assert _classify_app_function(b"OPER\x00\x00\x00\x00") == "Operate"

    def test_cold_restart(self):
        assert _classify_app_function(b"COLD RESTART\x00") == "ColdRestart"

    def test_unknown(self):
        assert _classify_app_function(b"random\x00\x00") == "UnknownDNP3"


class TestParseDnp3Packet:
    def test_no_raw_returns_none(self):
        from scapy.all import IP, TCP, Ether
        pkt = Ether() / IP() / TCP()
        assert parse_dnp3_packet(pkt) is None

    def test_classifies_read(self):
        pkt = _dnp3pkt(b"READ\x00\x00\x00\x00")
        out = parse_dnp3_packet(pkt)
        assert out is not None
        assert out["function"] == "Read"
        assert out["suspect"] is False

    def test_classifies_operate_as_suspect(self):
        pkt = _dnp3pkt(b"OPER\x00\x00\x00\x00")
        out = parse_dnp3_packet(pkt)
        assert out is not None
        assert out["suspect"] is True
