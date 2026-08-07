"""Tests for the strict DNP3 parser (binary decoding per IEEE 1815-2012)."""

from __future__ import annotations

from scapy.all import IP, TCP, Ether, Raw

from dnp3_monitor.parsers import (
    APP_FUNC_COLD_RESTART,
    APP_FUNC_OPERATE,
    APP_FUNC_READ,
    APP_FUNC_WRITE,
    DNP3_SYNC_0,
    DNP3_SYNC_1,
    LINK_FUNC_USER_DATA,
    _classify_app_function,
    _find_dnp3_payload,
    _parse_link_layer,
    parse_dnp3_packet,
)


def _dnp3pkt(payload: bytes):
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=20000) / Raw(load=payload)


def _build_dnp3_frame(
    link_func: int = LINK_FUNC_USER_DATA, app_func: int = APP_FUNC_READ, with_app: bool = True
) -> bytes:
    """Build a minimal DNP3 frame for testing.

    Link layer (10 bytes):
        byte 0: SYNC 0 (0x05)
        byte 1: SYNC 1 (0x64)
        byte 2: length (number of bytes after this byte, including CRCs)
        byte 3: control (DIR=1, PRM=1, FCB=0, FCV=1, function)
        bytes 4-5: destination (16-bit LE)
        bytes 6-7: source (16-bit LE)
        bytes 8-9: link CRC (placeholder zeros)
    Transport (1 byte, only if User Data link func):
        byte 10: transport control (FIR+FIN+SEQ)
    Application (2+ bytes, only if User Data link func):
        byte 11: app control
        byte 12: function code
    """
    if with_app and link_func == LINK_FUNC_USER_DATA:
        # User data: transport(1) + app_ctrl(1) + app_func(1) = 3 bytes
        # Plus 2 bytes for link CRC = 5 bytes after the link header (bytes 2-9)
        # but the length field counts from byte 3 onwards, including the CRC at the end.
        length = 5 + 3  # dest(2) + src(2) + crc(2) + user_data(3) = 9, but length=8 means
        # 5 (header from byte 3) + 3 (user data) = 8. We use length=8 with 3 bytes of user data
        # to match real captures that count dest+src+crc as 6 bytes plus user data.
        # Actually: length field = (bytes after byte 2) - 2 = user_data_bytes + 5
        length = 8
    else:
        length = 5  # dest + src + crc, no user data
    ctrl = 0xC0 | (link_func & 0x0F)  # DIR=1, PRM=1, FCB=0, FCV=1
    frame = (
        bytes([DNP3_SYNC_0, DNP3_SYNC_1, length, ctrl])
        + (1024).to_bytes(2, "little")  # dest
        + (1).to_bytes(2, "little")  # src
        + b"\x00\x00"  # link CRC placeholder
    )
    if link_func == LINK_FUNC_USER_DATA and with_app:
        # transport byte + app control + app function
        frame += bytes([0x00, 0xC0, app_func])
    return frame


class TestFindDNP3Payload:
    def test_clean_frame(self):
        frame = _build_dnp3_frame()
        found = _find_dnp3_payload(frame)
        assert found is not None
        assert found[0] == DNP3_SYNC_0
        assert found[1] == DNP3_SYNC_1

    def test_padding_before_magic(self):
        frame = b"\x00\x00garbage" + _build_dnp3_frame()
        found = _find_dnp3_payload(frame)
        assert found is not None
        assert found[0] == DNP3_SYNC_0

    def test_no_dnp3(self):
        assert _find_dnp3_payload(b"random data here") is None

    def test_too_short(self):
        assert _find_dnp3_payload(b"\x05\x64short") is None


class TestParseLinkLayer:
    def test_valid_link(self):
        frame = _build_dnp3_frame(link_func=LINK_FUNC_USER_DATA)
        link = _parse_link_layer(frame)
        assert link is not None
        assert link["sync0"] == DNP3_SYNC_0
        assert link["sync1"] == DNP3_SYNC_1
        assert link["link_func"] == LINK_FUNC_USER_DATA
        assert link["dest"] == 1024
        assert link["src"] == 1

    def test_wrong_magic(self):
        assert _parse_link_layer(b"\x00\x01" + b"\x00" * 8) is None

    def test_too_short(self):
        assert _parse_link_layer(b"\x05\x64") is None


class TestClassifyAppFunction:
    def test_non_dnp3(self):
        assert _classify_app_function(b"random data") == "NonDNP3"

    def test_empty_payload(self):
        assert _classify_app_function(b"") == "NonDNP3"

    def test_read(self):
        frame = _build_dnp3_frame(app_func=APP_FUNC_READ)
        assert _classify_app_function(frame) == "Read"

    def test_write(self):
        frame = _build_dnp3_frame(app_func=APP_FUNC_WRITE)
        assert _classify_app_function(frame) == "Write"

    def test_operate(self):
        frame = _build_dnp3_frame(app_func=APP_FUNC_OPERATE)
        assert _classify_app_function(frame) == "Operate"

    def test_cold_restart(self):
        frame = _build_dnp3_frame(app_func=APP_FUNC_COLD_RESTART)
        assert _classify_app_function(frame) == "ColdRestart"

    def test_unknown_function(self):
        # Use a function code that we don't have in the table.
        frame = _build_dnp3_frame(app_func=0xFF)
        # 0xFF is not in APP_FUNC_NAMES so it should return "UnknownDNP3".
        assert _classify_app_function(frame) == "UnknownDNP3"


class TestParseDnp3Packet:
    def test_no_raw_returns_none(self):
        from scapy.all import IP, TCP, Ether

        pkt = Ether() / IP() / TCP()
        assert parse_dnp3_packet(pkt) is None

    def test_classifies_read(self):
        frame = _build_dnp3_frame(app_func=APP_FUNC_READ)
        pkt = _dnp3pkt(frame)
        out = parse_dnp3_packet(pkt)
        assert out is not None
        assert out["function"] == "Read"
        assert out["suspect"] is False

    def test_classifies_operate_as_suspect(self):
        frame = _build_dnp3_frame(app_func=APP_FUNC_OPERATE)
        pkt = _dnp3pkt(frame)
        out = parse_dnp3_packet(pkt)
        assert out is not None
        assert out["suspect"] is True

    def test_classifies_cold_restart_as_suspect(self):
        frame = _build_dnp3_frame(app_func=APP_FUNC_COLD_RESTART)
        pkt = _dnp3pkt(frame)
        out = parse_dnp3_packet(pkt)
        assert out is not None
        assert out["function"] == "ColdRestart"
        assert out["suspect"] is True

    def test_non_dnp3_returns_unknown(self):
        pkt = _dnp3pkt(b"random data not dnp3")
        out = parse_dnp3_packet(pkt)
        assert out is not None
        assert out["function"] == "NonDNP3"
        assert out["suspect"] is False
