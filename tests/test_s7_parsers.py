"""Tests for the strict S7Comm parser (binary decoding, not heuristics)."""

from __future__ import annotations

from scapy.all import IP, TCP, Ether, Raw

from s7_comm_analyzer.parsers import (
    FUNC_FIRMWARE_UPDATE,
    FUNC_READ_VAR,
    FUNC_SETUP_COMM,
    FUNC_START,
    FUNC_STOP,
    FUNC_WRITE_VAR,
    ROSCTR_JOB,
    S7_PROTOCOL_ID,
    _classify_function,
    _guess_function,
    _parse_parameter_block,
    _parse_s7_header,
    parse_s7_packet,
)


def _s7pkt(payload: bytes):
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=102) / Raw(load=payload)


def _build_s7_frame(
    rosctr: int, func: int = 0, param_len: int = 0, data: bytes = b"", pdu_ref: int = 0
) -> bytes:
    """Build a minimal S7Comm frame for testing.

    S7 header (10 bytes):
        byte 0: protocol id (0x32)
        byte 1: rosctr
        bytes 2-3: reserved (0x0000)
        bytes 4-5: PDU reference
        bytes 6-7: parameter length
        bytes 8-9: data length
    Parameter block (if param_len > 0):
        byte 0: function group
        byte 1: sub-function / item count
    """
    data_len = len(data)
    param_block = bytes([func, 0x00])[:param_len] if param_len > 0 else b""
    return (
        bytes([S7_PROTOCOL_ID, rosctr])
        + b"\x00\x00"
        + pdu_ref.to_bytes(2, "big")
        + param_len.to_bytes(2, "big")
        + data_len.to_bytes(2, "big")
        + param_block
        + data
    )


class TestParseS7Header:
    def test_valid_s7_header(self):
        payload = _build_s7_frame(ROSCTR_JOB, param_len=2, func=FUNC_READ_VAR)
        header = _parse_s7_header(payload)
        assert header is not None
        assert header["protocol_id"] == S7_PROTOCOL_ID
        assert header["rosctr"] == ROSCTR_JOB
        assert header["param_len"] == 2

    def test_too_short(self):
        assert _parse_s7_header(b"\x32\x01\x00") is None

    def test_wrong_magic(self):
        assert _parse_s7_header(b"\x00\x01" + b"\x00" * 8) is None


class TestClassifyFunction:
    def test_read_var(self):
        payload = _build_s7_frame(ROSCTR_JOB, param_len=2, func=FUNC_READ_VAR)
        header = _parse_s7_header(payload)
        param = _parse_parameter_block(payload, header)
        assert _classify_function(header, param) == "ReadVar"

    def test_write_var(self):
        payload = _build_s7_frame(ROSCTR_JOB, param_len=2, func=FUNC_WRITE_VAR)
        header = _parse_s7_header(payload)
        param = _parse_parameter_block(payload, header)
        assert _classify_function(header, param) == "WriteVar"

    def test_start(self):
        payload = _build_s7_frame(ROSCTR_JOB, param_len=2, func=FUNC_START)
        header = _parse_s7_header(payload)
        param = _parse_parameter_block(payload, header)
        assert _classify_function(header, param) == "Start"

    def test_stop(self):
        payload = _build_s7_frame(ROSCTR_JOB, param_len=2, func=FUNC_STOP)
        header = _parse_s7_header(payload)
        param = _parse_parameter_block(payload, header)
        assert _classify_function(header, param) == "Stop"

    def test_setup_comm(self):
        payload = _build_s7_frame(ROSCTR_JOB, param_len=2, func=FUNC_SETUP_COMM)
        header = _parse_s7_header(payload)
        param = _parse_parameter_block(payload, header)
        assert _classify_function(header, param) == "SetupComm"

    def test_firmware_update(self):
        payload = _build_s7_frame(ROSCTR_JOB, param_len=2, func=FUNC_FIRMWARE_UPDATE)
        header = _parse_s7_header(payload)
        param = _parse_parameter_block(payload, header)
        assert _classify_function(header, param) == "FirmwareUpdate"


class TestGuessFunction:
    def test_empty_payload(self):
        assert _guess_function(b"") == "NonS7Payload"

    def test_non_s7_payload(self):
        assert _guess_function(b"\x00\x04") == "NonS7Payload"

    def test_wrong_magic(self):
        # 10+ bytes but wrong first byte
        assert _guess_function(b"\x33\x01" + b"\x00" * 12) == "NonS7Payload"

    def test_valid_read_var(self):
        payload = _build_s7_frame(ROSCTR_JOB, param_len=2, func=FUNC_READ_VAR)
        assert _guess_function(payload) == "ReadVar"

    def test_valid_stop(self):
        payload = _build_s7_frame(ROSCTR_JOB, param_len=2, func=FUNC_STOP)
        assert _guess_function(payload) == "Stop"


class TestParseS7Packet:
    def test_returns_none_for_non_s7(self):
        pkt = _s7pkt(b"not s7 traffic")
        assert parse_s7_packet(pkt) is None

    def test_returns_dict_for_s7(self):
        payload = _build_s7_frame(ROSCTR_JOB, param_len=2, func=FUNC_READ_VAR)
        pkt = _s7pkt(payload)
        out = parse_s7_packet(pkt)
        assert out is not None
        assert out["function_code"] == "ReadVar"
        assert out["src"] == "10.0.0.1"
        assert out["dst"] == "10.0.0.2"
        assert out["rosctr"] == "Job"

    def test_returns_none_for_short_payload(self):
        # S7 magic byte but too short to be a real frame
        pkt = _s7pkt(b"\x32\x01")
        assert parse_s7_packet(pkt) is None
