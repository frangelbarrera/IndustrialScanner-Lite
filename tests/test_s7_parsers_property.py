"""Property-based tests for the strict S7Comm parser using Hypothesis.

These tests verify parser invariants across a wide range of synthetic
byte sequences, ensuring the parser never crashes and always returns
a known function name.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from s7_comm_analyzer.parsers import (
    FUNC_NAMES,
    S7_PROTOCOL_ID,
    _guess_function,
    _parse_parameter_block,
    _parse_s7_header,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------
@st.composite
def s7_payload(draw):
    """Generate a byte sequence that starts with the S7 magic byte 0x32."""
    length = draw(st.integers(min_value=10, max_value=1500))
    extra = draw(
        st.lists(
            st.integers(min_value=0, max_value=255),
            min_size=length - 1,
            max_size=length - 1,
        )
    )
    return bytes([S7_PROTOCOL_ID]) + bytes(extra)


@st.composite
def valid_s7_frame(draw):
    """Generate a well-formed S7 frame with a known function code."""
    rosctr = draw(st.integers(min_value=0, max_value=255))
    func = draw(st.sampled_from(list(FUNC_NAMES.keys())))
    param_len = 2
    data_len = draw(st.integers(min_value=0, max_value=200))
    pdu_ref = draw(st.integers(min_value=0, max_value=65535))
    data = bytes(
        draw(
            st.lists(
                st.integers(min_value=0, max_value=255),
                min_size=data_len,
                max_size=data_len,
            )
        )
    )
    frame = (
        bytes([S7_PROTOCOL_ID, rosctr])
        + b"\x00\x00"
        + pdu_ref.to_bytes(2, "big")
        + param_len.to_bytes(2, "big")
        + data_len.to_bytes(2, "big")
        + bytes([func, 0x00])
        + data
    )
    return frame


@st.composite
def arbitrary_bytes(draw):
    """Generate any byte sequence including garbage."""
    length = draw(st.integers(min_value=0, max_value=2000))
    return bytes(
        draw(
            st.lists(
                st.integers(min_value=0, max_value=255),
                min_size=length,
                max_size=length,
            )
        )
    )


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------
class TestParserInvariants:
    """The parser must satisfy these invariants for ANY input."""

    @settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(payload=arbitrary_bytes())
    def test_parser_never_crashes_on_arbitrary_bytes(self, payload):
        """For ANY byte sequence, _guess_function MUST NOT raise."""
        result = _guess_function(payload)
        assert isinstance(result, str)

    @settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(payload=s7_payload())
    def test_parser_never_crashes_on_s7_magic(self, payload):
        """For any byte sequence starting with 0x32, parser MUST NOT raise."""
        result = _guess_function(payload)
        assert isinstance(result, str)

    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(payload=arbitrary_bytes())
    def test_parse_s7_header_returns_none_or_dict(self, payload):
        """_parse_s7_header returns None or a dict with required keys."""
        result = _parse_s7_header(payload)
        if result is not None:
            assert "protocol_id" in result
            assert "rosctr" in result
            assert "pdu_ref" in result
            assert "param_len" in result
            assert "data_len" in result
            assert result["protocol_id"] == S7_PROTOCOL_ID


class TestValidFrameClassification:
    """For well-formed S7 frames, the parser must classify correctly."""

    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(frame=valid_s7_frame())
    def test_valid_frame_classified_as_known_function(self, frame):
        """A valid S7 frame with a known function code MUST be classified
        into FUNC_NAMES (or 'Unknown' if rosctr is weird, but never crash)."""
        result = _guess_function(frame)
        assert isinstance(result, str)
        # The result must be one of the known function names OR 'Unknown'
        # if the rosctr is not Job/Ack/AckData/Userdata.
        KNOWN = set(FUNC_NAMES.values()) | {"Unknown", "Userdata", "SetupComm", "NonS7Payload"}
        assert result in KNOWN, f"Unexpected function name: {result}"

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(frame=valid_s7_frame())
    def test_header_parsed_correctly_for_valid_frame(self, frame):
        """For a valid frame, header parsing must succeed."""
        header = _parse_s7_header(frame)
        assert header is not None
        assert header["protocol_id"] == S7_PROTOCOL_ID
        assert header["param_len"] == 2


class TestEdgeCases:
    """Specific edge cases that must be handled gracefully."""

    def test_empty_payload(self):
        assert _guess_function(b"") == "NonS7Payload"

    def test_single_byte(self):
        assert _guess_function(b"\x32") == "NonS7Payload"

    def test_only_magic_byte(self):
        assert _guess_function(b"\x32\x00") == "NonS7Payload"

    def test_short_header(self):
        # 9 bytes is too short for an S7 header (needs 10)
        assert _guess_function(b"\x32" + b"\x00" * 8) == "NonS7Payload"

    def test_wrong_magic_byte(self):
        # Wrong magic, even with 10+ bytes
        assert _guess_function(b"\x33" + b"\x00" * 12) == "NonS7Payload"

    def test_zero_param_len_with_job(self):
        # A Job with param_len=0 should be classified as SetupComm
        payload = (
            bytes([S7_PROTOCOL_ID, 0x01])  # Job
            + b"\x00\x00"
            + b"\x00\x00"  # pdu_ref
            + b"\x00\x00"  # param_len = 0
            + b"\x00\x00"  # data_len = 0
        )
        assert _guess_function(payload) == "SetupComm"

    def test_unknown_function_code(self):
        # A function code not in FUNC_NAMES should return 'Unknown'
        payload = (
            bytes([S7_PROTOCOL_ID, 0x01])  # Job
            + b"\x00\x00"
            + b"\x00\x00"  # pdu_ref
            + b"\x00\x02"  # param_len = 2
            + b"\x00\x00"  # data_len = 0
            + bytes([0xFF, 0x00])  # unknown function code
        )
        assert _guess_function(payload) == "Unknown"


class TestParameterBlockParsing:
    """Property-based tests for parameter block parsing."""

    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(
        param_len=st.integers(min_value=0, max_value=100),
        data_len=st.integers(min_value=0, max_value=200),
    )
    def test_parameter_block_respects_param_len(self, param_len, data_len):
        """The parameter block parsing must respect the declared param_len
        AND the actual payload length.

        _parse_parameter_block returns None when:
          - param_len == 0 (no parameter block declared), OR
          - len(payload) < param_offset(10) + 2 = 12 bytes (cannot read 2 bytes
            at offset 10 to get function_group and sub_function)

        In our generated frame:
          len(payload) = 10 (header) + param_len + data_len
        So the parser returns None when:
          - param_len == 0, OR
          - 10 + param_len + data_len < 12, i.e., param_len + data_len < 2
        """
        # Build a frame with a parameter block of param_len bytes
        param_data = bytes([0x04, 0x00]) + b"\x00" * max(0, param_len - 2)
        param_data = param_data[:param_len]
        data = b"\x00" * data_len
        payload = (
            bytes([S7_PROTOCOL_ID, 0x01])  # Job
            + b"\x00\x00"
            + b"\x00\x00"  # pdu_ref
            + param_len.to_bytes(2, "big")
            + data_len.to_bytes(2, "big")
            + param_data
            + data
        )
        header = _parse_s7_header(payload)
        assert header is not None
        param = _parse_parameter_block(payload, header)

        payload_len = len(payload)
        # The parser needs at least 12 bytes (10 header + 2 param) AND param_len > 0
        if param_len == 0 or payload_len < 12:
            assert param is None, (
                f"Expected None for param_len={param_len}, payload_len={payload_len}, got {param}"
            )
        else:
            assert param is not None, (
                f"Expected dict for param_len={param_len}, payload_len={payload_len}, got None"
            )
            assert param["param_len"] == param_len


class TestFieldPreservation:
    """Field-preservation invariants: parsed fields must match the input."""

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(
        pdu_ref=st.integers(min_value=0, max_value=65535),
        rosctr=st.integers(min_value=0, max_value=255),
    )
    def test_pdu_ref_preserved(self, pdu_ref, rosctr):
        """The pdu_ref field set in the frame MUST be preserved in the parsed header."""
        payload = (
            bytes([S7_PROTOCOL_ID, rosctr])
            + b"\x00\x00"
            + pdu_ref.to_bytes(2, "big")
            + b"\x00\x02"  # param_len
            + b"\x00\x00"  # data_len
            + bytes([0x04, 0x00])  # ReadVar
        )
        header = _parse_s7_header(payload)
        assert header is not None
        assert header["pdu_ref"] == pdu_ref
        assert header["rosctr"] == rosctr

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(
        param_len=st.integers(min_value=2, max_value=50),
        data_len=st.integers(min_value=0, max_value=100),
    )
    def test_param_and_data_len_preserved(self, param_len, data_len):
        """param_len and data_len declared in the header must be preserved."""
        param_data = b"\x04\x00" + b"\x00" * (param_len - 2)
        data = b"\x00" * data_len
        payload = (
            bytes([S7_PROTOCOL_ID, 0x01])
            + b"\x00\x00"
            + b"\x00\x00"
            + param_len.to_bytes(2, "big")
            + data_len.to_bytes(2, "big")
            + param_data
            + data
        )
        header = _parse_s7_header(payload)
        assert header is not None
        assert header["param_len"] == param_len
        assert header["data_len"] == data_len


class TestRoundTripConsistency:
    """Round-trip invariants: parsing the same frame twice yields the same result."""

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(frame=valid_s7_frame())
    def test_parse_twice_yields_same_result(self, frame):
        """Parsing the same frame twice MUST yield the same classification."""
        result1 = _guess_function(frame)
        result2 = _guess_function(frame)
        assert result1 == result2

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(frame=valid_s7_frame())
    def test_header_parse_twice_yields_same_result(self, frame):
        """Header parsing MUST be deterministic."""
        header1 = _parse_s7_header(frame)
        header2 = _parse_s7_header(frame)
        assert header1 == header2
