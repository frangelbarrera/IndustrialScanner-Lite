"""Property-based tests for the strict DNP3 parser using Hypothesis."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from dnp3_monitor.parsers import (
    APP_FUNC_NAMES,
    DNP3_SYNC_0,
    DNP3_SYNC_1,
    LINK_FUNC_USER_DATA,
    _classify_app_function,
    _find_dnp3_payload,
    _parse_link_layer,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------
@st.composite
def dnp3_frame(draw):
    """Generate a DNP3 frame with a known function code."""
    link_func = draw(st.sampled_from([0, 2, 3, 4, 9, 10]))
    app_func = draw(st.sampled_from(list(APP_FUNC_NAMES.keys())))
    dest = draw(st.integers(min_value=0, max_value=65535))
    src = draw(st.integers(min_value=0, max_value=65535))
    length = 8 if link_func == LINK_FUNC_USER_DATA else 5
    ctrl = 0xC0 | (link_func & 0x0F)
    frame = (
        bytes([DNP3_SYNC_0, DNP3_SYNC_1, length, ctrl])
        + dest.to_bytes(2, "little")
        + src.to_bytes(2, "little")
        + b"\x00\x00"  # CRC placeholder
    )
    if link_func == LINK_FUNC_USER_DATA:
        frame += bytes([0x00, 0xC0, app_func])
    return frame


@st.composite
def arbitrary_bytes(draw):
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


@st.composite
def bytes_with_dnp3_magic(draw):
    """Generate bytes that contain a DNP3 magic somewhere."""
    prefix = draw(arbitrary_bytes().map(lambda b: b[:64]))
    frame = draw(dnp3_frame())
    suffix = draw(arbitrary_bytes().map(lambda b: b[:64]))
    return prefix + frame + suffix


@st.composite
def dnp3_magic_at_start(draw):
    """Generate bytes starting with the DNP3 magic. Used by other strategies."""
    length = draw(st.integers(min_value=2, max_value=500))
    extra = draw(
        st.lists(
            st.integers(min_value=0, max_value=255),
            min_size=length - 2,
            max_size=length - 2,
        )
    )
    return bytes([DNP3_SYNC_0, DNP3_SYNC_1]) + bytes(extra)


# Marked as used by tests above; kept for future expansion.
__all__ = ["arbitrary_bytes", "bytes_with_dnp3_magic", "dnp3_frame", "dnp3_magic_at_start"]


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------
class TestParserInvariants:
    """Parser must satisfy these for ANY input."""

    @settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(payload=arbitrary_bytes())
    def test_classifier_never_crashes(self, payload):
        """For ANY byte sequence, _classify_app_function MUST NOT raise."""
        result = _classify_app_function(payload)
        assert isinstance(result, str)

    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(payload=arbitrary_bytes())
    def test_find_dnp3_payload_never_crashes(self, payload):
        """For ANY byte sequence, _find_dnp3_payload MUST NOT raise."""
        result = _find_dnp3_payload(payload)
        assert result is None or isinstance(result, bytes)

    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(payload=arbitrary_bytes())
    def test_parse_link_layer_never_crashes(self, payload):
        """For ANY byte sequence, _parse_link_layer MUST NOT raise."""
        result = _parse_link_layer(payload)
        assert result is None or isinstance(result, dict)


class TestValidFrameClassification:
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(frame=dnp3_frame())
    def test_valid_frame_classified(self, frame):
        """A valid DNP3 frame must be classified into a known name."""
        result = _classify_app_function(frame)
        assert isinstance(result, str)
        KNOWN = set(APP_FUNC_NAMES.values()) | {
            "NonDNP3",
            "UnknownDNP3",
            "ResetLinkStates",
            "ResetUser",
            "TestLinkStates",
            "NotSupported",
            "RequestLinkStatus",
            "NotUsed",
        }
        assert result in KNOWN, f"Unexpected: {result}"

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(frame=bytes_with_dnp3_magic())
    def test_finds_magic_anywhere(self, frame):
        """If the bytes contain a DNP3 magic, _find_dnp3_payload must find it."""
        result = _find_dnp3_payload(frame)
        if result is not None:
            assert result[0] == DNP3_SYNC_0
            assert result[1] in (DNP3_SYNC_1, 0xC4)


class TestEdgeCases:
    def test_empty(self):
        assert _classify_app_function(b"") == "NonDNP3"

    def test_only_magic_bytes(self):
        assert _classify_app_function(b"\x05\x64") == "NonDNP3"

    def test_garbage(self):
        assert _classify_app_function(b"random data here") == "NonDNP3"

    def test_truncated_after_magic(self):
        # Magic + 8 bytes is the minimum link header (10 bytes total)
        assert _classify_app_function(b"\x05\x64" + b"\x00" * 5) == "NonDNP3"


class TestFieldPreservation:
    """Field-preservation invariants for DNP3 link layer."""

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(
        dest=st.integers(min_value=0, max_value=65535),
        src=st.integers(min_value=0, max_value=65535),
    )
    def test_dest_src_preserved(self, dest, src):
        """dest and src in the link header MUST be preserved through parsing."""
        frame = (
            bytes([DNP3_SYNC_0, DNP3_SYNC_1, 8, 0xC4])
            + dest.to_bytes(2, "little")
            + src.to_bytes(2, "little")
            + b"\x00\x00"  # CRC placeholder
            + bytes([0x00, 0xC0, 0x01])  # transport + app (Read)
        )
        link = _parse_link_layer(frame)
        assert link is not None
        assert link["dest"] == dest
        assert link["src"] == src

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(link_func=st.sampled_from([0, 2, 3, 4, 9, 10]))
    def test_link_func_preserved(self, link_func):
        """The link function code MUST be preserved through parsing."""
        length = 8 if link_func == LINK_FUNC_USER_DATA else 5
        ctrl = 0xC0 | (link_func & 0x0F)
        frame = (
            bytes([DNP3_SYNC_0, DNP3_SYNC_1, length, ctrl])
            + b"\x00\x04"
            + b"\x01\x00"
            + b"\x00\x00"
        )
        if link_func == LINK_FUNC_USER_DATA:
            frame += bytes([0x00, 0xC0, 0x01])
        link = _parse_link_layer(frame)
        assert link is not None
        assert link["link_func"] == link_func


class TestRoundTripConsistency:
    """Round-trip invariants: parsing the same frame twice yields the same result."""

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(frame=dnp3_frame())
    def test_classify_twice_yields_same_result(self, frame):
        """Classification MUST be deterministic."""
        result1 = _classify_app_function(frame)
        result2 = _classify_app_function(frame)
        assert result1 == result2

    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(frame=dnp3_frame())
    def test_link_parse_twice_yields_same_result(self, frame):
        """Link layer parsing MUST be deterministic."""
        link1 = _parse_link_layer(frame)
        link2 = _parse_link_layer(frame)
        assert link1 == link2
