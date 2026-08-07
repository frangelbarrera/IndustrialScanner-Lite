"""
Strict S7Comm packet parser.

Decodes the S7 protocol stack per the Siemens S7Comm specification and
Wireshark's packet-s7comm dissector (epan/dissectors/packet-s7comm.c).

Layered structure on top of TCP/102:
    [TPKT header (4 bytes)] [COTP header (3-17 bytes)] [S7 header (10+ bytes)]
                                                                              |
                                                  [S7 parameter block]
                                                                              |
                                                                  [S7 data block]

The S7 header byte 1 is the ROSCTR (Request/Response type), NOT the function
code. Function codes live in the parameter block which starts at byte 10 of
the S7 header.
"""

from typing import Any

from scapy.all import Raw

# ---------------------------------------------------------------------------
# S7 header constants
# ---------------------------------------------------------------------------
S7_PROTOCOL_ID = 0x32

# ROSCTR (byte 1 of S7 header) — message type, NOT function code
ROSCTR_JOB = 0x01  # Request (Job)
ROSCTR_ACK = 0x02  # Acknowledgement
ROSCTR_ACK_DATA = 0x03  # Response with data
ROSCTR_USERDATA = 0x07  # Userdata (programming commands)

ROSCTR_NAMES = {
    ROSCTR_JOB: "Job",
    ROSCTR_ACK: "Ack",
    ROSCTR_ACK_DATA: "AckData",
    ROSCTR_USERDATA: "Userdata",
}

# Parameter block function codes (per Siemens spec, byte 0 of the parameter
# block which begins at S7 header offset 10).
# Reference: Wireshark packet-s7comm.c, "param_func" enumeration.
FUNC_READ_VAR = 0x04
FUNC_WRITE_VAR = 0x05
FUNC_START = 0x28  # 0x28 = Start CPU
FUNC_STOP = 0x29  # 0x29 = Stop CPU
FUNC_START_DELETE = 0x2A  # (rarely seen)
FUNC_SETUP_COMM = 0xF0  # Setup communication (handshake)

# Block / firmware / RAM operations (parameter function group 0x3 series)
FUNC_DOWNLOAD_BLOCK = 0x3A
FUNC_UPLOAD_BLOCK = 0x3B
FUNC_DELETE_BLOCK = 0x3C
FUNC_COPY_RAM_TO_ROM = 0x4E
FUNC_COPY_ROM_TO_RAM = 0x4F
FUNC_FIRMWARE_UPDATE = 0x44
FUNC_PASSWORD = 0x45
FUNC_READ_DIAG = 0x46

FUNC_NAMES = {
    FUNC_READ_VAR: "ReadVar",
    FUNC_WRITE_VAR: "WriteVar",
    FUNC_START: "Start",
    FUNC_STOP: "Stop",
    FUNC_START_DELETE: "StartDelete",
    FUNC_SETUP_COMM: "SetupComm",
    FUNC_DOWNLOAD_BLOCK: "DownloadBlock",
    FUNC_UPLOAD_BLOCK: "UploadBlock",
    FUNC_DELETE_BLOCK: "DeleteBlock",
    FUNC_COPY_RAM_TO_ROM: "CopyRamToRom",
    FUNC_COPY_ROM_TO_RAM: "CopyRomToRam",
    FUNC_FIRMWARE_UPDATE: "FirmwareUpdate",
    FUNC_PASSWORD: "Password",
    FUNC_READ_DIAG: "ReadDiag",
}

# Function codes that represent control operations and should be flagged as
# suspect when present in traffic (potential unauthorized control attempts).
SUSPECT_FUNCS = {
    "WriteVar",
    "Start",
    "Stop",
    "DownloadBlock",
    "DeleteBlock",
    "CopyRamToRom",
    "FirmwareUpdate",
    "Password",
}

# Indicative ASCII strings sometimes present in payloads (kept for additional
# context tags, not as the primary classification mechanism).
BLOCK_HINTS = [b"OB1", b"OB", b"DB", b"FB", b"FC", b"System", b"PLC", b"Firmware", b"Update"]


# TPKT/COTP framing constants
# S7Comm runs over TPKT (RFC 1006) on TCP/102, which wraps the S7 PDU in:
#   [TPKT header 4 bytes][COTP header 3-17 bytes][S7 PDU]
# TPKT header: version(1) = 0x03, reserved(1) = 0x00, length(2, big-endian)
# COTP header: length(1), PDU type(1), ref(1)  (for DT class 0: 0x02 0xF0 0x80)
TPKT_VERSION = 0x03
TPKT_HEADER_LEN = 4
COTP_DT_PDU_TYPE = 0xF0  # Data (DT) PDU type
COTP_HEADER_LEN_MIN = 3  # length(1) + PDU type(1) + ref(1)


def _unwrap_tpkt_cotp(payload: bytes) -> bytes:
    """Strip TPKT/COTP framing to expose the inner S7 PDU.

    S7Comm frames are carried over TPKT (RFC 1006) which adds a 4-byte
    header, then COTP (ISO 8073) which adds a 3-17 byte header. The S7
    PDU begins after both.

    If the payload does not look like TPKT/COTP, return it unchanged —
    the caller will treat it as a raw S7 PDU (backwards-compatible with
    captures that omit TPKT/COTP framing).
    """
    if len(payload) < TPKT_HEADER_LEN + 1:
        return payload
    # Check TPKT magic: version 0x03, reserved 0x00
    if payload[0] != TPKT_VERSION or payload[1] != 0x00:
        # Not TPKT-framed; assume raw S7 PDU
        return payload
    tpkt_len = int.from_bytes(payload[2:4], "big")
    if tpkt_len < TPKT_HEADER_LEN + COTP_HEADER_LEN_MIN or tpkt_len > len(payload):
        # Malformed TPKT length
        return payload
    # COTP header: first byte is the length of the COTP header (excluding
    # the length byte itself). For DT (Data Transfer) PDU type 0xF0, the
    # standard header is 0x02 0xF0 0x80 (length=2, type=DT, ref=0x80).
    cotp_len_byte = payload[TPKT_HEADER_LEN]
    cotp_header_len = cotp_len_byte + 1  # +1 for the length byte itself
    if TPKT_HEADER_LEN + cotp_header_len > len(payload):
        return payload
    return payload[TPKT_HEADER_LEN + cotp_header_len :]


def _parse_s7_header(payload: bytes) -> "dict[str, int] | None":
    """Parse the S7 header (10 bytes minimum) from a payload.

    If the payload is wrapped in TPKT/COTP framing, the framing is stripped
    first. Returns None if the payload is too short or not an S7 frame.
    """
    # Strip TPKT/COTP framing if present
    payload = _unwrap_tpkt_cotp(payload)
    if len(payload) < 10:
        return None
    if payload[0] != S7_PROTOCOL_ID:
        return None
    return {
        "protocol_id": payload[0],
        "rosctr": payload[1],
        # bytes 2-3 are reserved (always 0x0000)
        "reserved": int.from_bytes(payload[2:4], "big"),
        "pdu_ref": int.from_bytes(payload[4:6], "big"),
        "param_len": int.from_bytes(payload[6:8], "big"),
        "data_len": int.from_bytes(payload[8:10], "big"),
    }


def _parse_parameter_block(payload: bytes, header: "dict[str, int]") -> "dict[str, Any] | None":
    """Parse the S7 parameter block that follows the 10-byte S7 header.

    The parameter block begins at byte 10. Byte 0 of the parameter block is
    the function group; byte 1 is the sub-function (or item count).
    """
    param_offset = 10
    param_len = header["param_len"]
    if param_len == 0 or len(payload) < param_offset + 2:
        return None
    return {
        "function_group": payload[param_offset],
        "sub_function": payload[param_offset + 1] if param_len > 1 else 0,
        "param_len": param_len,
        "raw": payload[param_offset : param_offset + param_len],
    }


def _classify_function(header: "dict[str, int]", param: "dict[str, Any] | None") -> str:
    """Classify the S7 operation by combining header and parameter info."""
    # If we have a parameter block with a known function code, use it.
    if param is not None:
        fg = param["function_group"]
        if fg in FUNC_NAMES:
            return FUNC_NAMES[fg]
        # For Userdata (0x07) frames, the function group may be a different
        # set of codes (programmer commands). Mark as Unknown for now.
        if header["rosctr"] == ROSCTR_USERDATA:
            return "Userdata"
    # Setup communication is sometimes sent without a parameter block (handshake).
    if header["rosctr"] == ROSCTR_JOB and header["param_len"] == 0:
        return "SetupComm"
    return "Unknown"


def _guess_function(payload: bytes) -> str:
    """Classify an S7Comm payload into a human-readable function name.

    Strict implementation: parses the S7 header and the parameter block
    to identify the function code. Falls back to 'Unknown' for ambiguous
    frames rather than guessing from ASCII substrings.

    The payload may be wrapped in TPKT/COTP framing (RFC 1006 / ISO 8073),
    which is stripped before parsing.
    """
    # Strip TPKT/COTP framing if present (one-time unwrap, reused below)
    unwrapped = _unwrap_tpkt_cotp(payload)
    header = _parse_s7_header(unwrapped)
    if header is None:
        return "NonS7Payload"
    # _parse_parameter_block expects the unwrapped payload (S7 PDU starting
    # at byte 0 = protocol_id 0x32)
    param = _parse_parameter_block(unwrapped, header)
    return _classify_function(header, param)


def parse_s7_packet(pkt) -> "dict | None":
    """Extract useful metadata from an S7Comm packet.

    Returns a dict with src, dst, function_code, length, hints, rosctr,
    pdu_ref. Returns None if the packet is not a valid S7Comm frame.
    """
    if Raw not in pkt:
        return None

    payload = bytes(pkt[Raw])

    header = _parse_s7_header(payload)
    if header is None:
        return None

    param = _parse_parameter_block(payload, header)
    func_name = _classify_function(header, param)

    src = getattr(pkt[0][1], "src", None)
    dst = getattr(pkt[0][1], "dst", None)

    hints: list[str] = []
    for h in BLOCK_HINTS:
        if h in payload:
            hints.append(h.decode("latin-1", errors="ignore"))

    return {
        "src": src or "unknown",
        "dst": dst or "unknown",
        "function_code": func_name,
        "length": len(payload),
        "hints": hints,
        "rosctr": ROSCTR_NAMES.get(header["rosctr"], f"0x{header['rosctr']:02x}"),
        "pdu_ref": header["pdu_ref"],
    }
