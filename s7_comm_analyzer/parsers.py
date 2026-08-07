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
from __future__ import annotations

from scapy.all import Raw

# ---------------------------------------------------------------------------
# S7 header constants
# ---------------------------------------------------------------------------
S7_PROTOCOL_ID = 0x32

# ROSCTR (byte 1 of S7 header) — message type, NOT function code
ROSCTR_JOB = 0x01         # Request (Job)
ROSCTR_ACK = 0x02         # Acknowledgement
ROSCTR_ACK_DATA = 0x03    # Response with data
ROSCTR_USERDATA = 0x07    # Userdata (programming commands)

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
FUNC_START = 0x28           # 0x28 = Start CPU
FUNC_STOP = 0x29            # 0x29 = Stop CPU
FUNC_START_DELETE = 0x2A    # (rarely seen)
FUNC_SETUP_COMM = 0xF0      # Setup communication (handshake)

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
    "WriteVar", "Start", "Stop", "DownloadBlock", "DeleteBlock",
    "CopyRamToRom", "FirmwareUpdate", "Password",
}

# Indicative ASCII strings sometimes present in payloads (kept for additional
# context tags, not as the primary classification mechanism).
BLOCK_HINTS = [b"OB1", b"OB", b"DB", b"FB", b"FC", b"System", b"PLC",
               b"Firmware", b"Update"]


def _parse_s7_header(payload: bytes) -> dict[str, int] | None:
    """Parse the S7 header (10 bytes minimum) from a payload.

    Returns a dict with: protocol_id, rosctr, pdu_ref, param_len, data_len.
    Returns None if the payload is too short or not an S7 frame.
    """
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


def _parse_parameter_block(payload: bytes, header: dict[str, int]) -> dict[str, int] | None:
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
        "raw": payload[param_offset:param_offset + param_len],
    }


def _classify_function(header: dict[str, int],
                       param: dict[str, int] | None) -> str:
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
    """
    header = _parse_s7_header(payload)
    if header is None:
        return "NonS7Payload"
    param = _parse_parameter_block(payload, header)
    return _classify_function(header, param)


def parse_s7_packet(pkt) -> dict | None:
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
