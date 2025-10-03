# -*- coding: utf-8 -*-
"""
Parsers for S7Comm packets (extended with heuristics).
- Maintains basic detection (ReadVar, WriteVar, Start, Stop).
- Adds heuristics for block downloads (OB1/DB), Copy RAM->ROM, and large-scale updates.
"""
from typing import Dict, Optional, Tuple, List
from scapy.all import Raw

# Heuristics: function names and high-level tags
FUNC_MAP = {
    0x04: "ReadVar",       # S7 parameter for variable reads (common convention)
    0x05: "WriteVar",      # S7 parameter for variable writes
    0x02: "Start",         # start CPU (heuristic)
    0x03: "Stop",          # stop CPU (heuristic)
    0xF0: "SetupComm",     # handshake/session layer (heuristic)
}

SUSPECT_FUNCS = {"WriteVar", "Start", "Stop", "DownloadBlock", "CopyRamToRom", "FirmwareUpdate"}

# Indicative words within payload (some captures include ASCII names)
BLOCK_HINTS = [b"OB1", b"OB", b"DB", b"FB", b"FC", b"System", b"PLC", b"Firmware", b"Update"]

def _guess_function(payload: bytes) -> str:
    """
    Attempts to infer S7 function:
    - S7Comm PDU typically starts with 0x32 (S7 header).
    - The function parameter is not always at byte 1, so we use heuristics:
      1) If ASCII block patterns appear -> "DownloadBlock" (if size is high or many writes occur).
      2) If byte 1 matches typical codes -> map via FUNC_MAP.
      3) If intensive write patterns (large payload) -> "WriteVar" or "DownloadBlock".
    """
    if not payload or payload[0] != 0x32:
        return "NonS7Payload"

    # Size heuristic: downloads/firmware are usually large packets
    big = len(payload) >= 200
    huge = len(payload) >= 800

    # Direct attempt using the second byte as an "indicator" (non-standard, but useful in several captures)
    func_byte = payload[1]
    base = FUNC_MAP.get(func_byte)

    # If we find block references and the packet is large, mark as download
    if big and any(h in payload for h in BLOCK_HINTS):
        # OB/DB in payload with large packet -> likely block download
        return "DownloadBlock"

    # Firmware heuristic: very large and includes firmware/update markers
    if huge and (b"Firmware" in payload or b"Update" in payload):
        return "FirmwareUpdate"

    # Copy RAM to ROM: some captures show this semantics; without a fixed signature, use hints
    if big and b"Copy" in payload and b"Rom" in payload:
        return "CopyRamToRom"

    # If we have a mapped base function, return it
    if base:
        return base

    # Heuristic via item/var patterns (often includes 0x05 for WriteVar and 0x04 for ReadVar within parameters)
    if 0x05 in payload:
        return "WriteVar"
    if 0x04 in payload:
        return "ReadVar"

    return "Unknown"


def parse_s7_packet(pkt) -> Optional[Dict]:
    """
    Extracts useful metadata from an S7Comm packet.
    """
    if Raw not in pkt:
        return None

    payload = bytes(pkt[Raw])
    # S7Comm PDU header signature
    if len(payload) < 10 or payload[0] != 0x32:
        return None

    func_name = _guess_function(payload)
    src = getattr(pkt[0][1], "src", None)
    dst = getattr(pkt[0][1], "dst", None)

    # Additional context tags
    hints: List[str] = []
    for h in BLOCK_HINTS:
        if h in payload:
            hints.append(h.decode("latin-1", errors="ignore"))

    return {
        "src": src or "unknown",
        "dst": dst or "unknown",
        "function_code": func_name,
        "length": len(payload),
        "hints": hints,
    }
