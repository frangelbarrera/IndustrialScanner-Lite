# -*- coding: utf-8 -*-
"""
Parsing heuristics for DNP3 (over TCP/UDP:20000).
"""

from typing import Optional, Dict, List
from scapy.all import Raw


SUSPECT_FUNCS = {
    "Operate",
    "Write",
    "EnableUnsolicited",
    "ColdRestart",
    "WarmRestart",
    "ClearRestart",
}


HINTS = [b"UNSOL", b"OPER", b"RESTART", b"SELECT", b"READ", b"WRITE", b"DNP"]

def _classify_app_function(payload: bytes) -> str:
    if not payload or len(payload) < 8:
        return "UnknownDNP3"

    if b"READ" in payload:
        return "Read"
    if b"WRITE" in payload:
        return "Write"
    if b"OPER" in payload:
        return "Operate"
    if b"SELECT" in payload:
        return "Select"
    if b"UNSOL" in payload:
        return "EnableUnsolicited"
    if b"COLD" in payload and b"RESTART" in payload:
        return "ColdRestart"
    if b"WARM" in payload and b"RESTART" in payload:
        return "WarmRestart"
    if b"CLEAR" in payload and b"RESTART" in payload:
        return "ClearRestart"

    return "UnknownDNP3"

def parse_dnp3_packet(pkt) -> Optional[Dict]:
    if Raw not in pkt:
        return None

    payload = bytes(pkt[Raw])
    src = getattr(pkt[0][1], "src", None)
    dst = getattr(pkt[0][1], "dst", None)

    func = _classify_app_function(payload)

    hints: List[str] = []
    for h in HINTS:
        if h in payload:
            try:
                hints.append(h.decode("latin-1"))
            except Exception:
                hints.append(str(h))

    return {
        "src": src or "unknown",
        "dst": dst or "unknown",
        "function": func,
        "length": len(payload),
        "hints": hints,
        "suspect": func in SUSPECT_FUNCS,
    }
