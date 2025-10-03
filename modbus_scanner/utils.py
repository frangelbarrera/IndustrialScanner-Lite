# -*- coding: utf-8 -*-
"""
Utilities for IndustrialScanner-Lite Modbus scanner.
"""

import ipaddress
import logging
from datetime import datetime
from pathlib import Path
from typing import List


def setup_logger(name: str) -> logging.Logger:
    """
    Configure a lightweight console logger.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")
        ch.setFormatter(fmt)
        logger.addHandler(ch)
    return logger


def utc_ts() -> str:
    """
    Return ISO-like timestamp in UTC.
    """
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_str(e: Exception) -> str:
    """
    Safely stringify exceptions for logging.
    """
    try:
        return str(e)
    except Exception:
        return e.__class__.__name__


def expand_targets(arg: str) -> List[str]:
    """
    Expand targets from multiple input formats:
    - "192.168.0.10,192.168.0.11"
    - "192.168.0.0/24" (CIDR)
    - "@targets.txt" (file with one IP per line)
    """
    arg = arg.strip()
    out: List[str] = []

    if arg.startswith("@"):
        # File mode
        path = Path(arg[1:])
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(line)
        return out

    if "," in arg:
        # Comma-separated IPs
        for token in arg.split(","):
            token = token.strip()
            if token:
                out.append(token)
        return out

    # CIDR or single IP
    try:
        net = ipaddress.ip_network(arg, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        # Single IP fallback
        return [arg]


def html_template_path(name: str) -> Path:
    """
    Resolve bundled HTML template path.
    """
    base = Path(__file__).resolve().parents[1] / "reports" / "templates"
    return base / name
