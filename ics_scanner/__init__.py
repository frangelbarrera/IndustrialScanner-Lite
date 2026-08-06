# -*- coding: utf-8 -*-
"""
ics_scanner: shared security primitives for IndustrialScanner-Lite.

This package centralizes:
  - HTML/JSON output sanitization (XSS prevention).
  - Target validation (private IPs only by default, CIDR limits).
  - Structured logging.
  - Path traversal guards for report paths.
"""
from __future__ import annotations

from .security import (
    html_escape,
    safe_render,
    is_safe_target,
    TargetPolicyError,
    safe_join_path,
    configure_logging,
)

__all__ = [
    "html_escape",
    "safe_render",
    "is_safe_target",
    "TargetPolicyError",
    "safe_join_path",
    "configure_logging",
]

__version__ = "0.2.0.dev0"
