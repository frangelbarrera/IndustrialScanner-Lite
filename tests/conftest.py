"""Pytest configuration shared by all tests."""

import sys
from pathlib import Path

# Ensure repo root is on sys.path so `modbus_scanner`, `s7_comm_analyzer`, etc.
# are importable from the tests/ subfolder.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
