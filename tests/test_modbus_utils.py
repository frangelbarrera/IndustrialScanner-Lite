# -*- coding: utf-8 -*-
"""Tests for modbus_scanner utility functions."""
from __future__ import annotations

from pathlib import Path

from modbus_scanner.utils import expand_targets, safe_str, utc_ts


class TestExpandTargets:
    def test_single_ip(self):
        assert expand_targets("192.168.1.1") == ["192.168.1.1"]

    def test_comma_separated(self):
        result = expand_targets("192.168.1.1,192.168.1.2")
        assert result == ["192.168.1.1", "192.168.1.2"]

    def test_cidr(self):
        result = expand_targets("192.168.1.0/30")
        # /30 has 2 usable hosts
        assert len(result) == 2

    def test_file_input(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("10.0.0.1\n10.0.0.2\n\n# comment line will be returned as-is\n", encoding="utf-8")
        result = expand_targets(f"@{f}")
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result


class TestUtcTs:
    def test_format(self):
        ts = utc_ts()
        assert ts.endswith("Z")
        assert "T" in ts


class TestSafeStr:
    def test_normal_exception(self):
        assert safe_str(ValueError("hello")) == "hello"

    def test_str_raises(self):
        class Bad(Exception):
            def __str__(self):
                raise RuntimeError("oops")
        assert safe_str(Bad()) == "Bad"
