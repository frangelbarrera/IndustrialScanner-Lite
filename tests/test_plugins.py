"""Tests for the protocol parser plugin registry."""
from __future__ import annotations

from ics_scanner.plugins import ParserEntry, discover_parsers, list_parsers, load_parser


class TestDiscoverParsers:
    def test_returns_builtins(self):
        parsers = discover_parsers()
        names = [p.name for p in parsers]
        assert "modbus" in names
        assert "s7comm" in names
        assert "dnp3" in names

    def test_returns_sorted(self):
        parsers = discover_parsers()
        names = [p.name for p in parsers]
        assert names == sorted(names)

    def test_entries_have_required_fields(self):
        parsers = discover_parsers()
        for p in parsers:
            assert p.name
            assert p.protocol_name
            assert p.module


class TestListParsers:
    def test_returns_dicts(self):
        parsers = list_parsers()
        assert isinstance(parsers, list)
        assert len(parsers) >= 3
        for p in parsers:
            assert "name" in p
            assert "protocol" in p
            assert "module" in p


class TestLoadParser:
    def test_load_builtin_returns_none_for_uninstantiable(self):
        # The builtin entries reference modules/classes that may not implement
        # the ProtocolParser protocol exactly. Loading them should not raise.
        entry = ParserEntry(
            name="nonexistent",
            protocol_name="Nonexistent",
            module="nonexistent_module",
            class_name="NonexistentClass",
        )
        # Should return None, not raise.
        parser = load_parser(entry)
        assert parser is None
