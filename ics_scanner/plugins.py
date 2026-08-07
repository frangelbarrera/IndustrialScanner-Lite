"""
Protocol parser plugin registry.

Provides a pluggable architecture for protocol parsers via Python entry points.
Third-party packages can register new protocol parsers by adding an entry
under the `industrial_scanner.parsers` group in their pyproject.toml:

    [project.entry-points."industrial_scanner.parsers"]
    proflnet = "my_package.profinet_parser:ProfinetParser"

Parsers must implement the `ProtocolParser` protocol defined below.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ProtocolParser(Protocol):
    """Protocol that every protocol parser must implement."""

    @property
    def protocol_name(self) -> str:
        """Human-readable protocol name (e.g., 'Modbus/TCP', 'S7Comm')."""
        ...

    def can_parse(self, packet: Any) -> bool:
        """Return True if this parser can handle the given packet."""
        ...

    def parse(self, packet: Any) -> dict[str, Any] | None:
        """Parse a single packet into a structured dict.

        Returns None if the packet cannot be parsed (e.g., not for this
        protocol), or a dict with at minimum: src, dst, function, length.
        """
        ...


@dataclass(frozen=True)
class ParserEntry:
    """A registered parser plugin."""

    name: str  # short identifier (e.g., 'modbus')
    protocol_name: str  # human-readable (e.g., 'Modbus/TCP')
    module: str  # python module path
    class_name: str  # parser class name
    description: str = ""


ENTRY_POINT_GROUP = "industrial_scanner.parsers"


def discover_parsers() -> list[ParserEntry]:
    """Discover all installed parser plugins via entry points.

    Returns a sorted list of ParserEntry instances. Built-in parsers
    (modbus, s7comm, dnp3) are always included; third-party parsers
    are discovered via setuptools entry points.
    """
    entries: list[ParserEntry] = []

    # Built-in parsers (always available)
    builtins = [
        ParserEntry(
            name="modbus",
            protocol_name="Modbus/TCP",
            module="modbus_scanner.modbus_scan",
            class_name="ModbusScanner",
            description="Active read-only Modbus/TCP scanner (function codes 0x01-0x04).",
        ),
        ParserEntry(
            name="s7comm",
            protocol_name="Siemens S7Comm",
            module="s7_comm_analyzer.parsers",
            class_name="S7CommParser",
            description="Passive S7Comm parser (TPKT/COTP/S7 stack on TCP/102).",
        ),
        ParserEntry(
            name="dnp3",
            protocol_name="DNP3 (IEEE 1815)",
            module="dnp3_monitor.parsers",
            class_name="DNP3Parser",
            description="Passive DNP3 parser (link + transport + application layer).",
        ),
    ]
    entries.extend(builtins)

    # Discover third-party parsers via entry points
    try:
        eps = importlib_metadata.entry_points()
        if hasattr(eps, "select"):
            group = eps.select(group=ENTRY_POINT_GROUP)
        else:  # Python <3.10 fallback
            group = eps.get(ENTRY_POINT_GROUP, [])
        for ep in group:
            entries.append(
                ParserEntry(
                    name=ep.name,
                    protocol_name=ep.name.replace("_", " ").title(),
                    module=ep.value.split(":")[0] if ":" in ep.value else ep.value,
                    class_name=ep.value.split(":")[1] if ":" in ep.value else "",
                    description=f"Third-party parser via entry point: {ep.value}",
                )
            )
    except Exception:
        # If entry point discovery fails (e.g., no metadata), return builtins only.
        pass

    return sorted(entries, key=lambda e: e.name)


def load_parser(entry: ParserEntry) -> ProtocolParser | None:
    """Load and instantiate a parser plugin.

    Returns None if the parser cannot be loaded.
    """
    try:
        import importlib

        module = importlib.import_module(entry.module)
        cls = getattr(module, entry.class_name)
        return cls()
    except Exception:
        return None


def list_parsers() -> list[dict[str, str]]:
    """Return a list of parser metadata dicts (for CLI display)."""
    return [
        {
            "name": e.name,
            "protocol": e.protocol_name,
            "module": e.module,
            "class": e.class_name,
            "description": e.description,
        }
        for e in discover_parsers()
    ]
