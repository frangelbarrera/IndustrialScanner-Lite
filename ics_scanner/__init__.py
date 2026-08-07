"""
ics_scanner: shared security primitives, MITRE ATT&CK mapping, and
protocol parser plugin registry for IndustrialScanner.
"""
from __future__ import annotations

from .mitre_attack import (
    ATTACKTechnique,
    enrich_report_with_attack,
    map_function_to_techniques,
)
from .plugins import (
    ProtocolParser,
    discover_parsers,
    list_parsers,
    load_parser,
)
from .security import (
    TargetPolicyError,
    configure_logging,
    html_escape,
    is_safe_target,
    safe_join_path,
    safe_render,
)

__all__ = [
    "ATTACKTechnique",
    "ProtocolParser",
    "TargetPolicyError",
    "configure_logging",
    "discover_parsers",
    "enrich_report_with_attack",
    "html_escape",
    "is_safe_target",
    "list_parsers",
    "load_parser",
    "map_function_to_techniques",
    "safe_join_path",
    "safe_render",
]

__version__ = "0.2.0.dev0"
