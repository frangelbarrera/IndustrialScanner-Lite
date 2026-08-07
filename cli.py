"""
IndustrialScanner - Project-level legacy CLI.

Note: For new code, prefer the unified CLI in ics_scanner/cli.py which uses
Click + Rich and enforces the target safety policy. This file is kept for
backward compatibility with documented entry points.

Modules:
  - modbus: Read-only Modbus/TCP scanner
  - s7: Passive S7Comm analyzer (from PCAP)
  - dnp3: Passive DNP3 analyzer (from PCAP)
"""
from __future__ import annotations

import argparse

from dnp3_monitor.dnp3_analyze import main as dnp3_main
from modbus_scanner.modbus_scan import main as modbus_main
from modbus_scanner.utils import utc_ts
from s7_comm_analyzer.s7_analyze import analyze_pcap
from s7_comm_analyzer.s7_analyze import write_html_report as s7_write_html
from s7_comm_analyzer.s7_analyze import write_json_report as s7_write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IndustrialScanner CLI")
    sub = parser.add_subparsers(dest="module", required=True)

    p_modbus = sub.add_parser("modbus", help="Read-only Modbus/TCP scanner")
    p_modbus.add_argument(
        "--targets", required=True,
        help="Comma-separated IPs, CIDR (e.g., 192.168.0.0/24), or @file with one IP per line",
    )
    p_modbus.add_argument("--port", type=int, default=502, help="Modbus/TCP port (default: 502)")
    p_modbus.add_argument("--unit", type=int, default=1, help="Modbus Unit ID (default: 1)")
    p_modbus.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds (default: 2.0)")
    p_modbus.add_argument("--json-out", type=str, default=None, help="Path for JSON report")
    p_modbus.add_argument("--html-out", type=str, default=None, help="Path for HTML report")

    p_s7 = sub.add_parser("s7", help="Passive S7Comm analyzer (from PCAP)")
    p_s7.add_argument("--pcap", required=True, help="Path to PCAP file with S7Comm traffic")
    p_s7.add_argument("--json-out", type=str, default=None, help="Path for JSON report")
    p_s7.add_argument("--html-out", type=str, default=None, help="Path for HTML report")

    p_dnp3 = sub.add_parser("dnp3", help="Passive DNP3 analyzer (from PCAP)")
    p_dnp3.add_argument("--pcap", required=True, help="Path to PCAP file with DNP3 traffic")
    p_dnp3.add_argument("--json-out", type=str, default=None, help="Path for JSON report")
    p_dnp3.add_argument("--html-out", type=str, default=None, help="Path for HTML report")

    return parser


def dispatch(args: argparse.Namespace) -> None:
    if args.module == "modbus":
        modbus_main(
            targets_arg=args.targets,
            port=args.port,
            unit_id=args.unit,
            timeout=args.timeout,
            json_out=args.json_out,
            html_out=args.html_out,
        )
    elif args.module == "s7":
        # s7_analyze.main() takes no args (processes pcaps/s7/* directly).
        # The CLI honors --pcap by calling analyze_pcap() and writing the
        # requested output paths.
        from pathlib import Path
        data = analyze_pcap(args.pcap)
        ts = utc_ts().replace(":", "-")
        base = Path(args.pcap).stem
        json_path = Path(args.json_out or f"reports/s7_batch/{base}_{ts}.json")
        html_path = Path(args.html_out or f"reports/s7_batch/{base}_{ts}.html")
        s7_write_json(data, json_path)
        s7_write_html(data, html_path)
    elif args.module == "dnp3":
        dnp3_main(
            pcap_file=args.pcap,
            json_out=args.json_out,
            html_out=args.html_out,
        )
    else:
        raise SystemExit(f"Unknown module: {args.module}")


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    dispatch(args)
