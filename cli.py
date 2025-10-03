# -*- coding: utf-8 -*-
"""
IndustrialScanner-Lite - Project-level CLI

Modules:
  - modbus: Read-only Modbus/TCP scanner
  - s7: Passive S7Comm analyzer (from PCAP)
  - dnp3: Passive DNP3 analyzer (from PCAP)

Examples:
  python cli.py modbus --targets 192.168.0.100,192.168.0.101 --unit 1
  python cli.py modbus --targets 192.168.0.0/24 --json-out reports/out.json --html-out reports/out.html
  python cli.py modbus --targets @targets.txt --port 502 --timeout 2.5

  python cli.py s7 --pcap pruebas_s7.pcap
  python cli.py s7 --pcap pruebas_s7.pcap --json-out reports/s7.json --html-out reports/s7.html

  python cli.py dnp3 --pcap pruebas_dnp3.pcap
  python cli.py dnp3 --pcap pruebas_dnp3.pcap --json-out reports/dnp3.json --html-out reports/dnp3.html
"""

import argparse

# Import modules
from modbus_scanner.modbus_scan import main as modbus_main
from s7_comm_analyzer.s7_analyze import main as s7_main
from dnp3_monitor.dnp3_analyze import main as dnp3_main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IndustrialScanner-Lite CLI")
    sub = parser.add_subparsers(dest="module", required=True)

    # -------------------
    # Modbus subcommand
    # -------------------
    p_modbus = sub.add_parser("modbus", help="Read-only Modbus/TCP scanner")
    p_modbus.add_argument("--targets", required=True,
                          help="Comma-separated IPs, CIDR (e.g., 192.168.0.0/24), or @file with one IP per line")
    p_modbus.add_argument("--port", type=int, default=502, help="Modbus/TCP port (default: 502)")
    p_modbus.add_argument("--unit", type=int, default=1, help="Modbus Unit ID (default: 1)")
    p_modbus.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds (default: 2.0)")
    p_modbus.add_argument("--json-out", type=str, default=None, help="Path for JSON report")
    p_modbus.add_argument("--html-out", type=str, default=None, help="Path for HTML report")

    # -------------------
    # S7Comm subcommand
    # -------------------
    p_s7 = sub.add_parser("s7", help="Passive S7Comm analyzer (from PCAP)")
    p_s7.add_argument("--pcap", required=True, help="Path to PCAP file with S7Comm traffic")
    p_s7.add_argument("--json-out", type=str, default=None, help="Path for JSON report")
    p_s7.add_argument("--html-out", type=str, default=None, help="Path for HTML report")

    # -------------------
    # DNP3 subcommand
    # -------------------
    p_dnp3 = sub.add_parser("dnp3", help="Passive DNP3 analyzer (from PCAP)")
    p_dnp3.add_argument("--pcap", required=True, help="Path to PCAP file with DNP3 traffic")
    p_dnp3.add_argument("--json-out", type=str, default=None, help="Path for JSON report")
    p_dnp3.add_argument("--html-out", type=str, default=None, help="Path for HTML report")

    return parser


def dispatch(args: argparse.Namespace):
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
        s7_main(
            pcap_file=args.pcap,
            json_out=args.json_out,
            html_out=args.html_out,
        )
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

