# -*- coding: utf-8 -*-
"""
Modbus Scanner (Read-only) - IndustrialScanner-Lite
Author: Frank + Copilot
Description:
  Safe, read-only Modbus/TCP scanner for OT networks. It probes hosts, reads small
  register/coils windows, assesses exposure risks, and generates JSON/HTML reports.

Usage (module):
  See CLI usage in cli.py or run directly:
    python -m modbus_scanner.modbus_scan --targets 192.168.0.10 --port 502 --unit 1
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

from jinja2 import Template
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusIOException

from .utils import (
    expand_targets,
    setup_logger,
    utc_ts,
    safe_str,
    html_template_path
)

LOG = setup_logger("modbus_scanner")


def probe_host(ip: str, port: int, unit_id: int, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Probe a single Modbus/TCP host safely (read-only).
    - Attempts short reads for coils, discrete inputs, holding and input registers.
    - Collects basic latency and exposure signals.
    """
    start = time.time()
    result: Dict[str, Any] = {
        "ip": ip,
        "port": port,
        "unit_id": unit_id,
        "reachable": False,
        "latency_ms": None,
        "reads": {
            "coils": None,
            "discrete_inputs": None,
            "holding_registers": None,
            "input_registers": None,
        },
        "exposure": {
            "unauthenticated_read": False,
            "broad_register_access": False,
        },
        "errors": []
    }

    try:
        client = ModbusTcpClient(host=ip, port=port, timeout=timeout)
        if not client.connect():
            result["errors"].append("Connection failed")
            return result

        result["reachable"] = True

        try:
            rr = client.read_coils(address=0, count=16, unit=unit_id)
            if not isinstance(rr, ModbusIOException) and rr.isError() is False:
                result["reads"]["coils"] = list(rr.bits) if rr.bits is not None else []
                result["exposure"]["unauthenticated_read"] = True
        except Exception as e:
            result["errors"].append(f"coils_read_error: {safe_str(e)}")

        try:
            rr = client.read_discrete_inputs(address=0, count=16, unit=unit_id)
            if not isinstance(rr, ModbusIOException) and rr.isError() is False:
                result["reads"]["discrete_inputs"] = list(rr.bits) if rr.bits is not None else []
                result["exposure"]["unauthenticated_read"] = True
        except Exception as e:
            result["errors"].append(f"discrete_inputs_read_error: {safe_str(e)}")

        try:
            rr = client.read_holding_registers(address=0, count=10, unit=unit_id)
            if not isinstance(rr, ModbusIOException) and rr.isError() is False:
                result["reads"]["holding_registers"] = list(rr.registers) if rr.registers is not None else []
                result["exposure"]["unauthenticated_read"] = True
        except Exception as e:
            result["errors"].append(f"holding_registers_read_error: {safe_str(e)}")

        try:
            rr = client.read_input_registers(address=0, count=10, unit=unit_id)
            if not isinstance(rr, ModbusIOException) and rr.isError() is False:
                result["reads"]["input_registers"] = list(rr.registers) if rr.registers is not None else []
                result["exposure"]["unauthenticated_read"] = True
        except Exception as e:
            result["errors"].append(f"input_registers_read_error: {safe_str(e)}")

        windows_with_data = sum(
            1 for k, v in result["reads"].items() if isinstance(v, list) and len(v) > 0
        )
        if windows_with_data >= 2:
            result["exposure"]["broad_register_access"] = True

    except Exception as e:
        result["errors"].append(f"probe_error: {safe_str(e)}")
    finally:
        try:
            client.close()
        except Exception:
            pass
        end = time.time()
        result["latency_ms"] = round((end - start) * 1000, 2)

    return result


def scan_targets(targets: List[str], port: int, unit_id: int, timeout: float) -> Dict[str, Any]:
    aggregate = {
        "meta": {
            "generated_at": utc_ts(),
            "targets": targets,
            "port": port,
            "unit_id": unit_id,
            "timeout": timeout,
        },
        "results": [],
        "summary": {
            "reachable": 0,
            "unauthenticated_read": 0,
            "broad_register_access": 0
        }
    }

    for ip in targets:
        LOG.info(f"Probing {ip}:{port} (unit {unit_id})")
        res = probe_host(ip, port, unit_id, timeout)
        aggregate["results"].append(res)

        if res["reachable"]:
            aggregate["summary"]["reachable"] += 1
        if res["exposure"]["unauthenticated_read"]:
            aggregate["summary"]["unauthenticated_read"] += 1
        if res["exposure"]["broad_register_access"]:
            aggregate["summary"]["broad_register_access"] += 1

    return aggregate


def write_json_report(data: Dict[str, Any], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return out_path


def write_html_report(data: Dict[str, Any], out_path: Path, template_path: Optional[Path] = None) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tpath = template_path or html_template_path("modbus_report.html")
    template_str = tpath.read_text(encoding="utf-8")
    template = Template(template_str)
    html = template.render(report=data)
    out_path.write_text(html, encoding="utf-8")
    return out_path


def main(
    targets_arg: str,
    port: int = 502,
    unit_id: int = 1,
    timeout: float = 2.0,
    json_out: Optional[str] = None,
    html_out: Optional[str] = None,
):
    targets = expand_targets(targets_arg)
    LOG.info(f"Expanded targets: {targets}")

    data = scan_targets(targets=targets, port=port, unit_id=unit_id, timeout=timeout)

    # Default outputs if not provided → ahora en reports/modbus_batch/
    ts = utc_ts().replace(":", "-")
    json_path = Path(json_out or f"reports/modbus_batch/modbus_scan_{ts}.json")
    html_path = Path(html_out or f"reports/modbus_batch/modbus_scan_{ts}.html")

    write_json_report(data, json_path)
    write_html_report(data, html_path)

    LOG.info(f"JSON report: {json_path}")
    LOG.info(f"HTML report: {html_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IndustrialScanner-Lite Modbus read-only scanner")
    parser.add_argument("--targets", required=True,
                        help="Comma-separated IPs, CIDR (e.g., 192.168.0.0/24), or @file with one IP per line")
    parser.add_argument("--port", type=int, default=502, help="Modbus/TCP port (default: 502)")
    parser.add_argument("--unit", type=int, default=1, help="Modbus Unit ID (default: 1)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds (default: 2.0)")
    parser.add_argument("--json-out", type=str, default=None, help="Path for JSON report")
    parser.add_argument("--html-out", type=str, default=None, help="Path for HTML report")

    args = parser.parse_args()
    main(
        targets_arg=args.targets,
        port=args.port,
        unit_id=args.unit,
        timeout=args.timeout,
        json_out=args.json_out,
        html_out=args.html_out,
    )
