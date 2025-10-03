# -*- coding: utf-8 -*-
"""
Passive analyzer for Siemens S7Comm traffic.
Scans all PCAP/PCAPNG files inside pcaps/s7/,
extracts metadata, detects sensitive function codes,
and generates JSON/HTML reports in reports/s7_batch/.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

from jinja2 import Template
from scapy.all import rdpcap, TCP

from .parsers import parse_s7_packet
from modbus_scanner.utils import setup_logger, utc_ts, html_template_path

LOG = setup_logger("s7_analyzer")

PCAP_DIR = Path("pcaps/s7")
OUT_DIR = Path("reports/s7_batch")


def analyze_pcap(pcap_path: str) -> Dict[str, Any]:
    """Analyze a PCAP file for S7Comm traffic."""
    packets = rdpcap(str(pcap_path))
    results = []
    summary = {
        "total_packets": 0,
        "s7_packets": 0,
        "suspect_functions": 0,
        "unique_hosts": set()
    }

    for pkt in packets:
        summary["total_packets"] += 1
        if TCP in pkt and (pkt[TCP].dport == 102 or pkt[TCP].sport == 102):
            parsed = parse_s7_packet(pkt)
            if parsed:
                results.append(parsed)
                summary["s7_packets"] += 1
                summary["unique_hosts"].add(parsed["src"])
                summary["unique_hosts"].add(parsed["dst"])
                if parsed["function_code"] in {
                    "WriteVar", "Start", "Stop", "DownloadBlock", "CopyRamToRom", "FirmwareUpdate"
                }:
                    summary["suspect_functions"] += 1

    return {
        "meta": {
            "generated_at": utc_ts(),
            "pcap_file": str(pcap_path),
        },
        "results": results,
        "summary": {
            "total_packets": summary["total_packets"],
            "s7_packets": summary["s7_packets"],
            "suspect_functions": summary["suspect_functions"],
            "unique_hosts": list(filter(None, summary["unique_hosts"]))
        }
    }


def write_json_report(data: Dict[str, Any], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return out_path


def write_html_report(data: Dict[str, Any], out_path: Path, template_path: Optional[Path] = None) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tpath = template_path or html_template_path("s7_report.html")
    template_str = tpath.read_text(encoding="utf-8")
    template = Template(template_str)
    html = template.render(report=data)
    out_path.write_text(html, encoding="utf-8")
    return out_path


def main():
    if not PCAP_DIR.exists():
        LOG.error(f"PCAP folder does not exist: {PCAP_DIR}")
        return

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    pcaps = [f for f in PCAP_DIR.iterdir() if f.suffix in [".pcap", ".pcapng"]]
    if not pcaps:
        LOG.info(f"No PCAP files found in {PCAP_DIR}")
        return

    LOG.info(f"Processing {len(pcaps)} S7 PCAP files from {PCAP_DIR}...")

    for pcap_file in pcaps:
        LOG.info(f"Analyzing {pcap_file.name}")
        try:
            data = analyze_pcap(pcap_file)
            base = pcap_file.stem
            json_path = OUT_DIR / f"{base}.json"
            html_path = OUT_DIR / f"{base}.html"
            write_json_report(data, json_path)
            write_html_report(data, html_path)
            LOG.info(f"[OK] Reports generated: {json_path}, {html_path}")
        except Exception as e:
            LOG.error(f"[ERROR] Failed to process {pcap_file}: {e}")


if __name__ == "__main__":
    main()
