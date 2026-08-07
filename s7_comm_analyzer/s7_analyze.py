"""
Passive analyzer for Siemens S7Comm traffic.

Scans all PCAP/PCAPNG files inside pcaps/s7/, extracts metadata, detects
sensitive function codes, and generates JSON/HTML reports in reports/s7_batch/.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scapy.all import TCP, rdpcap

from modbus_scanner.utils import setup_logger, utc_ts

from .parsers import parse_s7_packet

LOG = setup_logger("s7_analyzer")

PCAP_DIR = Path("pcaps/s7")
OUT_DIR = Path("reports/s7_batch")


def analyze_pcap(pcap_path: str) -> dict[str, Any]:
    """Analyze a PCAP file for S7Comm traffic."""
    packets = rdpcap(str(pcap_path))
    results: list[dict[str, Any]] = []
    summary = {
        "total_packets": 0,
        "s7_packets": 0,
        "suspect_functions": 0,
        "unique_hosts": set(),
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
                    "WriteVar",
                    "Start",
                    "Stop",
                    "DownloadBlock",
                    "CopyRamToRom",
                    "FirmwareUpdate",
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
            "unique_hosts": list(filter(None, summary["unique_hosts"])),
        },
    }


def write_json_report(data: dict[str, Any], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return out_path


def write_html_report(
    data: dict[str, Any], out_path: Path, template_path: Path | None = None
) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Render with autoescape=True to prevent XSS from untrusted PCAP bytes.
    from ics_scanner.security import safe_render

    template_dir = template_path.parent if template_path else Path("reports/templates")
    template_name = template_path.name if template_path else "s7_report.html"
    html = safe_render(template_name, {"report": data}, template_dir=str(template_dir))
    out_path.write_text(html, encoding="utf-8")
    return out_path


def main() -> None:
    if not PCAP_DIR.exists():
        LOG.error("PCAP folder does not exist: %s", PCAP_DIR)
        return

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    pcaps = [f for f in PCAP_DIR.iterdir() if f.suffix in (".pcap", ".pcapng")]
    if not pcaps:
        LOG.info("No PCAP files found in %s", PCAP_DIR)
        return

    LOG.info("Processing %d S7 PCAP files from %s...", len(pcaps), PCAP_DIR)

    for pcap_file in pcaps:
        LOG.info("Analyzing %s", pcap_file.name)
        try:
            data = analyze_pcap(pcap_file)
            base = pcap_file.stem
            json_path = OUT_DIR / f"{base}.json"
            html_path = OUT_DIR / f"{base}.html"
            write_json_report(data, json_path)
            write_html_report(data, html_path)
            LOG.info("[OK] Reports generated: %s, %s", json_path, html_path)
        except Exception as e:
            LOG.error("[ERROR] Failed to process %s: %s", pcap_file, e)


if __name__ == "__main__":
    main()
