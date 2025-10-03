# -*- coding: utf-8 -*-
"""
DNP3 Monitor: PCAP analysis for DNP3 traffic over TCP/UDP port 20000.
Generates JSON and HTML reports with summary and per-packet details.
"""
import json
import os
from typing import Any, Dict, List
from datetime import datetime
from scapy.all import rdpcap, TCP, UDP
from .parsers import parse_dnp3_packet, SUSPECT_FUNCS

def utc_ts() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")

def analyze_pcap(pcap_path: str) -> Dict[str, Any]:
    packets = rdpcap(pcap_path)
    results: List[Dict[str, Any]] = []

    summary = {
        "total_packets": 0,
        "dnp3_packets": 0,
        "suspect_functions": 0,
        "unique_hosts": set()
    }

    for pkt in packets:
        summary["total_packets"] += 1
        is_dnp3 = False
        if TCP in pkt and (pkt[TCP].dport == 20000 or pkt[TCP].sport == 20000):
            is_dnp3 = True
        elif UDP in pkt and (pkt[UDP].dport == 20000 or pkt[UDP].sport == 20000):
            is_dnp3 = True

        if not is_dnp3:
            continue

        parsed = parse_dnp3_packet(pkt)
        if parsed:
            results.append(parsed)
            summary["dnp3_packets"] += 1
            summary["unique_hosts"].add(parsed["src"])
            summary["unique_hosts"].add(parsed["dst"])
            if parsed.get("suspect"):
                summary["suspect_functions"] += 1

    return {
        "meta": {
            "generated_at": utc_ts(),
            "pcap_file": pcap_path,
        },
        "results": results,
        "summary": {
            "total_packets": summary["total_packets"],
            "dnp3_packets": summary["dnp3_packets"],
            "suspect_functions": summary["suspect_functions"],
            "unique_hosts": list(filter(None, summary["unique_hosts"]))
        }
    }

def save_json(report: Dict[str, Any], json_out: str) -> None:
    os.makedirs(os.path.dirname(json_out), exist_ok=True)
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

def build_html(report: Dict[str, Any]) -> str:
    
    rows = []
    for r in report.get("results", []):
        func = r.get("function", "")
        func_html = f"<span class='bad'>{func}</span>" if r.get("suspect") else func
        hints = ", ".join(r.get("hints", []))
        rows.append(
            f"<tr>"
            f"<td>{r.get('src','')}</td>"
            f"<td>{r.get('dst','')}</td>"
            f"<td>{func_html}</td>"
            f"<td>{r.get('length','')}</td>"
            f"<td>{hints}</td>"
            f"</tr>"
        )

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>IndustrialScanner-Lite | DNP3 Analysis Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #222; }}
    h1 {{ margin-bottom: 4px; }}
    .meta {{ color: #555; margin-bottom: 16px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; font-size: 14px; }}
    th {{ background: #f4f4f4; text-align: left; }}
    .bad {{ color: #c62828; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>DNP3 Analysis Report</h1>
  <div class="meta">
    <div><strong>Generated:</strong> {report['meta']['generated_at']}</div>
    <div><strong>PCAP File:</strong> {report['meta']['pcap_file']}</div>
  </div>

  <h2>Summary</h2>
  <table>
    <tr>
      <th>Total Packets</th>
      <th>DNP3 Packets</th>
      <th>Suspect Functions</th>
      <th>Unique Hosts</th>
    </tr>
    <tr>
      <td>{report['summary']['total_packets']}</td>
      <td>{report['summary']['dnp3_packets']}</td>
      <td>{report['summary']['suspect_functions']}</td>
      <td>{", ".join(report['summary']['unique_hosts'])}</td>
    </tr>
  </table>

  <h2>Per-Packet Details</h2>
  <table>
    <tr>
      <th>Source</th>
      <th>Destination</th>
      <th>Function</th>
      <th>Length</th>
      <th>Hints</th>
    </tr>
    {''.join(rows)}
  </table>

  <h2>Notes</h2>
  <ul>
    <li>This analysis is passive and read-only.</li>
    <li>Suspect operations include Operate, Write, EnableUnsolicited, and Restart commands.</li>
    <li>Heuristic parsing: deeper decoding can be added later.</li>
  </ul>
</body>
</html>
"""
    return html

def save_html(report: Dict[str, Any], html_out: str) -> None:
    os.makedirs(os.path.dirname(html_out), exist_ok=True)
    html = build_html(report)
    with open(html_out, "w", encoding="utf-8") as f:
        f.write(html)

def main(
    pcap_file: str,
    json_out: str = None,
    html_out: str = None,
) -> Dict[str, Any]:
    data = analyze_pcap(pcap_file)
    if not json_out:
        json_out = os.path.join("reports", f"dnp3_scan_{utc_ts()}.json")
    if not html_out:
        html_out = os.path.join("reports", f"dnp3_scan_{utc_ts()}.html")

    save_json(data, json_out)
    save_html(data, html_out)
    return {
        "json": json_out,
        "html": html_out,
    }
