# -*- coding: utf-8 -*-
"""
Minimalist Executive Meta-Dashboard
Consolidates global metrics for Modbus, S7Comm, and DNP3
and generates an index.html with summary and links.
"""

import os, json
from datetime import datetime

REPORTS = {
    "Modbus": os.path.join("reports", "modbus_batch"),
    "S7Comm": os.path.join("reports", "s7_batch"),
    "DNP3":   os.path.join("reports", "dnp3_batch"),
}

OUTPUT_FILE = os.path.join("reports", "index.html")

def collect_summary(folder):
    total_pcaps = 0
    total_packets = 0
    suspect = 0
    if not os.path.exists(folder):
        return (0,0,0)
    for fname in os.listdir(folder):
        if fname.endswith(".json"):
            total_pcaps += 1
            try:
                with open(os.path.join(folder, fname), "r", encoding="utf-8") as f:
                    data = json.load(f)
                summ = data.get("summary", {})
                total_packets += summ.get("total_packets", 0)
                suspect += summ.get("suspect_functions", 0)
            except:
                pass
    return (total_pcaps, total_packets, suspect)

def build_index(results):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    html = []
    html.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    html.append("<title>IndustrialScanner-Lite | Global Executive Dashboard</title>")
    html.append("<style>body{font-family:Arial;margin:24px;color:#222;} table{border-collapse:collapse;width:100%;margin-top:20px;} th,td{border:1px solid #ddd;padding:8px;} th{background:#f4f4f4;} .bad{color:#c62828;font-weight:bold;} a.button{display:inline-block;padding:6px 12px;margin:4px;background:#1976d2;color:#fff;text-decoration:none;border-radius:4px;}</style>")
    html.append("</head><body>")
    html.append("<h1>Global Executive Dashboard</h1>")
    html.append(f"<div><strong>Generated:</strong> {now}</div>")
    html.append("<table><tr><th>Protocol</th><th>PCAPs Processed</th><th>Total Packets</th><th>Suspect Functions</th><th>Dashboard</th></tr>")
    for proto, (pcaps, packets, suspects) in results.items():
        suspect_html = f"<span class='bad'>{suspects}</span>" if suspects>0 else str(suspects)
        link = f"{proto.lower()}_index.html"
        html.append(f"<tr><td>{proto}</td><td>{pcaps}</td><td>{packets}</td><td>{suspect_html}</td><td><a class='button' href='{link}'>Open {proto}</a></td></tr>")
    html.append("</table>")
    html.append("<p>This meta-dashboard provides an executive view: global metrics and quick access to each detailed analysis.</p>")
    html.append("</body></html>")
    return "\n".join(html)

if __name__ == "__main__":
    results = {}
    for proto, folder in REPORTS.items():
        results[proto] = collect_summary(folder)
    html = build_index(results)
    os.makedirs("reports", exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] Global meta-dashboard generated at {OUTPUT_FILE}")
