# -*- coding: utf-8 -*-
"""
Global Index Generator for S7Comm Analyzer with charts.
Reads all JSON reports in reports/s7_batch/ and builds an s7_index.html
with executive summary, links to HTML reports, and Chart.js visualizations.
"""

import os
import json
from datetime import datetime

REPORT_DIR = os.path.join("reports", "s7_batch")
OUTPUT_FILE = os.path.join("reports", "s7_index.html")

def load_reports():
    reports = []
    for fname in os.listdir(REPORT_DIR):
        if fname.endswith(".json"):
            path = os.path.join(REPORT_DIR, fname)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                html_name = fname.replace(".json", ".html")
                reports.append({
                    "json": fname,
                    "html": html_name,
                    "meta": data.get("meta", {}),
                    "summary": data.get("summary", {})
                })
            except Exception as e:
                print(f"[WARN] Could not read {fname}: {e}")
    return reports

def build_index(reports):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

    # Data for charts
    labels, total_packets, s7_packets, suspects = [], [], [], []

    for r in reports:
        labels.append(r["html"])
        summ = r["summary"]
        total_packets.append(summ.get("total_packets", 0))
        s7_packets.append(summ.get("s7_packets", 0))
        suspects.append(summ.get("suspect_functions", 0))

    html = []
    html.append("<!doctype html><html lang='en'><head>")
    html.append("<meta charset='utf-8'>")
    html.append("<title>IndustrialScanner-Lite | S7Comm Global Report Index</title>")
    html.append("<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>")
    html.append("<style>")
    html.append("body { font-family: Arial, sans-serif; margin: 24px; color: #222; }")
    html.append("h1 { margin-bottom: 4px; }")
    html.append("table { border-collapse: collapse; width: 100%; margin-top: 12px; }")
    html.append("th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; }")
    html.append("th { background: #f4f4f4; text-align: left; }")
    html.append(".bad { color: #c62828; font-weight: bold; }")
    html.append(".charts { display: flex; gap: 40px; margin-top: 24px; }")
    html.append(".chart-container { width: 45%; }")
    html.append("</style></head><body>")
    html.append("<h1>S7Comm Global Report Index</h1>")
    html.append(f"<div><strong>Generated:</strong> {now}</div>")

    # Consolidated table
    html.append("<table>")
    html.append("<tr><th>Report</th><th>PCAP File</th><th>Total Packets</th><th>S7 Packets</th><th>Suspect Functions</th><th>Unique Hosts</th></tr>")
    for r in reports:
        meta, summ = r["meta"], r["summary"]
        suspect = summ.get("suspect_functions", 0)
        suspect_html = f"<span class='bad'>{suspect}</span>" if suspect > 0 else str(suspect)
        html.append("<tr>")
        html.append(f"<td><a href='s7_batch/{r['html']}'>{r['html']}</a></td>")
        html.append(f"<td>{meta.get('pcap_file','')}</td>")
        html.append(f"<td>{summ.get('total_packets','')}</td>")
        html.append(f"<td>{summ.get('s7_packets','')}</td>")
        html.append(f"<td>{suspect_html}</td>")
        html.append(f"<td>{', '.join(summ.get('unique_hosts', []))}</td>")
        html.append("</tr>")
    html.append("</table>")

    # Charts
    html.append("<div class='charts'>")
    html.append("<div class='chart-container'><canvas id='chartPackets'></canvas></div>")
    html.append("<div class='chart-container'><canvas id='chartSuspects'></canvas></div>")
    html.append("</div>")
    html.append("<script>")
    html.append(f"const labels = {labels};")
    html.append(f"const totalPackets = {total_packets};")
    html.append(f"const s7Packets = {s7_packets};")
    html.append(f"const suspects = {suspects};")
    html.append("""
    new Chart(document.getElementById('chartPackets'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                { label: 'Total Packets', data: totalPackets, backgroundColor: 'rgba(54, 162, 235, 0.6)' },
                { label: 'S7 Packets', data: s7Packets, backgroundColor: 'rgba(75, 192, 192, 0.6)' }
            ]
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'top' } },
            scales: { x: { ticks: { autoSkip: false, maxRotation: 90, minRotation: 45 } } }
        }
    });
    new Chart(document.getElementById('chartSuspects'), {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                label: 'Suspect Functions',
                data: suspects,
                backgroundColor: [
                    'rgba(255, 99, 132, 0.6)',
                    'rgba(255, 159, 64, 0.6)',
                    'rgba(255, 205, 86, 0.6)',
                    'rgba(75, 192, 192, 0.6)',
                    'rgba(54, 162, 235, 0.6)',
                    'rgba(153, 102, 255, 0.6)',
                    'rgba(201, 203, 207, 0.6)'
                ]
            }]
        },
        options: { responsive: true, plugins: { legend: { position: 'right' } } }
    });
    """)
    html.append("</script>")

    # Notes
    html.append("<h2>Notes</h2><ul>")
    html.append("<li>This index consolidates all reports generated in <code>reports/s7_batch/</code>.</li>")
    html.append("<li>Click on the report name to open the detailed HTML view.</li>")
    html.append("<li>Values in red indicate detected suspect functions (Start, Stop, WriteVar, DownloadBlock, CopyRamToRom, FirmwareUpdate).</li>")
    html.append("<li>The charts display the global distribution of packets and suspect functions.</li>")
    html.append("</ul>")
    html.append("</body></html>")
    return "\n".join(html)

if __name__ == "__main__":
    reports = load_reports()
    if not reports:
        print("[INFO] No JSON reports found in reports/s7_batch/")
    else:
        html = build_index(reports)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[OK] Global S7Comm index generated at {OUTPUT_FILE}")
