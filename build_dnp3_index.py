# -*- coding: utf-8 -*-
"""
Generador de índice global para DNP3 Monitor
Lee todos los reportes JSON en reports/dnp3_batch/ y construye un index.html
con tabla consolidada y gráficas interactivas (Chart.js).
"""

import os
import json
from datetime import datetime

REPORT_DIR = os.path.join("reports", "dnp3_batch")
OUTPUT_FILE = os.path.join("reports", "dnp3_index.html")

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
                print(f"[WARN] No se pudo leer {fname}: {e}")
    return reports

def build_index(reports):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

    labels = []
    total_packets = []
    dnp3_packets = []
    suspects = []

    for r in reports:
        labels.append(r["html"])
        summ = r["summary"]
        total_packets.append(summ.get("total_packets", 0))
        dnp3_packets.append(summ.get("dnp3_packets", 0))
        suspects.append(summ.get("suspect_functions", 0))

    html = []
    html.append("<!doctype html>")
    html.append("<html lang='en'>")
    html.append("<head>")
    html.append("<meta charset='utf-8'>")
    html.append("<title>IndustrialScanner-Lite | DNP3 Global Report Index</title>")
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
    html.append("</style>")
    html.append("</head><body>")
    html.append("<h1>DNP3 Global Report Index</h1>")
    html.append(f"<div><strong>Generated:</strong> {now}</div>")

    # Consolidated table
    html.append("<table>")
    html.append("<tr><th>Report</th><th>PCAP File</th><th>Total Packets</th><th>DNP3 Packets</th><th>Suspect Functions</th><th>Unique Hosts</th></tr>")
    for r in reports:
        meta = r["meta"]
        summ = r["summary"]
        suspect = summ.get("suspect_functions", 0)
        suspect_html = f"<span class='bad'>{suspect}</span>" if suspect and suspect > 0 else str(suspect)
        html.append("<tr>")
        html.append(f"<td><a href='dnp3_batch/{r['html']}'>{r['html']}</a></td>")
        html.append(f"<td>{meta.get('pcap_file','')}</td>")
        html.append(f"<td>{summ.get('total_packets','')}</td>")
        html.append(f"<td>{summ.get('dnp3_packets','')}</td>")
        html.append(f"<td>{suspect_html}</td>")
        html.append(f"<td>{', '.join(summ.get('unique_hosts', []))}</td>")
        html.append("</tr>")
    html.append("</table>")

    # Graphics
    html.append("<div class='charts'>")
    html.append("<div class='chart-container'><canvas id='chartPackets'></canvas></div>")
    html.append("<div class='chart-container'><canvas id='chartSuspects'></canvas></div>")
    html.append("</div>")

    html.append("<script>")
    html.append(f"const labels = {labels};")
    html.append(f"const totalPackets = {total_packets};")
    html.append(f"const dnp3Packets = {dnp3_packets};")
    html.append(f"const suspects = {suspects};")

    
    html.append("""
    new Chart(document.getElementById('chartPackets'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                { label: 'Total Packets', data: totalPackets, backgroundColor: 'rgba(54, 162, 235, 0.6)' },
                { label: 'DNP3 Packets', data: dnp3Packets, backgroundColor: 'rgba(75, 192, 192, 0.6)' }
            ]
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'top' } },
            scales: { x: { ticks: { autoSkip: false, maxRotation: 90, minRotation: 45 } } }
        }
    });
    """)

    
    html.append("""
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
        options: {
            responsive: true,
            plugins: { legend: { position: 'right' } }
        }
    });
    """)
    html.append("</script>")

    # Notes
    html.append("<h2>Notes</h2>")
    html.append("<ul>")
    html.append("<li>Este índice consolida todos los reportes generados en <code>reports/dnp3_batch/</code>.</li>")
    html.append("<li>Haz clic en el nombre del reporte para abrir el HTML detallado.</li>")
    html.append("<li>Los valores en rojo indican funciones sospechosas detectadas (Operate, Write, EnableUnsolicited, Restart).</li>")
    html.append("<li>Las gráficas muestran la distribución global de paquetes y funciones sospechosas.</li>")
    html.append("</ul>")

    html.append("</body></html>")
    return "\n".join(html)

if __name__ == "__main__":
    reports = load_reports()
    if not reports:
        print("[INFO] No se encontraron reportes JSON en reports/dnp3_batch/")
    else:
        html = build_index(reports)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[OK] Índice global de DNP3 generado en {OUTPUT_FILE}")
# -*- coding: utf-8 -*-
"""
Global Index Generator for DNP3 Monitor
Reads all JSON reports in reports/dnp3_batch/ and builds an index.html
with a consolidated table and interactive charts (Chart.js).
"""

import os
import json
from datetime import datetime

REPORT_DIR = os.path.join("reports", "dnp3_batch")
OUTPUT_FILE = os.path.join("reports", "dnp3_index.html")

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

    labels = []
    total_packets = []
    dnp3_packets = []
    suspects = []

    for r in reports:
        labels.append(r["html"])
        summ = r["summary"]
        total_packets.append(summ.get("total_packets", 0))
        dnp3_packets.append(summ.get("dnp3_packets", 0))
        suspects.append(summ.get("suspect_functions", 0))

    html = []
    html.append("<!doctype html>")
    html.append("<html lang='en'>")
    html.append("<head>")
    html.append("<meta charset='utf-8'>")
    html.append("<title>IndustrialScanner-Lite | DNP3 Global Report Index</title>")
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
    html.append("</style>")
    html.append("</head><body>")
    html.append("<h1>DNP3 Global Report Index</h1>")
    html.append(f"<div><strong>Generated:</strong> {now}</div>")

    # Consolidated table
    html.append("<table>")
    html.append("<tr><th>Report</th><th>PCAP File</th><th>Total Packets</th><th>DNP3 Packets</th><th>Suspect Functions</th><th>Unique Hosts</th></tr>")
    for r in reports:
        meta = r["meta"]
        summ = r["summary"]
        suspect = summ.get("suspect_functions", 0)
        suspect_html = f"<span class='bad'>{suspect}</span>" if suspect and suspect > 0 else str(suspect)
        html.append("<tr>")
        html.append(f"<td><a href='dnp3_batch/{r['html']}'>{r['html']}</a></td>")
        html.append(f"<td>{meta.get('pcap_file','')}</td>")
        html.append(f"<td>{summ.get('total_packets','')}</td>")
        html.append(f"<td>{summ.get('dnp3_packets','')}</td>")
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
    html.append(f"const dnp3Packets = {dnp3_packets};")
    html.append(f"const suspects = {suspects};")

    html.append("""
    new Chart(document.getElementById('chartPackets'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                { label: 'Total Packets', data: totalPackets, backgroundColor: 'rgba(54, 162, 235, 0.6)' },
                { label: 'DNP3 Packets', data: dnp3Packets, backgroundColor: 'rgba(75, 192, 192, 0.6)' }
            ]
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'top' } },
            scales: { x: { ticks: { autoSkip: false, maxRotation: 90, minRotation: 45 } } }
        }
    });
    """)

    html.append("""
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
        options: {
            responsive: true,
            plugins: { legend: { position: 'right' } }
        }
    });
    """)
    html.append("</script>")

    # Notes
    html.append("<h2>Notes</h2>")
    html.append("<ul>")
    html.append("<li>This index consolidates all reports generated in <code>reports/dnp3_batch/</code>.</li>")
    html.append("<li>Click on the report name to open the detailed HTML view.</li>")
    html.append("<li>Values in red indicate detected suspect functions (Operate, Write, EnableUnsolicited, Restart).</li>")
    html.append("<li>The charts display the global distribution of packets and suspect functions.</li>")
    html.append("</ul>")

    html.append("</body></html>")
    return "\n".join(html)

if __name__ == "__main__":
    reports = load_reports()
    if not reports:
        print("[INFO] No JSON reports found in reports/dnp3_batch/")
    else:
        html = build_index(reports)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[OK] Global DNP3 index generated at {OUTPUT_FILE}")
