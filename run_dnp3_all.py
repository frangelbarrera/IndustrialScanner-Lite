# -*- coding: utf-8 -*-
"""
Batch runner for DNP3 Monitor
Processes all PCAP/PCAPNG files in pcaps/dnp3/ and generates JSON/HTML reports
in reports/dnp3_batch/
"""

import os
from dnp3_monitor import dnp3_analyze

PCAP_DIR = os.path.join("pcaps", "dnp3")
REPORT_DIR = os.path.join("reports", "dnp3_batch")

def main():
    if not os.path.exists(PCAP_DIR):
        print(f"[ERROR] Folder {PCAP_DIR} does not exist")
        return

    os.makedirs(REPORT_DIR, exist_ok=True)

    pcaps = [f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap") or f.endswith(".pcapng")]
    if not pcaps:
        print(f"[INFO] No .pcap files found in {PCAP_DIR}")
        return

    print(f"[INFO] Processing {len(pcaps)} DNP3 files...")

    for fname in pcaps:
        pcap_path = os.path.join(PCAP_DIR, fname)
        base = os.path.splitext(fname)[0]
        json_out = os.path.join(REPORT_DIR, f"{base}.json")
        html_out = os.path.join(REPORT_DIR, f"{base}.html")

        try:
            out = dnp3_analyze.main(
                pcap_file=pcap_path,
                json_out=json_out,
                html_out=html_out,
            )
            print(f"[OK] {fname} → {out['json']} | {out['html']}")
        except Exception as e:
            print(f"[ERROR] Failed {fname}: {e}")

if __name__ == "__main__":
    main()
