# MITRE ATT&CK for ICS mapping

IndustrialScanner maps every detected protocol function to one or more
MITRE ATT&CK for ICS techniques. This allows SOC analysts to enrich
findings with the MITRE framework they already use.

## How it works

The mapping is defined in `ics_scanner/mitre_attack.py` as a
`PROTOCOL_FUNCTION_MAPPING` dict:

```python
PROTOCOL_FUNCTION_MAPPING = {
    "s7comm": {
        "ReadVar": ["T0801", "T0802", "T0808", "T0881"],
        "WriteVar": ["T0848", "T0858"],
        "Start": ["T0858"],
        "Stop": ["T0858"],
        "DownloadBlock": ["T0848", "T0885", "T0879"],
        "FirmwareUpdate": ["T0858", "T0885", "T0879"],
        ...
    },
    "dnp3": {
        "Read": ["T0801", "T0802", "T0808", "T0881"],
        "Operate": ["T0858", "T0894"],
        "ColdRestart": ["T0858", "T0879"],
        ...
    },
}
```

Each report produced by `analyze_pcap_service` includes a `mitre_attack`
field per result, listing the techniques that match the detected function.

## Technique catalog

The full catalog of techniques used by IndustrialScanner:

| Technique | Name | Tactic | When it's mapped |
|---|---|---|---|
| T0801 | Monitor Process State | Discovery | Read operations (Modbus, S7, DNP3) |
| T0802 | Automated Discovery | Discovery | Read operations (Modbus, S7, DNP3) |
| T0808 | Control System Identification | Discovery | SetupComm, Diagnostics |
| T0848 | Modify Program | Execution, Persistence | WriteVar, DownloadBlock, Write |
| T0858 | Change Operating Mode | Execution, Impact | Start, Stop, Operate, Restart |
| T0859 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access | Password, Authenticate |
| T0879 | Modify Program (impact) | Persistence, Execution | DeleteBlock, CopyRamToRom, FirmwareUpdate, DeleteFile, ColdRestart |
| T0881 | Service System Information Discovery | Discovery | Read operations (added for ICS-aware discovery) |
| T0885 | Persistent Component Location | Persistence | DownloadBlock, CopyRamToRom, FirmwareUpdate |
| T0894 | Modify Program (impact) | Impact | Operate, DirectOperate |

## Enrichment API

To enrich any report dict with MITRE techniques:

```python
from ics_scanner.mitre_attack import enrich_report_with_attack

# report is a dict with 'results' list, each item having 'function_code' (S7)
# or 'function' (DNP3) field
enriched = enrich_report_with_attack(report, "s7comm")
# Each item now has a 'mitre_attack' list of technique dicts
```

## References

- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [IEEE 1815-2012 (DNP3)](https://standards.ieee.org/ieee/1815/5897/)
- [Siemens S7Comm spec](https://support.industry.siemens.com/cs/document/22109851)
