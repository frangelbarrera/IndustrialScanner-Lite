"""
MITRE ATT&CK for ICS mapping.

Maps protocol-level suspect functions to MITRE ATT&CK for ICS techniques
(https://attack.mitre.org/matrices/ics/). This produces structured threat
intelligence that SOCs and analysts can use to enrich findings.

The mapping is intentionally conservative: only suspect functions that
represent meaningful adversary techniques are mapped. Read operations are
mapped to T0801 (Monitor Process State) where they enable reconnaissance.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ATTACKTechnique:
    """A MITRE ATT&CK for ICS technique."""
    technique_id: str
    name: str
    tactic: str
    description: str
    url: str


# MITRE ATT&CK for ICS technique mapping.
# Source: https://attack.mitre.org/techniques/ics/
# Last reviewed: 2025-01
TECHNIQUE_CATALOG: dict[str, ATTACKTechnique] = {
    "T0801": ATTACKTechnique(
        technique_id="T0801",
        name="Monitor Process State",
        tactic="Discovery",
        description="Adversaries may monitor process state to understand the"
                   " current operational state of the ICS.",
        url="https://attack.mitre.org/techniques/T0801/",
    ),
    "T0807": ATTACKTechnique(
        technique_id="T0807",
        name="Command-Line Interface",
        tactic="Execution",
        description="Adversaries may use command-line interfaces to interact"
                   " with systems and execute commands.",
        url="https://attack.mitre.org/techniques/T0807/",
    ),
    "T0817": ATTACKTechnique(
        technique_id="T0817",
        name="Drive-by Compromise",
        tactic="Initial Access",
        description="Adversaries may compromise victims through drive-by"
                   " downloads of malicious code.",
        url="https://attack.mitre.org/techniques/T0817/",
    ),
    "T0853": ATTACKTechnique(
        technique_id="T0853",
        name="Panel Shell",
        tactic="Execution",
        description="Adversaries may use panel shells to interact with the"
                   " HMI/panel.",
        url="https://attack.mitre.org/techniques/T0853/",
    ),
    "T0859": ATTACKTechnique(
        technique_id="T0859",
        name="Valid Accounts",
        tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        description="Adversaries may use valid accounts to gain access to"
                   " systems and execute operations.",
        url="https://attack.mitre.org/techniques/T0859/",
    ),
    "T0866": ATTACKTechnique(
        technique_id="T0866",
        name="Exploitation of Remote Services",
        tactic="Lateral Movement",
        description="Adversaries may exploit remote services to obtain access"
                   " to systems.",
        url="https://attack.mitre.org/techniques/T0866/",
    ),
    "T0872": ATTACKTechnique(
        technique_id="T0872",
        name="Native API",
        tactic="Execution",
        description="Adversaries may directly interact with the native OS API"
                   " to execute procedures or modify files.",
        url="https://attack.mitre.org/techniques/T0872/",
    ),
    "T0885": ATTACKTechnique(
        technique_id="T0885",
        name="Persistent Component Location",
        tactic="Persistence",
        description="Adversaries may persist their components in specific"
                   " locations to maintain access.",
        url="https://attack.mitre.org/techniques/T0885/",
    ),
    "T0888": ATTACKTechnique(
        technique_id="T0888",
        name="Remote Services",
        tactic="Lateral Movement",
        description="Adversaries may use remote services to access and control"
                   " systems.",
        url="https://attack.mitre.org/techniques/T0888/",
    ),
    "T0890": ATTACKTechnique(
        technique_id="T0890",
        name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="Adversaries may exploit software vulnerabilities to"
                   " escalate privileges.",
        url="https://attack.mitre.org/techniques/T0890/",
    ),
    "T0802": ATTACKTechnique(
        technique_id="T0802",
        name="Automated Discovery",
        tactic="Discovery",
        description="Adversaries may use automated discovery to gather"
                   " information about the system or network.",
        url="https://attack.mitre.org/techniques/T0802/",
    ),
    "T0808": ATTACKTechnique(
        technique_id="T0808",
        name="Control System Identification",
        tactic="Discovery",
        description="Adversaries may attempt to identify the control system"
                   " and its components.",
        url="https://attack.mitre.org/techniques/T0808/",
    ),
    "T0848": ATTACKTechnique(
        technique_id="T0848",
        name="Modify Program",
        tactic="Execution, Persistence",
        description="Adversaries may modify programs to achieve malicious"
                   " objectives by altering the original control logic.",
        url="https://attack.mitre.org/techniques/T0848/",
    ),
    "T0858": ATTACKTechnique(
        technique_id="T0858",
        name="Change Operating Mode",
        tactic="Execution, Impact",
        description="Adversaries may change the operating mode of a control"
                   " device (PLC, RTU, etc.) to enable further actions or"
                   " cause impact.",
        url="https://attack.mitre.org/techniques/T0858/",
    ),
    "T0879": ATTACKTechnique(
        technique_id="T0879",
        name="Modify Program",
        tactic="Persistence, Execution",
        description="Adversaries may modify control logic to disrupt or damage"
                   " operations.",
        url="https://attack.mitre.org/techniques/T0879/",
    ),
    "T0881": ATTACKTechnique(
        technique_id="T0881",
        name="Service System Information",
        tactic="Discovery",
        description="Adversaries may gather information about service systems"
                   " and their components.",
        url="https://attack.mitre.org/techniques/T0881/",
    ),
    "T0887": ATTACKTechnique(
        technique_id="T0887",
        name="Modify Program",
        tactic="Impact",
        description="Adversaries may modify control logic to cause physical"
                   " impact.",
        url="https://attack.mitre.org/techniques/T0887/",
    ),
    "T0894": ATTACKTechnique(
        technique_id="T0894",
        name="Modify Program",
        tactic="Impact",
        description="Adversaries may modify the control logic to cause"
                   " physical impact.",
        url="https://attack.mitre.org/techniques/T0894/",
    ),
}


# Mapping of (protocol, function_name) -> list of MITRE technique IDs.
# These are the analyst-vetted correlations between protocol-level functions
# and MITRE ATT&CK for ICS techniques.
PROTOCOL_FUNCTION_MAPPING: dict[str, dict[str, list[str]]] = {
    "modbus": {
        # Modbus read operations
        "ReadCoils": ["T0801", "T0802"],
        "ReadDiscreteInputs": ["T0801", "T0802"],
        "ReadHoldingRegisters": ["T0801", "T0802"],
        "ReadInputRegisters": ["T0801", "T0802"],
        # Modbus write/control operations (not issued by this tool, but
        # detected in passive PCAP analysis)
        "WriteSingleCoil": ["T0858", "T0858"],
        "WriteMultipleCoils": ["T0858"],
        "WriteSingleRegister": ["T0858"],
        "WriteMultipleRegisters": ["T0858"],
        "ForceListenOnly": ["T0858"],
        "RestartCommunications": ["T0858"],
        "Diagnostics": ["T0808"],
    },
    "s7comm": {
        "ReadVar": ["T0801", "T0802", "T0808"],
        "WriteVar": ["T0848", "T0858"],
        "Start": ["T0858"],
        "Stop": ["T0858"],
        "SetupComm": ["T0808"],
        "DownloadBlock": ["T0848", "T0885", "T0879"],
        "UploadBlock": ["T0801"],
        "DeleteBlock": ["T0879"],
        "CopyRamToRom": ["T0885", "T0879"],
        "FirmwareUpdate": ["T0858", "T0885", "T0879"],
        "Password": ["T0859"],
        "ReadDiag": ["T0801", "T0808"],
    },
    "dnp3": {
        "Read": ["T0801", "T0802", "T0808"],
        "Write": ["T0848", "T0858"],
        "Select": ["T0858"],
        "Operate": ["T0858", "T0894"],
        "DirectOperate": ["T0858", "T0894"],
        "DirectOperateNoAck": ["T0858", "T0894"],
        "ImmediateFreeze": ["T0801"],
        "FreezeClear": ["T0858"],
        "ColdRestart": ["T0858", "T0879"],
        "WarmRestart": ["T0858"],
        "StopApplication": ["T0858"],
        "StartApplication": ["T0858"],
        "DeleteFile": ["T0879"],
        "EnableUnsolicited": ["T0858"],
        "AssignClass": ["T0858"],
        "Authenticate": ["T0859"],
        "OpenFile": ["T0801"],
        "CloseFile": ["T0801"],
    },
}


def map_function_to_techniques(protocol: str, function_name: str) -> list[ATTACKTechnique]:
    """Map a (protocol, function_name) pair to MITRE ATT&CK for ICS techniques.

    Returns an empty list if no mapping is defined (e.g., for benign read
    operations or unknown functions).
    """
    proto_map = PROTOCOL_FUNCTION_MAPPING.get(protocol.lower(), {})
    technique_ids = proto_map.get(function_name, [])
    return [TECHNIQUE_CATALOG[tid] for tid in technique_ids if tid in TECHNIQUE_CATALOG]


def enrich_report_with_attack(report: dict, protocol: str) -> dict:
    """Add a `mitre_attack` field to each parsed packet in a report's results.

    The report is expected to have a `results` list where each item has a
    `function_code` (S7Comm) or `function` (DNP3) field. After enrichment,
    each item will also have a `mitre_attack` list with technique dictionaries.
    """
    func_field = "function_code" if "function_code" in (report.get("results") or [{}])[0] else "function"
    for item in report.get("results", []):
        func_name = item.get(func_field, "")
        techniques = map_function_to_techniques(protocol, func_name)
        item["mitre_attack"] = [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "url": t.url,
            }
            for t in techniques
        ]
    return report
