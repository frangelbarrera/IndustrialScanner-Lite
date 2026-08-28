"""
MITRE ATT&CK for ICS mapping.

Maps protocol-level suspect functions to MITRE ATT&CK for ICS techniques
(https://attack.mitre.org/matrices/ics/). This produces structured threat
intelligence that SOCs and analysts can use to enrich findings.

The technique catalog is kept in sync with the official MITRE ATT&CK for ICS
STIX bundle (validated by tests/test_mitre_attack_ground_truth.py against
tests/fixtures/attack_ics_official.json). The mapping is intentionally
conservative: only functions that represent meaningful adversary techniques
are mapped.
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


# MITRE ATT&CK for ICS technique catalog.
# Source: official MITRE ATT&CK for ICS STIX bundle (ics-attack.json).
TECHNIQUE_CATALOG: dict[str, ATTACKTechnique] = {
    "T0801": ATTACKTechnique(
        technique_id="T0801",
        name="Monitor Process State",
        tactic="Collection",
        description="Adversaries may gather information about the physical process state.",
        url="https://attack.mitre.org/techniques/T0801/",
    ),
    "T0802": ATTACKTechnique(
        technique_id="T0802",
        name="Automated Collection",
        tactic="Collection",
        description="Adversaries may automate collection of industrial environment "
        "information using tools or scripts.",
        url="https://attack.mitre.org/techniques/T0802/",
    ),
    "T0816": ATTACKTechnique(
        technique_id="T0816",
        name="Device Restart/Shutdown",
        tactic="Inhibit Response Function",
        description="Adversaries may forcibly restart or shutdown a device in an ICS "
        "environment to disrupt and potentially negatively impact "
        "physical processes.",
        url="https://attack.mitre.org/techniques/T0816/",
    ),
    "T0821": ATTACKTechnique(
        technique_id="T0821",
        name="Modify Controller Tasking",
        tactic="Execution",
        description="Adversaries may modify the tasking of a controller to allow for "
        "the execution of their own programs.",
        url="https://attack.mitre.org/techniques/T0821/",
    ),
    "T0831": ATTACKTechnique(
        technique_id="T0831",
        name="Manipulation of Control",
        tactic="Impact",
        description="Adversaries may manipulate physical process control within the "
        "industrial environment.",
        url="https://attack.mitre.org/techniques/T0831/",
    ),
    "T0836": ATTACKTechnique(
        technique_id="T0836",
        name="Modify Parameter",
        tactic="Impair Process Control",
        description="Adversaries may modify parameters used to instruct industrial "
        "control system devices.",
        url="https://attack.mitre.org/techniques/T0836/",
    ),
    "T0843": ATTACKTechnique(
        technique_id="T0843",
        name="Program Download",
        tactic="Lateral Movement",
        description="Adversaries may perform a program download to transfer a user "
        "program to a controller.",
        url="https://attack.mitre.org/techniques/T0843/",
    ),
    "T0845": ATTACKTechnique(
        technique_id="T0845",
        name="Program Upload",
        tactic="Collection",
        description="Adversaries may attempt to upload a program from a PLC to gather "
        "information about an industrial process.",
        url="https://attack.mitre.org/techniques/T0845/",
    ),
    "T0858": ATTACKTechnique(
        technique_id="T0858",
        name="Change Operating Mode",
        tactic="Evasion, Execution",
        description="Adversaries may change the operating mode of a controller to "
        "gain additional access to engineering functions such as Program "
        "Download.",
        url="https://attack.mitre.org/techniques/T0858/",
    ),
    "T0859": ATTACKTechnique(
        technique_id="T0859",
        name="Valid Accounts",
        tactic="Lateral Movement, Persistence",
        description="Adversaries may steal the credentials of a specific user or "
        "service account using credential access techniques.",
        url="https://attack.mitre.org/techniques/T0859/",
    ),
    "T0868": ATTACKTechnique(
        technique_id="T0868",
        name="Detect Operating Mode",
        tactic="Collection",
        description="Adversaries may gather information about a PLCs or controllers "
        "current operating mode.",
        url="https://attack.mitre.org/techniques/T0868/",
    ),
    "T0888": ATTACKTechnique(
        technique_id="T0888",
        name="Remote System Information Discovery",
        tactic="Discovery",
        description="An adversary may attempt to get detailed information about "
        "remote systems and their peripherals, such as make/model, role, "
        "and configuration.",
        url="https://attack.mitre.org/techniques/T0888/",
    ),
    "T0889": ATTACKTechnique(
        technique_id="T0889",
        name="Modify Program",
        tactic="Persistence",
        description="Adversaries may modify or add a program on a controller to "
        "affect how it interacts with the physical process, peripheral "
        "devices and other hosts on the network.",
        url="https://attack.mitre.org/techniques/T0889/",
    ),
}


# Mapping of (protocol, function_name) -> list of MITRE technique IDs.
# Analyst-vetted correlations between protocol-level functions and MITRE
# ATT&CK for ICS techniques. Benign handshakes and data-freeze operations
# are intentionally unmapped.
PROTOCOL_FUNCTION_MAPPING: dict[str, dict[str, list[str]]] = {
    "modbus": {
        # Modbus read operations
        "ReadCoils": ["T0801", "T0802"],
        "ReadDiscreteInputs": ["T0801", "T0802"],
        "ReadHoldingRegisters": ["T0801", "T0802"],
        "ReadInputRegisters": ["T0801", "T0802"],
        # Modbus write/control operations (not issued by this tool, but
        # detected in passive PCAP analysis)
        "WriteSingleCoil": ["T0836"],
        "WriteMultipleCoils": ["T0836"],
        "WriteSingleRegister": ["T0836"],
        "WriteMultipleRegisters": ["T0836"],
        "ForceListenOnly": ["T0858"],
        "RestartCommunications": ["T0858"],
        "Diagnostics": ["T0888"],
    },
    "s7comm": {
        "ReadVar": ["T0801", "T0802"],
        "WriteVar": ["T0836"],
        "Start": ["T0858"],
        "Stop": ["T0858", "T0816"],
        "DownloadBlock": ["T0843", "T0889"],
        "UploadBlock": ["T0845"],
        "CopyRamToRom": ["T0889"],
        "Password": ["T0859"],
        "ReadSzl": ["T0868", "T0888"],
    },
    "dnp3": {
        "Read": ["T0801", "T0802"],
        "Write": ["T0836"],
        "Operate": ["T0821", "T0831"],
        "DirectOperate": ["T0821", "T0831"],
        "DirectOperateNoAck": ["T0821", "T0831"],
        "ImmediateFreeze": ["T0801"],
        "ColdRestart": ["T0816"],
        "WarmRestart": ["T0816"],
        "StopApplication": ["T0816"],
        "StartApplication": ["T0858"],
        "DeleteFile": ["T0889"],
        "EnableUnsolicited": ["T0858"],
        "DisableUnsolicited": ["T0858"],
        "AssignClass": ["T0858"],
        "Authenticate": ["T0859"],
        "OpenFile": ["T0801"],
        "CloseFile": ["T0801"],
        "DelayMeasure": ["T0801"],
        "RecordCurrentTime": ["T0801"],
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
    func_field = (
        "function_code" if "function_code" in (report.get("results") or [{}])[0] else "function"
    )
    for item in report.get("results") or []:
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
