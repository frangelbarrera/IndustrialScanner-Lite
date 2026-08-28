# Compliance References & Gap Analysis

IndustrialScanner is a research and educational tool for passive ICS protocol
analysis. It is **not** compliance-certified and does not replace a formal
audit. This page maps where its capabilities align with common OT security
standards — and, just as importantly, where the gaps are — so that anyone
evaluating the tool knows exactly what it does and does not provide.

## Positioning summary

| Standard | Relationship | What the tool provides |
|---|---|---|
| **MITRE ATT&CK for ICS** | Direct mapping | Suspect protocol functions are enriched with ATT&CK for ICS techniques. The catalog is validated against the official STIX bundle in CI (`tests/test_mitre_attack_ground_truth.py`). |
| **NIST SP 800-82 Rev. 3** | Partial support (detection aid) | Passive PCAP analysis of Modbus/TCP, S7Comm and DNP3 can feed the network-monitoring evidence expected for OT security programs. It is a point tool, not a monitoring platform. |
| **IEC 62443** | Reference only | Read-only design and a target safety policy are aligned with the spirit of zone/conduit segmentation (IEC 62443-3-3 SR 5.x network monitoring), but the tool implements no 62443 requirements and performs no certification testing. |
| **NERC CIP** | Reference only | Report outputs (JSON/HTML, per-PCAP evidence) can contribute to an audit evidence portfolio (e.g. CIP-010 configuration monitoring), but the tool itself satisfies no CIP requirement. |
| **ISO/IEC 27019** | Reference only | Same as above: outputs may inform energy-utility security reviews; the tool makes no certification claim. |

## Known gaps

Honest limitations of the current implementation:

- **Passive scope only for S7Comm/DNP3.** The Modbus scanner is active but
  strictly read-only (function codes `0x01`–`0x04`). There are no write or
  control primitives for any protocol.
- **No continuous monitoring.** Analysis is batch-oriented (per PCAP file);
  there is no live capture, streaming detection, or alerting pipeline.
- **No asset inventory or profiling.** The tool classifies protocol functions,
  not devices; it does not build a passive asset baseline.
- **Protocol coverage is deliberately narrow.** S7Comm (classic), Modbus/TCP
  and DNP3 only. No S7Comm-Plus (`0x72`), PROFINET, EtherNet/IP or IEC 61850.
- **Target safety policy covers the CLI entry point.** The service layer and
  CLI filter public targets; scripts that import the Modbus scanner directly
  bypass that filter and are the operator's responsibility.
- **Reports are evidence, not attestations.** Generated JSON/HTML reports
  document what was observed in the analyzed captures and carry no compliance
  status.

## Using the tool in an audit context

The intended role is narrow and concrete: produce repeatable, structured
evidence of which ICS protocol operations appear in a capture, with MITRE
ATT&CK for ICS attribution for suspect functions. Feed those outputs into
your audit workflow; do not treat running the tool as fulfilling any control
by itself.
