# Security Policy — IndustrialScanner

> **Repository status:** This repository is being **archived** (read-only). It
> remains available for educational reference, but no active development or
> security fixes are planned. See *Supported Versions* below.

IndustrialScanner is a Python toolkit for **passive analysis of ICS/OT
traffic** (Siemens S7Comm over TCP/102, DNP3 over TCP-UDP/20000) and
**read-only active probing** of Modbus/TCP devices (port 502). It is designed
for auditors, researchers, and educators working on industrial control systems
security, and **must never be deployed against production OT environments**
without explicit written authorization from the asset owner.

---

## Supported Versions

| Version | Supported          | Notes                                                |
|---------|--------------------|------------------------------------------------------|
| `main`  | :x: Archived       | No new fixes will be released upstream.              |
| forks   | Community-driven   | The maintainer does not track downstream forks.      |

Because the project is archived, vulnerability reports will be acknowledged
and documented, but **patches will not be issued upstream**. Researchers who
need a fixed version are encouraged to maintain a private fork.

---

## Reporting a Vulnerability

Please report security issues **privately** before any public disclosure:

- **Email:** `frangelrcbarrera@gmail.com`
- **Subject prefix:** `[SECURITY] IndustrialScanner — <short summary>`
- **PGP:** Not available at this time. If the issue is sensitive, send a
  short summary first and request an encrypted channel.

Include in the report:

1. Affected file(s) and line numbers (e.g., `s7_comm_analyzer/parsers.py:42`).
2. A minimal reproduction (PoC) or PCAP snippet if applicable.
3. Impact assessment and the affected protocol(s): Modbus, S7Comm, DNP3.
4. Your suggested mitigation, if any.
5. Whether you intend to publish the finding, and your preferred timeline.

**Do not open public GitHub issues for security reports.**

---

## Response Timeline

| Step                              | Target                |
|-----------------------------------|-----------------------|
| Acknowledgement of receipt        | ≤ 5 business days     |
| Initial triage & severity rating  | ≤ 10 business days    |
| Coordinated disclosure discussion | ≤ 30 calendar days    |
| Public advisory (if accepted)     | Mutually agreed date  |

The maintainer operates this project on a personal, part-time basis. The
above targets are best-effort and may slip; researchers will be kept
informed if delays occur.

---

## Scope

### In scope

- The Python source tree under `modbus_scanner/`, `s7_comm_analyzer/`,
  `dnp3_monitor/`, plus the top-level `cli.py`, `build_*_index.py`, and
  `run_dnp3_all.py` scripts.
- The Jinja2 HTML templates under `reports/templates/`.
- Parsing of untrusted PCAP/PCAPNG files via `scapy.rdpcap`.
- HTML/JSON report generation from PCAP-derived or Modbus-derived data.

### Out of scope

- The committed sample PCAPs under `pcaps/` (public ICS training captures,
  not part of the tool's runtime).
- `ModbusPal.jar`, an unrelated third-party Modbus emulator bundled for
  convenience — report issues to its upstream project.
- Vulnerabilities in dependencies (`pymodbus`, `scapy`, `Jinja2`) — please
  report them to their respective maintainers via their CVE/CSAF channels.
- Self-XSS requiring the attacker to already control the auditor's machine.
- The committed `.pyc` files in `__pycache__/` (build artifacts).

---

## Safe Harbor

Good-faith security research on **systems you own or are explicitly
authorized to test** is welcomed. The maintainer will not pursue civil or
criminal action against researchers who:

- Respect the in-scope/out-of-scope boundaries above.
- Avoid disruption to live ICS/OT environments, including production PLCs,
  RTUs, HMIs, or SCADA hosts.
- Do not access, exfiltrate, or destroy data that does not belong to them.
- Provide reasonable time for acknowledgement before public disclosure.
- Refrain from leveraging findings for extortion, ransom, or competitive gain.

Researchers who wish to validate findings against ICS protocols are strongly
encouraged to use isolated lab setups such as ModbusPal, snap7, OpenPLC, or
the sample PCAPs bundled with this repository.

---

## Legal Framework

This policy is informed by widely recognized international instruments and
national computer-misuse statutes. Researchers are responsible for
understanding and complying with the laws of their jurisdiction.

- **Council of Europe Convention on Cybercrime (Budapest Convention, 2001)**
  — Articles 2, 3, and 5 on illegal access, system interference, and the
  interference with data; Article 15 on safeguards for legitimate research.
- **United States — Computer Fraud and Abuse Act (18 U.S.C. § 1030)**,
  particularly the research and good-faith limitations recognized in
  recent DOJ guidelines.
- **United Kingdom — Computer Misuse Act 1990**, sections 1 (unauthorized
  access) and 3 (unauthorized acts impairing operation).
- **European Union — Directive 2013/40/EU** on attacks against information
  systems, in particular Article 4 (illegal system interference) and the
  recitals acknowledging proportionate treatment of research.

Nothing in this policy overrides statutory obligations; it only expresses the
maintainer's intent **not to refer for prosecution** reports that comply
with this Safe Harbor.

---

## Known Security Considerations

The repository is a **research prototype**, not a production tool. Honest
disclosure of its current limitations:

- **Heuristic parsers.** S7Comm and DNP3 protocol classifiers rely on
  ASCII substring matching and approximate byte offsets rather than strict
  protocol decoding. They are **not suitable** as the sole basis for
  compliance or incident-response decisions and may produce both false
  positives and false negatives.
- **HTML report generation.** JSON and HTML reports are produced without
  strict output escaping. Reports should be opened in a sandboxed browser
  and treated as untrusted if generated from PCAPs of unknown provenance.
- **Active Modbus probing.** The Modbus scanner is read-only by design
  (`read_coils`, `read_discrete_inputs`, `read_holding_registers`,
  `read_input_registers`). It does not issue write or control commands.
  Even so, scanning live PLCs carries operational risk; only scan devices
  you own or are explicitly authorized to test, and avoid wide CIDR sweeps
  against legacy equipment.
- **Repo hygiene.** Historical commits include build artifacts
  (`__pycache__/*.pyc`), a bundled third-party JAR (`ModbusPal.jar`), and
  sample PCAP files. None of these affect runtime security of the tool,
  but they inflate the clone footprint and may include IPs from lab
  networks.
- **No automated CI, tests, or dependency scanning.** There is no
  continuous integration pipeline; downstream users should pin and audit
  dependencies (`pymodbus`, `scapy`, `Jinja2`) themselves.
- **Prototype CLI integration.** The unified `cli.py` does not cleanly map
  to every analyzer's `main()` signature. Use the per-module entry points
  (`python -m modbus_scanner.modbus_scan`,
  `python -m s7_comm_analyzer.s7_analyze`,
  `python -m dnp3_monitor.dnp3_analyze`) for reliable behavior.

---

## Contact

- **Maintainer:** Frangel Raúl Crespo Barrera
- **Email:** `frangelrcbarrera@gmail.com`
- **GitHub:** [`frangelbarrera/IndustrialScanner`](https://github.com/frangelbarrera/IndustrialScanner)

For non-security questions, please open a regular GitHub issue while the
repository is still interactive. After archiving, the issue tracker will be
disabled and email will remain the only channel.

---

*This policy is versioned with the repository. Last update coincides with the
final commit prior to archival.*
