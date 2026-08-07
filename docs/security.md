# Security

IndustrialScanner is a security tool. This page describes its security
model, what it does and does not do, and how to use it safely.

## Read-only by design

The tool **never issues write or control operations**:

- **Modbus scanner**: only function codes 0x01–0x04 (read coils, discrete
  inputs, holding registers, input registers). Write codes 0x05, 0x06,
  0x0F, 0x10 are NOT issued.
- **S7Comm analyzer**: passive PCAP analysis only. No S7 traffic is sent.
- **DNP3 analyzer**: passive PCAP analysis only. No DNP3 traffic is sent.

## Target safety policy

The CLI enforces a target safety policy:

- **RFC1918 + loopback + link-local**: always allowed (10.0.0.0/8,
  172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16)
- **Public IPs**: refused by default. Pass `--allow-public` only after
  written authorization from the asset owner.
- **CIDR size limit**: /24 maximum (256 hosts) by default. Override with
  `max_hosts=` parameter if needed.

This prevents accidental wide-area scanning of legacy PLCs.

## HTML/JSON output safety

All reports use HTML escaping to prevent XSS:

- `modbus_scanner` and `s7_comm_analyzer`: Jinja2 with `autoescape=True`
- `dnp3_monitor`: `markupsafe.escape()` on every untrusted field
- `build_*.py` index builders: `html.escape()` on every untrusted field

This prevents a malicious PCAP from injecting JavaScript into reports
that an auditor opens in a browser.

## No telemetry, no outbound calls

IndustrialScanner runs entirely offline. It does not:

- Phone home
- Send usage statistics
- Download updates
- Connect to any external service

All processing is local. The only network connections are the ones you
initiate via the Modbus scanner.

## Reporting vulnerabilities

See [SECURITY.md](https://github.com/frangelbarrera/IndustrialScanner/blob/main/SECURITY.md)
for the vulnerability reporting process, Safe Harbor, and supported versions.

## Known limitations

- The S7Comm parser does not decode S7Comm-Plus (encrypted firmware ≥ V3.0)
- The DNP3 parser does not validate DNP3 SA v5 challenge-responses
- The Modbus scanner does not implement Modbus/TCP TLS (RFC 9441) yet
  (roadmap: Q2 2026)
