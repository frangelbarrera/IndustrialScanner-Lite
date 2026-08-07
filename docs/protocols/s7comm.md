# Siemens S7Comm

S7Comm is the proprietary protocol used by Siemens S7-300, S7-400, S7-1200,
and S7-1500 PLCs. It runs over TCP/102 and is layered:

```
[TPKT header 4B][COTP header 3-17B][S7 header 10B][Parameter][Data]
```

- **TPKT** (RFC 1006): wraps ISO transport over TCP
- **COTP** (ISO 8073): ISO transport class 0
- **S7**: Siemens application layer

## What IndustrialScanner does

The S7Comm analyzer:

1. Reads PCAP/PCAPNG files
2. Filters TCP traffic on port 102
3. Unwraps TPKT/COTP framing
4. Parses the S7 header (byte 0 = 0x32 magic, byte 1 = ROSCTR)
5. Parses the parameter block (function code at offset 10)
6. Classifies each packet by function code
7. Flags suspect functions (WriteVar, Start, Stop, DownloadBlock,
   CopyRamToRom, FirmwareUpdate, Password)
8. Enriches with MITRE ATT&CK for ICS techniques

## Function codes detected

| Code | Name | Suspect | Description |
|---|---|---|---|
| 0x04 | ReadVar | No | Read variables |
| 0x05 | WriteVar | Yes | Write variables |
| 0x28 | Start | Yes | Start CPU |
| 0x29 | Stop | Yes | Stop CPU |
| 0xF0 | SetupComm | No | Setup communication handshake |
| 0x3A | DownloadBlock | Yes | Download block to PLC |
| 0x3B | UploadBlock | No | Upload block from PLC |
| 0x3C | DeleteBlock | Yes | Delete block |
| 0x44 | FirmwareUpdate | Yes | Update firmware |
| 0x45 | Password | Yes | Authentication |
| 0x46 | ReadDiag | No | Read diagnostic data |
| 0x4E | CopyRamToRom | Yes | Persist RAM to ROM |

## Usage

```bash
# Analyze a single PCAP
industrial-scanner s7 --pcap capture.pcapng

# Batch process all PCAPs in pcaps/s7/
python -m s7_comm_analyzer.s7_analyze
```

## Output

- **JSON report** in `reports/s7_batch/<basename>.json`
- **HTML report** in `reports/s7_batch/<basename>.html`

Each packet entry includes:

- src, dst, function_code, length, hints (ASCII strings found in payload)
- rosctr (Job, Ack, AckData, Userdata)
- pdu_ref (PDU reference number)
- mitre_attack (list of MITRE techniques)

## Limitations

- **S7Comm-Plus** (firmware ≥ V3.0 on S7-1200/1500) uses encrypted X3.1324
  framing and is **not** supported. The analyzer will return `NonS7Payload`
  for these frames.
- The parser does not yet decode the **item structure** within the
  parameter block (variable addresses, data types). Only the function code
  is extracted.

## Security considerations

- S7Comm has **no authentication** by default (the 0x45 Password function
  is optional and rarely used)
- Anyone with network access to TCP/102 can issue Start/Stop/DownloadBlock
- For production, use **S7Comm-Plus** (encrypted) or restrict TCP/102
  access via firewall rules
