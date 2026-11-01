# PLC Guardian forensic report

## 1. Evidence

| Item | Value |
| --- | --- |
| Capture file | modbus_capture_practice.pcapng |
| SHA-256 | ad9cc550da93da0d702651a6b0d3a20f7ddb55a2a39cb5858238e4fd4786b630 |
| Size (bytes) | 1220 |
| Frames | 8 |
| First packet (UTC) | 2026-10-13T01:06:00.605668Z |
| Last packet (UTC) | 2026-10-13T01:06:00.627295Z |
| Duration (s) | 0.022 |
| Timestamps | from capture file (clock of the capturing host) |
| Guardian config SHA-256 | c765466d28276d6911d5156158fdeba9c41ba6a1d2bb6f32dfb8812ae76d3f7b |
| Authorized sources | 192.168.8.10 (HMI (Pro-face): read/write), 192.168.8.50 (Engineering laptop: read/write/config) |
| Evidence log | events.jsonl (chain head 98166a05d615d5ba...) |
| Report generated | 2026-10-21T18:04:20.303240Z on claude (Linux) |

## 2. Summary

- Modbus requests: **1** (ALLOW 1, ALERT 0, BLOCK-worthy 0); responses: 1; exception responses: 0
- Event types: NORMAL_READ x1
- No unauthorized Modbus activity detected.

## 3. Hosts observed

| IP | MAC(s) | Identity | Modbus requests (by category) | First packet (UTC) |
| --- | --- | --- | --- | --- |
| 192.168.8.11 | 00:80:f4:54:1d:67 | PLC | - | 2026-10-13T01:06:00.606664Z |
| 192.168.8.50 | a0:ce:c8:62:e9:e1 | Engineering laptop | {'read': 1} | 2026-10-13T01:06:00.606766Z |

## 4. Findings

No unauthorized sources.

## 5. Timeline of notable events

Authorized reads (normal polling) are omitted; first contact by each host on the Modbus port is included.

| Time (UTC) | Frame | Source | Action | Event | Verdict | PLC outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-13T01:06:00.622849Z | 4 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=10 | NORMAL_READ [first contact] | ALLOW | OK |

## 6. Authorized changes

None.


## 7. Method and limitations

- Each TCP flow to/from the Modbus port was reassembled by sequence number; Ethernet padding was excluded using the IP total length; retransmissions were skipped.
- Authorization is decided from the source IP (and MAC, where configured) against `config.json`; an attacker on the same segment who spoofs both IP and MAC of an authorized host would not be caught by the allowlist rule alone (the MAC-mismatch and multiple-MAC checks catch the common case).
- PLC outcome is taken from the PLC's response with the same Modbus transaction ID on the same TCP connection. 'ACCEPTED_BY_PLC' means the PLC acknowledged the write; it does not prove the physical process changed.
- Timestamps come from the capture file and are only as accurate as the capturing host's clock.
