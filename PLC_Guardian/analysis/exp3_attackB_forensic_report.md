# PLC Guardian forensic report

## 1. Evidence

| Item | Value |
| --- | --- |
| Capture file | e4.pcapng |
| SHA-256 | a575fc622e679f08d8a73bda0917ad2d51b68c10e98e370818451d3a33b13704 |
| Size (bytes) | 11988 |
| Frames | 114 |
| First packet (UTC) | 2026-10-22T02:02:39.009810Z |
| Last packet (UTC) | 2026-10-22T02:03:20.041760Z |
| Duration (s) | 41.032 |
| Timestamps | from capture file (clock of the capturing host) |
| Guardian config SHA-256 | cf46cbb3e1bcd21d4d0ca58ca340511cfed4239c86fb57fd73947a104dbce385 |
| Authorized sources | 192.168.8.10 (HMI (Pro-face): read/write), 192.168.8.2 (HMI (team laptop running updated HMI project, seen in Test1 2026-10-21): read/write), 192.168.8.50 (Engineering laptop: read/write/config) |
| Evidence log | events.jsonl (chain head 8d9cfd1283dcfe47...) |
| Report generated | 2026-10-22T02:04:40.427231Z on vm (Linux) |

## 2. Summary

- Modbus requests: **3** (ALLOW 0, ALERT 0, BLOCK-worthy 3); responses: 3; exception responses: 0
- Event types: UNAUTHORIZED_READ x2, UNAUTHORIZED_CHANGE x1
- **Unauthorized activity detected from: 192.168.8.99**

## 3. Hosts observed

| IP | MAC(s) | Identity | Modbus requests (by category) | First packet (UTC) |
| --- | --- | --- | --- | --- |
| 192.168.8.11 | 00:80:f4:54:1d:67 | PLC | - | 2026-10-22T02:02:56.947207Z |
| 192.168.8.99 | 00:e0:4c:1d:3d:70 | UNKNOWN | {'read': 2, 'write': 1} | 2026-10-22T02:02:56.946435Z |

## 4. Findings

### 192.168.8.99 (NOT AUTHORIZED)

- MAC: 00:e0:4c:1d:3d:70
- Active: 2026-10-22T02:02:56.964873Z -> 2026-10-22T02:02:56.970748Z (frames 48-52)
- Requests: 3 ({'read': 2, 'write': 1}); rules fired: {'SRC_NOT_ALLOWLISTED': 3, 'VALUE_OUT_OF_RANGE': 1}
- Attempted changes: 1; **accepted by the PLC: 1**
  - frame 50 2026-10-22T02:02:56.970747Z: FC5 Write Single Coil addr=4 qty=1 values=[1] -> ACCEPTED_BY_PLC

## 5. Timeline of notable events

Authorized reads (normal polling) are omitted; first contact by each host on the Modbus port is included.

| Time (UTC) | Frame | Source | Action | Event | Verdict | PLC outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-22T02:02:56.964873Z | 48 | 192.168.8.99 (NOT AUTHORIZED) | FC1 Read Coils addr=4 qty=1 | UNAUTHORIZED_READ [first contact] | BLOCK (SRC_NOT_ALLOWLISTED) | OK |
| 2026-10-22T02:02:56.970747Z | 50 | 192.168.8.99 (NOT AUTHORIZED) | FC5 Write Single Coil addr=4 qty=1 values=[1] | UNAUTHORIZED_CHANGE | BLOCK (SRC_NOT_ALLOWLISTED, VALUE_OUT_OF_RANGE) | ACCEPTED_BY_PLC |
| 2026-10-22T02:02:56.970748Z | 52 | 192.168.8.99 (NOT AUTHORIZED) | FC1 Read Coils addr=4 qty=1 | UNAUTHORIZED_READ | BLOCK (SRC_NOT_ALLOWLISTED) | OK |

## 6. Authorized changes

None.


## 7. Method and limitations

- Each TCP flow to/from the Modbus port was reassembled by sequence number; Ethernet padding was excluded using the IP total length; retransmissions were skipped.
- Authorization is decided from the source IP (and MAC, where configured) against `config.json`; an attacker on the same segment who spoofs both IP and MAC of an authorized host would not be caught by the allowlist rule alone (the MAC-mismatch and multiple-MAC checks catch the common case).
- PLC outcome is taken from the PLC's response with the same Modbus transaction ID on the same TCP connection. 'ACCEPTED_BY_PLC' means the PLC acknowledged the write; it does not prove the physical process changed.
- Timestamps come from the capture file and are only as accurate as the capturing host's clock.
