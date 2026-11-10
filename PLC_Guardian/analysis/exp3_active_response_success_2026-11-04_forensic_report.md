# PLC Guardian forensic report

## 1. Evidence

| Item | Value |
| --- | --- |
| Capture file | exp3_active_response_success_2026-11-04.pcapng |
| SHA-256 | 4025110a9692c1ae06ccc73448251ca9d3b262351e66a12f0841b6bb8feea7c9 |
| Size (bytes) | 33056 |
| Frames | 327 |
| First packet (UTC) | 2026-11-05T02:51:57.345678Z |
| Last packet (UTC) | 2026-11-05T02:52:07.125003Z |
| Duration (s) | 9.779 |
| Timestamps | from capture file (clock of the capturing host) |
| Guardian config SHA-256 | 59657f80f3c7905bf848b3e510a7727cd2d8349b4078db3d395afdbad74944b9 |
| Authorized sources | 192.168.8.10 (HMI (Pro-face): read/write), 192.168.8.2 (HMI (team laptop running updated HMI project, seen in Test1 2026-10-21): read/write/config), 192.168.8.50 (Engineering laptop: read/write/config) |
| Evidence log | events.jsonl (chain head e6b35d88d2ba6e12...) |
| Report generated | 2026-11-05T02:53:49.461059Z on Dj_24_Laptop (Windows) |

## 2. Summary

- Modbus requests: **122** (ALLOW 119, ALERT 0, BLOCK-worthy 3); responses: 121; exception responses: 0
- Event types: NORMAL_READ x118, UNAUTHORIZED_READ x2, UNAUTHORIZED_CHANGE x1, AUTHORIZED_CHANGE x1
- **Unauthorized activity detected from: 192.168.8.99**
- retransmissions skipped: 1

## 3. Hosts observed

| IP | MAC(s) | Identity | Modbus requests (by category) | First packet (UTC) |
| --- | --- | --- | --- | --- |
| 0.0.0.0 | cc:ba:bd:43:f2:ab | - | - | 2026-11-05T02:51:59.758851Z |
| 192.168.8.10 | 00:00:54:0b:c5:9a | HMI (Pro-face) | {'read': 118} | 2026-11-05T02:51:57.345678Z |
| 192.168.8.11 | 00:80:f4:54:1d:67 | PLC | - | 2026-11-05T02:51:57.345683Z |
| 192.168.8.50 | 00:e0:4c:68:00:f4 | Engineering laptop | {'write': 1} | 2026-11-05T02:51:59.938894Z |
| 192.168.8.99 | 00:e0:4c:1d:3d:70 | UNKNOWN | {'read': 2, 'write': 1} | 2026-11-05T02:51:59.911024Z |

## 4. Findings

### 192.168.8.99 (NOT AUTHORIZED)

- MAC: 00:e0:4c:1d:3d:70
- Active: 2026-11-05T02:51:59.923350Z -> 2026-11-05T02:51:59.936794Z (frames 87-97)
- Requests: 3 ({'read': 2, 'write': 1}); rules fired: {'SRC_NOT_ALLOWLISTED': 3, 'VALUE_OUT_OF_RANGE': 1}
- Attempted changes: 1; **accepted by the PLC: 1**
  - frame 94 2026-11-05T02:51:59.935695Z: FC5 Write Single Coil addr=4 qty=1 values=[1] -> ACCEPTED_BY_PLC

## 5. Timeline of notable events

Authorized reads (normal polling) are omitted; first contact by each host on the Modbus port is included.

| Time (UTC) | Frame | Source | Action | Event | Verdict | PLC outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-05T02:51:57.345678Z | 1 | 192.168.8.10 (HMI (Pro-face)) | FC1 Read Coils addr=2 qty=6 | NORMAL_READ [first contact] | ALLOW | OK |
| 2026-11-05T02:51:59.923350Z | 87 | 192.168.8.99 (NOT AUTHORIZED) | FC1 Read Coils addr=4 qty=1 | UNAUTHORIZED_READ [first contact] | BLOCK (SRC_NOT_ALLOWLISTED) | OK |
| 2026-11-05T02:51:59.935695Z | 94 | 192.168.8.99 (NOT AUTHORIZED) | FC5 Write Single Coil addr=4 qty=1 values=[1] | UNAUTHORIZED_CHANGE | BLOCK (SRC_NOT_ALLOWLISTED, VALUE_OUT_OF_RANGE) | ACCEPTED_BY_PLC |
| 2026-11-05T02:51:59.936794Z | 97 | 192.168.8.99 (NOT AUTHORIZED) | FC1 Read Coils addr=4 qty=1 | UNAUTHORIZED_READ | BLOCK (SRC_NOT_ALLOWLISTED) | OK |
| 2026-11-05T02:51:59.941350Z | 105 | 192.168.8.50 (Engineering laptop) | FC5 Write Single Coil addr=7 qty=1 values=[1] | AUTHORIZED_CHANGE [first contact] | ALLOW | ACCEPTED_BY_PLC |

## 6. Authorized changes

- frame 105 2026-11-05T02:51:59.941350Z 192.168.8.50 (Engineering laptop): FC5 Write Single Coil addr=7 qty=1 values=[1] -> ACCEPTED_BY_PLC

## 7. Method and limitations

- Each TCP flow to/from the Modbus port was reassembled by sequence number; Ethernet padding was excluded using the IP total length; retransmissions were skipped.
- Authorization is decided from the source IP (and MAC, where configured) against `config.json`; an attacker on the same segment who spoofs both IP and MAC of an authorized host would not be caught by the allowlist rule alone (the MAC-mismatch and multiple-MAC checks catch the common case).
- PLC outcome is taken from the PLC's response with the same Modbus transaction ID on the same TCP connection. 'ACCEPTED_BY_PLC' means the PLC acknowledged the write; it does not prove the physical process changed.
- Timestamps come from the capture file and are only as accurate as the capturing host's clock.
