# PLC Guardian forensic report

## 1. Evidence

| Item | Value |
| --- | --- |
| Capture file | exp3_no_inline_baseline_2026-11-04.pcapng |
| SHA-256 | ddd963fb9ed68b5624bad2ed86a166ebd2edbb2d2e9aef8a8068039f0ce582ba |
| Size (bytes) | 120672 |
| Frames | 1203 |
| First packet (UTC) | 2026-11-05T01:53:06.022130Z |
| Last packet (UTC) | 2026-11-05T01:53:44.129101Z |
| Duration (s) | 38.107 |
| Timestamps | from capture file (clock of the capturing host) |
| Guardian config SHA-256 | 2ea5cd3dc9fc846a32262807c7da2895cdc0782d9d697853470cb334b954a496 |
| Authorized sources | 192.168.8.10 (HMI (Pro-face): read/write), 192.168.8.2 (HMI (team laptop running updated HMI project, seen in Test1 2026-10-21): read/write), 192.168.8.50 (Engineering laptop: read/write/config) |
| Evidence log | events.jsonl (chain head ddce8c2d106d7589...) |
| Report generated | 2026-11-05T01:54:54.842289Z on Dj_24_Laptop (Windows) |

## 2. Summary

- Modbus requests: **463** (ALLOW 460, ALERT 0, BLOCK-worthy 3); responses: 463; exception responses: 0
- Event types: NORMAL_READ x458, AUTHORIZED_CHANGE x2, UNAUTHORIZED_READ x2, UNAUTHORIZED_CHANGE x1
- **Unauthorized activity detected from: 192.168.8.99**

## 3. Hosts observed

| IP | MAC(s) | Identity | Modbus requests (by category) | First packet (UTC) |
| --- | --- | --- | --- | --- |
| 0.0.0.0 | cc:ba:bd:43:f2:ab | - | - | 2026-11-05T01:53:07.027237Z |
| 192.168.8.10 | 00:00:54:0b:c5:9a | HMI (Pro-face) | {'read': 458, 'write': 2} | 2026-11-05T01:53:06.127926Z |
| 192.168.8.11 | 00:80:f4:54:1d:67 | PLC | - | 2026-11-05T01:53:06.151659Z |
| 192.168.8.99 | 00:e0:4c:1d:3d:70 | UNKNOWN | {'read': 2, 'write': 1} | 2026-11-05T01:53:29.608939Z |

## 4. Findings

### 192.168.8.99 (NOT AUTHORIZED)

- MAC: 00:e0:4c:1d:3d:70
- Active: 2026-11-05T01:53:29.615442Z -> 2026-11-05T01:53:29.627440Z (frames 739-749)
- Requests: 3 ({'read': 2, 'write': 1}); rules fired: {'SRC_NOT_ALLOWLISTED': 3, 'VALUE_OUT_OF_RANGE': 1}
- Attempted changes: 1; **accepted by the PLC: 1**
  - frame 746 2026-11-05T01:53:29.626378Z: FC5 Write Single Coil addr=4 qty=1 values=[1] -> ACCEPTED_BY_PLC

## 5. Timeline of notable events

Authorized reads (normal polling) are omitted; first contact by each host on the Modbus port is included.

| Time (UTC) | Frame | Source | Action | Event | Verdict | PLC outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-05T01:53:06.150268Z | 4 | 192.168.8.10 (HMI (Pro-face)) | FC1 Read Coils addr=2 qty=5 | NORMAL_READ [first contact] | ALLOW | OK |
| 2026-11-05T01:53:09.422649Z | 109 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-05T01:53:29.615442Z | 739 | 192.168.8.99 (NOT AUTHORIZED) | FC1 Read Coils addr=4 qty=1 | UNAUTHORIZED_READ [first contact] | BLOCK (SRC_NOT_ALLOWLISTED) | OK |
| 2026-11-05T01:53:29.626378Z | 746 | 192.168.8.99 (NOT AUTHORIZED) | FC5 Write Single Coil addr=4 qty=1 values=[1] | UNAUTHORIZED_CHANGE | BLOCK (SRC_NOT_ALLOWLISTED, VALUE_OUT_OF_RANGE) | ACCEPTED_BY_PLC |
| 2026-11-05T01:53:29.627440Z | 749 | 192.168.8.99 (NOT AUTHORIZED) | FC1 Read Coils addr=4 qty=1 | UNAUTHORIZED_READ | BLOCK (SRC_NOT_ALLOWLISTED) | OK |
| 2026-11-05T01:53:38.828286Z | 1037 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |

## 6. Authorized changes

- frame 109 2026-11-05T01:53:09.422649Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 1037 2026-11-05T01:53:38.828286Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[0] -> ACCEPTED_BY_PLC

## 7. Method and limitations

- Each TCP flow to/from the Modbus port was reassembled by sequence number; Ethernet padding was excluded using the IP total length; retransmissions were skipped.
- Authorization is decided from the source IP (and MAC, where configured) against `config.json`; an attacker on the same segment who spoofs both IP and MAC of an authorized host would not be caught by the allowlist rule alone (the MAC-mismatch and multiple-MAC checks catch the common case).
- PLC outcome is taken from the PLC's response with the same Modbus transaction ID on the same TCP connection. 'ACCEPTED_BY_PLC' means the PLC acknowledged the write; it does not prove the physical process changed.
- Timestamps come from the capture file and are only as accurate as the capturing host's clock.
