# PLC Guardian forensic report

## 1. Evidence

| Item | Value |
| --- | --- |
| Capture file | mixed_pm3_synthetic.pcap |
| SHA-256 | 4c530d642b08cc38e162d29e68b63f64693f8b7afaa73a0d2c830ebe618d9b50 |
| Size (bytes) | 56834 |
| Frames | 632 |
| First packet (UTC) | 2026-10-15T01:09:41.967510Z |
| Last packet (UTC) | 2026-10-15T01:09:54.533099Z |
| Duration (s) | 12.566 |
| Timestamps | from capture file (clock of the capturing host) |
| Guardian config SHA-256 | 609b01c26c390ccc02465ec54df8b4f8eba9ada6fd1431f04f0ff4884bea5ce2 |
| Authorized sources | 192.168.8.10 (HMI (Pro-face): read/write), 192.168.8.50 (Engineering laptop: read/write/config) |
| Evidence log | events.jsonl (chain head f0225845d8a84104...) |
| Report generated | 2026-10-21T18:20:10.423648Z on vm (Linux) |

## 2. Summary

- Modbus requests: **158** (ALLOW 150, ALERT 2, BLOCK-worthy 6); responses: 158; exception responses: 0
- Event types: NORMAL_READ x150, AUTHORIZED_CHANGE x3, UNAUTHORIZED_CHANGE x3, SPOOFED_SOURCE x1, UNAUTHORIZED_CONFIG_CHANGE x1
- **Unauthorized activity detected from: 192.168.8.10, 192.168.8.99**

## 3. Hosts observed

| IP | MAC(s) | Identity | Modbus requests (by category) | First packet (UTC) |
| --- | --- | --- | --- | --- |
| 192.168.8.10 | 00:00:54:0b:c5:9a, 00:e0:4c:1d:3d:70 **(multiple MACs: possible spoofing / ARP poisoning)** | HMI (Pro-face) | {'read': 100, 'config': 50, 'write': 4} | 2026-10-15T01:09:41.967510Z |
| 192.168.8.11 | 00:80:f4:54:1d:67 | PLC | - | 2026-10-15T01:09:42.126327Z |
| 192.168.8.99 | 00:e0:4c:1d:3d:70 | UNKNOWN | {'write': 3, 'config': 1} | 2026-10-15T01:09:42.605023Z |

## 4. Findings

### 192.168.8.10 (HMI (Pro-face))

- MAC: 00:00:54:0b:c5:9a, 00:e0:4c:1d:3d:70
- Active: 2026-10-15T01:09:50.019510Z -> 2026-10-15T01:09:50.019510Z (frames 411-411)
- Requests: 1 ({'write': 1}); rules fired: {'MAC_MISMATCH': 1}
- Attempted changes: 1; **accepted by the PLC: 1**
  - frame 411 2026-10-15T01:09:50.019510Z: FC5 Write Single Coil addr=3 qty=1 values=[0] -> ACCEPTED_BY_PLC

### 192.168.8.99 (NOT AUTHORIZED)

- MAC: 00:e0:4c:1d:3d:70
- Active: 2026-10-15T01:09:48.019510Z -> 2026-10-15T01:09:52.019510Z (frames 305-513)
- Requests: 4 ({'write': 3, 'config': 1}); rules fired: {'SRC_NOT_ALLOWLISTED': 4, 'VALUE_OUT_OF_RANGE': 1, 'WRITE_TO_READ_ONLY_POINT': 1}
- Attempted changes: 4; **accepted by the PLC: 4**
  - frame 305 2026-10-15T01:09:48.019510Z: FC5 Write Single Coil addr=4 qty=1 values=[1] -> ACCEPTED_BY_PLC
  - frame 307 2026-10-15T01:09:48.071510Z: FC5 Write Single Coil addr=2 qty=1 values=[1] -> ACCEPTED_BY_PLC
  - frame 309 2026-10-15T01:09:48.123510Z: FC6 Write Single Register addr=0 qty=1 values=[0] -> ACCEPTED_BY_PLC
  - frame 513 2026-10-15T01:09:52.019510Z: FC90 Schneider FC 0x5A (engineering / programming) sub=0x41 (STOP_PLC?) -> ACCEPTED_BY_PLC

## 5. Timeline of notable events

Authorized reads (normal polling) are omitted; first contact by each host on the Modbus port is included.

| Time (UTC) | Frame | Source | Action | Event | Verdict | PLC outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-15T01:09:42.124721Z | 2 | 192.168.8.10 (HMI (Pro-face)) | FC1 Read Coils addr=2 qty=4 | NORMAL_READ [first contact] | ALLOW | OK |
| 2026-10-15T01:09:44.019510Z | 101 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[1] | AUTHORIZED_CHANGE | ALERT (BASELINE_DEVIATION) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:46.019510Z | 203 | 192.168.8.10 (HMI (Pro-face)) | FC5 Write Single Coil addr=4 qty=1 values=[1] | AUTHORIZED_CHANGE | ALERT (VALUE_OUT_OF_RANGE, BASELINE_DEVIATION) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:48.019510Z | 305 | 192.168.8.99 (NOT AUTHORIZED) | FC5 Write Single Coil addr=4 qty=1 values=[1] | UNAUTHORIZED_CHANGE [first contact] | BLOCK (SRC_NOT_ALLOWLISTED, VALUE_OUT_OF_RANGE) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:48.071510Z | 307 | 192.168.8.99 (NOT AUTHORIZED) | FC5 Write Single Coil addr=2 qty=1 values=[1] | UNAUTHORIZED_CHANGE | BLOCK (SRC_NOT_ALLOWLISTED) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:48.123510Z | 309 | 192.168.8.99 (NOT AUTHORIZED) | FC6 Write Single Register addr=0 qty=1 values=[0] | UNAUTHORIZED_CHANGE | BLOCK (SRC_NOT_ALLOWLISTED, WRITE_TO_READ_ONLY_POINT) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:50.019510Z | 411 | 192.168.8.10 (HMI (Pro-face)) | FC5 Write Single Coil addr=3 qty=1 values=[0] | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:52.019510Z | 513 | 192.168.8.99 (NOT AUTHORIZED) | FC90 Schneider FC 0x5A (engineering / programming) sub=0x41 (STOP_PLC?) | UNAUTHORIZED_CONFIG_CHANGE | BLOCK (SRC_NOT_ALLOWLISTED) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:53.019510Z | 567 | 192.168.8.10 (HMI (Pro-face)) | FC6 Write Single Register addr=0 qty=1 values=[0] | AUTHORIZED_CHANGE | BLOCK (WRITE_TO_READ_ONLY_POINT, BASELINE_DEVIATION) | ACCEPTED_BY_PLC |

## 6. Authorized changes

- frame 4 2026-10-15T01:09:42.144664Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 11 2026-10-15T01:09:42.394866Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 38 2026-10-15T01:09:42.645090Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 45 2026-10-15T01:09:42.895143Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 52 2026-10-15T01:09:43.144945Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 59 2026-10-15T01:09:43.394836Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 86 2026-10-15T01:09:43.644888Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 93 2026-10-15T01:09:43.894723Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 101 2026-10-15T01:09:44.019510Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[1] -> ACCEPTED_BY_PLC [BASELINE_DEVIATION]
- frame 106 2026-10-15T01:09:44.144882Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 113 2026-10-15T01:09:44.394823Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 140 2026-10-15T01:09:44.644951Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 147 2026-10-15T01:09:44.894801Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 154 2026-10-15T01:09:45.145054Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 161 2026-10-15T01:09:45.394908Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 188 2026-10-15T01:09:45.647349Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 195 2026-10-15T01:09:45.894813Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 203 2026-10-15T01:09:46.019510Z 192.168.8.10 (HMI (Pro-face)): FC5 Write Single Coil addr=4 qty=1 values=[1] -> ACCEPTED_BY_PLC [VALUE_OUT_OF_RANGE, BASELINE_DEVIATION]
- frame 208 2026-10-15T01:09:46.145941Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 215 2026-10-15T01:09:46.395240Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 242 2026-10-15T01:09:46.644899Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 249 2026-10-15T01:09:46.895029Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 256 2026-10-15T01:09:47.145268Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 263 2026-10-15T01:09:47.395034Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 290 2026-10-15T01:09:47.644862Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 297 2026-10-15T01:09:47.894846Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 314 2026-10-15T01:09:48.145417Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 321 2026-10-15T01:09:48.395077Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 348 2026-10-15T01:09:48.646149Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 355 2026-10-15T01:09:48.894966Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 362 2026-10-15T01:09:49.144989Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 369 2026-10-15T01:09:49.397143Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 396 2026-10-15T01:09:49.650042Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 403 2026-10-15T01:09:49.900043Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 416 2026-10-15T01:09:50.150403Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 423 2026-10-15T01:09:50.400302Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 450 2026-10-15T01:09:50.650013Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 457 2026-10-15T01:09:50.900091Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 464 2026-10-15T01:09:51.150157Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 471 2026-10-15T01:09:51.400539Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 498 2026-10-15T01:09:51.695718Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 505 2026-10-15T01:09:51.909204Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 518 2026-10-15T01:09:52.154114Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 525 2026-10-15T01:09:52.409940Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 552 2026-10-15T01:09:52.654114Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 559 2026-10-15T01:09:52.904216Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 567 2026-10-15T01:09:53.019510Z 192.168.8.10 (HMI (Pro-face)): FC6 Write Single Register addr=0 qty=1 values=[0] -> ACCEPTED_BY_PLC [WRITE_TO_READ_ONLY_POINT, BASELINE_DEVIATION]
- frame 572 2026-10-15T01:09:53.154153Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 579 2026-10-15T01:09:53.405112Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 606 2026-10-15T01:09:53.659076Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 613 2026-10-15T01:09:53.909130Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 620 2026-10-15T01:09:54.159351Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC
- frame 628 2026-10-15T01:09:54.409080Z 192.168.8.10 (HMI (Pro-face)): FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 -> ACCEPTED_BY_PLC

## 7. Method and limitations

- Each TCP flow to/from the Modbus port was reassembled by sequence number; Ethernet padding was excluded using the IP total length; retransmissions were skipped.
- Authorization is decided from the source IP (and MAC, where configured) against `config.json`; an attacker on the same segment who spoofs both IP and MAC of an authorized host would not be caught by the allowlist rule alone (the MAC-mismatch and multiple-MAC checks catch the common case).
- PLC outcome is taken from the PLC's response with the same Modbus transaction ID on the same TCP connection. 'ACCEPTED_BY_PLC' means the PLC acknowledged the write; it does not prove the physical process changed.
- Timestamps come from the capture file and are only as accurate as the capturing host's clock.
