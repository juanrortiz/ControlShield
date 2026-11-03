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
| Evidence log | events.jsonl (chain head 1920d14e4f57ab7b...) |
| Report generated | 2026-11-03T01:31:20.605366Z on Dj_24_Laptop (Windows) |

## 2. Summary

- Modbus requests: **158** (ALLOW 151, ALERT 1, BLOCK-worthy 6); responses: 158; exception responses: 0
- Event types: NORMAL_READ x150, AUTHORIZED_CHANGE x3, UNAUTHORIZED_CHANGE x3, SPOOFED_SOURCE x1, UNAUTHORIZED_CONFIG_CHANGE x1
- **Unauthorized activity detected from: 192.168.8.10, 192.168.8.99**

## 3. Hosts observed

| IP | MAC(s) | Identity | Modbus requests (by category) | First packet (UTC) |
| --- | --- | --- | --- | --- |
| 192.168.8.10 | 00:00:54:0b:c5:9a, 00:e0:4c:1d:3d:70 **(multiple MACs: possible spoofing / ARP poisoning)** | HMI (Pro-face) | {'read': 150, 'write': 4} | 2026-10-15T01:09:41.967510Z |
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

### Authorized-source requests with decision ALERT/BLOCK

These came from an authorized source but the policy returned ALERT or BLOCK (rules and details below). BLOCK is the policy verdict; in a pcap analysis nothing was actually dropped.

| Time (UTC) | Frame | Source | Action | Decision | Rules | Details | PLC outcome |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-10-15T01:09:46.019510Z | 203 | 192.168.8.10 (HMI (Pro-face)) | FC5 Write Single Coil addr=4 qty=1 values=[1] | ALERT | VALUE_OUT_OF_RANGE | %M4 Maintenance bypass (ON defeats the level-80 stop) (coil 4) = 1, allowed 0..0 | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:53.019510Z | 567 | 192.168.8.10 (HMI (Pro-face)) | FC6 Write Single Register addr=0 qty=1 values=[0] | BLOCK | WRITE_TO_READ_ONLY_POINT | %MW0 Tank level (= counter %C0.V, computed by the PLC) (holding 0) is read-only | ACCEPTED_BY_PLC |

## 5. Timeline of notable events

Authorized reads (normal polling) are omitted; first contact by each host on the Modbus port is included.

| Time (UTC) | Frame | Source | Action | Event | Verdict | PLC outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-15T01:09:42.124721Z | 2 | 192.168.8.10 (HMI (Pro-face)) | FC1 Read Coils addr=2 qty=4 | NORMAL_READ [first contact] | ALLOW | OK |
| 2026-10-15T01:09:44.019510Z | 101 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:46.019510Z | 203 | 192.168.8.10 (HMI (Pro-face)) | FC5 Write Single Coil addr=4 qty=1 values=[1] | AUTHORIZED_CHANGE | ALERT (VALUE_OUT_OF_RANGE) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:48.019510Z | 305 | 192.168.8.99 (NOT AUTHORIZED) | FC5 Write Single Coil addr=4 qty=1 values=[1] | UNAUTHORIZED_CHANGE [first contact] | BLOCK (SRC_NOT_ALLOWLISTED, VALUE_OUT_OF_RANGE) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:48.071510Z | 307 | 192.168.8.99 (NOT AUTHORIZED) | FC5 Write Single Coil addr=2 qty=1 values=[1] | UNAUTHORIZED_CHANGE | BLOCK (SRC_NOT_ALLOWLISTED) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:48.123510Z | 309 | 192.168.8.99 (NOT AUTHORIZED) | FC6 Write Single Register addr=0 qty=1 values=[0] | UNAUTHORIZED_CHANGE | BLOCK (SRC_NOT_ALLOWLISTED, WRITE_TO_READ_ONLY_POINT) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:50.019510Z | 411 | 192.168.8.10 (HMI (Pro-face)) | FC5 Write Single Coil addr=3 qty=1 values=[0] | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:52.019510Z | 513 | 192.168.8.99 (NOT AUTHORIZED) | FC90 Schneider FC 0x5A (engineering / programming) sub=0x41 (STOP_PLC?) | UNAUTHORIZED_CONFIG_CHANGE | BLOCK (SRC_NOT_ALLOWLISTED) | ACCEPTED_BY_PLC |
| 2026-10-15T01:09:53.019510Z | 567 | 192.168.8.10 (HMI (Pro-face)) | FC6 Write Single Register addr=0 qty=1 values=[0] | AUTHORIZED_CHANGE | BLOCK (WRITE_TO_READ_ONLY_POINT) | ACCEPTED_BY_PLC |

## 6. Authorized changes

- frame 101 2026-10-15T01:09:44.019510Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 203 2026-10-15T01:09:46.019510Z 192.168.8.10 (HMI (Pro-face)): FC5 Write Single Coil addr=4 qty=1 values=[1] -> ACCEPTED_BY_PLC [VALUE_OUT_OF_RANGE]
- frame 567 2026-10-15T01:09:53.019510Z 192.168.8.10 (HMI (Pro-face)): FC6 Write Single Register addr=0 qty=1 values=[0] -> ACCEPTED_BY_PLC [WRITE_TO_READ_ONLY_POINT]

## 7. Method and limitations

- Each TCP flow to/from the Modbus port was reassembled by sequence number; Ethernet padding was excluded using the IP total length; retransmissions were skipped.
- Authorization is decided from the source IP (and MAC, where configured) against `config.json`; an attacker on the same segment who spoofs both IP and MAC of an authorized host would not be caught by the allowlist rule alone (the MAC-mismatch and multiple-MAC checks catch the common case).
- PLC outcome is taken from the PLC's response with the same Modbus transaction ID on the same TCP connection. 'ACCEPTED_BY_PLC' means the PLC acknowledged the write; it does not prove the physical process changed.
- Timestamps come from the capture file and are only as accurate as the capturing host's clock.
