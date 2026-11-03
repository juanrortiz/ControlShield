# PLC Guardian forensic report

## 1. Evidence

| Item | Value |
| --- | --- |
| Capture file | exp2_m4_flip_m6_overload_2026-11-02.pcapng |
| SHA-256 | 6cafd763ddd0b97d63bf2c9f62e00e1fc54f25d78a444bc18e423398fe241f70 |
| Size (bytes) | 393688 |
| Frames | 3928 |
| First packet (UTC) | 2026-11-03T03:21:58.507133Z |
| Last packet (UTC) | 2026-11-03T03:24:02.847126Z |
| Duration (s) | 124.34 |
| Timestamps | from capture file (clock of the capturing host) |
| Guardian config SHA-256 | 2ea5cd3dc9fc846a32262807c7da2895cdc0782d9d697853470cb334b954a496 |
| Authorized sources | 192.168.8.10 (HMI (Pro-face): read/write), 192.168.8.2 (HMI (team laptop running updated HMI project, seen in Test1 2026-10-21): read/write), 192.168.8.50 (Engineering laptop: read/write/config) |
| Evidence log | events.jsonl (chain head 1a963e56d737e5d5...) |
| Report generated | 2026-11-03T03:25:45.545869Z on Dj_24_Laptop (Windows) |

## 2. Summary

- Modbus requests: **1531** (ALLOW 1528, ALERT 0, BLOCK-worthy 3); responses: 1531; exception responses: 0
- Event types: NORMAL_READ x1504, AUTHORIZED_CHANGE x24, UNAUTHORIZED_READ x2, UNAUTHORIZED_CHANGE x1
- **Unauthorized activity detected from: 192.168.8.99**

## 3. Hosts observed

| IP | MAC(s) | Identity | Modbus requests (by category) | First packet (UTC) |
| --- | --- | --- | --- | --- |
| 0.0.0.0 | cc:ba:bd:43:f2:ab | - | - | 2026-11-03T03:22:00.657310Z |
| 192.168.8.10 | 00:00:54:0b:c5:9a | HMI (Pro-face) | {'read': 1504, 'write': 24} | 2026-11-03T03:21:58.507133Z |
| 192.168.8.11 | 00:80:f4:54:1d:67 | PLC | - | 2026-11-03T03:21:58.507133Z |
| 192.168.8.99 | 00:e0:4c:1d:3d:70 | UNKNOWN | {'read': 2, 'write': 1} | 2026-11-03T03:22:27.510898Z |

## 4. Findings

### 192.168.8.99 (NOT AUTHORIZED)

- MAC: 00:e0:4c:1d:3d:70
- Active: 2026-11-03T03:23:41.314765Z -> 2026-11-03T03:23:41.320354Z (frames 3253-3257)
- Requests: 3 ({'read': 2, 'write': 1}); rules fired: {'SRC_NOT_ALLOWLISTED': 3, 'VALUE_OUT_OF_RANGE': 1}
- Attempted changes: 1; **accepted by the PLC: 1**
  - frame 3255 2026-11-03T03:23:41.317976Z: FC5 Write Single Coil addr=4 qty=1 values=[1] -> ACCEPTED_BY_PLC

## 5. Timeline of notable events

Authorized reads (normal polling) are omitted; first contact by each host on the Modbus port is included.

| Time (UTC) | Frame | Source | Action | Event | Verdict | PLC outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-03T03:21:58.507133Z | 1 | 192.168.8.10 (HMI (Pro-face)) | FC90 Schneider FC 0x5A (engineering / programming) sub=0x74 | NORMAL_READ [first contact] | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:00.110103Z | 55 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:01.508804Z | 99 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:01.929447Z | 119 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:03.071434Z | 161 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:03.571460Z | 179 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:04.703211Z | 217 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:05.343348Z | 242 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:20.859463Z | 729 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:21.517910Z | 746 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=5 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:21.559015Z | 750 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=5 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:23.784125Z | 821 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:36.220530Z | 1208 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=5 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:36.310762Z | 1211 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=5 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:36.666454Z | 1229 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:41.738638Z | 1391 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:42.458847Z | 1417 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:22:45.001956Z | 1499 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:23:03.088102Z | 2063 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=5 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:23:03.097746Z | 2065 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=5 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:23:28.939671Z | 2863 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=5 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:23:28.961380Z | 2865 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=5 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:23:41.314765Z | 3253 | 192.168.8.99 (NOT AUTHORIZED) | FC1 Read Coils addr=4 qty=1 | UNAUTHORIZED_READ [first contact] | BLOCK (SRC_NOT_ALLOWLISTED) | OK |
| 2026-11-03T03:23:41.317976Z | 3255 | 192.168.8.99 (NOT AUTHORIZED) | FC5 Write Single Coil addr=4 qty=1 values=[1] | UNAUTHORIZED_CHANGE | BLOCK (SRC_NOT_ALLOWLISTED, VALUE_OUT_OF_RANGE) | ACCEPTED_BY_PLC |
| 2026-11-03T03:23:41.320354Z | 3257 | 192.168.8.99 (NOT AUTHORIZED) | FC1 Read Coils addr=4 qty=1 | UNAUTHORIZED_READ | BLOCK (SRC_NOT_ALLOWLISTED) | OK |
| 2026-11-03T03:24:00.204352Z | 3845 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:24:01.247382Z | 3879 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=5 qty=1 values=[1] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T03:24:01.267390Z | 3881 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=5 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |

## 6. Authorized changes

- frame 55 2026-11-03T03:22:00.110103Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 99 2026-11-03T03:22:01.508804Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[0] -> ACCEPTED_BY_PLC
- frame 119 2026-11-03T03:22:01.929447Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 161 2026-11-03T03:22:03.071434Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[0] -> ACCEPTED_BY_PLC
- frame 179 2026-11-03T03:22:03.571460Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 217 2026-11-03T03:22:04.703211Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[0] -> ACCEPTED_BY_PLC
- frame 242 2026-11-03T03:22:05.343348Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 729 2026-11-03T03:22:20.859463Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[0] -> ACCEPTED_BY_PLC
- frame 746 2026-11-03T03:22:21.517910Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=5 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 750 2026-11-03T03:22:21.559015Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=5 qty=1 values=[0] -> ACCEPTED_BY_PLC
- frame 821 2026-11-03T03:22:23.784125Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 1208 2026-11-03T03:22:36.220530Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=5 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 1211 2026-11-03T03:22:36.310762Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=5 qty=1 values=[0] -> ACCEPTED_BY_PLC
- frame 1229 2026-11-03T03:22:36.666454Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[0] -> ACCEPTED_BY_PLC
- frame 1391 2026-11-03T03:22:41.738638Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 1417 2026-11-03T03:22:42.458847Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[0] -> ACCEPTED_BY_PLC
- frame 1499 2026-11-03T03:22:45.001956Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 2063 2026-11-03T03:23:03.088102Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=5 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 2065 2026-11-03T03:23:03.097746Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=5 qty=1 values=[0] -> ACCEPTED_BY_PLC
- frame 2863 2026-11-03T03:23:28.939671Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=5 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 2865 2026-11-03T03:23:28.961380Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=5 qty=1 values=[0] -> ACCEPTED_BY_PLC
- frame 3845 2026-11-03T03:24:00.204352Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[0] -> ACCEPTED_BY_PLC
- frame 3879 2026-11-03T03:24:01.247382Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=5 qty=1 values=[1] -> ACCEPTED_BY_PLC
- frame 3881 2026-11-03T03:24:01.267390Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=5 qty=1 values=[0] -> ACCEPTED_BY_PLC

## 7. Method and limitations

- Each TCP flow to/from the Modbus port was reassembled by sequence number; Ethernet padding was excluded using the IP total length; retransmissions were skipped.
- Authorization is decided from the source IP (and MAC, where configured) against `config.json`; an attacker on the same segment who spoofs both IP and MAC of an authorized host would not be caught by the allowlist rule alone (the MAC-mismatch and multiple-MAC checks catch the common case).
- PLC outcome is taken from the PLC's response with the same Modbus transaction ID on the same TCP connection. 'ACCEPTED_BY_PLC' means the PLC acknowledged the write; it does not prove the physical process changed.
- Timestamps come from the capture file and are only as accurate as the capturing host's clock.
