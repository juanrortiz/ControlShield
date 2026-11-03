# PLC Guardian forensic report

## 1. Evidence

| Item | Value |
| --- | --- |
| Capture file | mixed_hmi_attacker_2026-11-02.pcapng |
| SHA-256 | 14bcd3a33f5e7c5970411e9e53d8f4200e14be34861d8f20006fdc3284409997 |
| Size (bytes) | 199300 |
| Frames | 2047 |
| First packet (UTC) | 2026-11-03T02:55:40.359806Z |
| Last packet (UTC) | 2026-11-03T02:56:03.702918Z |
| Duration (s) | 23.343 |
| Timestamps | from capture file (clock of the capturing host) |
| Guardian config SHA-256 | cf46cbb3e1bcd21d4d0ca58ca340511cfed4239c86fb57fd73947a104dbce385 |
| Authorized sources | 192.168.8.10 (HMI (Pro-face): read/write), 192.168.8.2 (HMI (team laptop running updated HMI project, seen in Test1 2026-10-21): read/write), 192.168.8.50 (Engineering laptop: read/write/config) |
| Evidence log | events.jsonl (chain head 74d543bbb99717aa...) |
| Report generated | 2026-11-03T03:00:56.528415Z on Dj_24_Laptop (Windows) |

## 2. Summary

- Modbus requests: **394** (ALLOW 282, ALERT 0, BLOCK-worthy 112); responses: 393; exception responses: 0
- Event types: NORMAL_READ x281, SPOOFED_SOURCE x109, UNAUTHORIZED_READ x2, UNAUTHORIZED_CHANGE x1, AUTHORIZED_CHANGE x1
- **Unauthorized activity detected from: 192.168.8.50, 192.168.8.99**
- retransmissions skipped: 108

## 3. Hosts observed

| IP | MAC(s) | Identity | Modbus requests (by category) | First packet (UTC) |
| --- | --- | --- | --- | --- |
| 0.0.0.0 | cc:ba:bd:43:f2:ab | - | - | 2026-11-03T02:55:44.436256Z |
| 192.168.8.10 | 00:00:54:0b:c5:9a | HMI (Pro-face) | {'read': 281, 'write': 1} | 2026-11-03T02:55:40.414925Z |
| 192.168.8.11 | 00:80:f4:54:1d:67 | PLC | - | 2026-11-03T02:55:40.359807Z |
| 192.168.8.50 | 00:e0:4c:68:00:f4 **(expected a0:ce:c8:62:e9:e1)** | Engineering laptop | {'read': 109} | 2026-11-03T02:55:40.359806Z |
| 192.168.8.99 | 00:e0:4c:1d:3d:70 | UNKNOWN | {'read': 2, 'write': 1} | 2026-11-03T02:55:44.891165Z |

## 4. Findings

### 192.168.8.50 (Engineering laptop)

- MAC: 00:e0:4c:68:00:f4
- Active: 2026-11-03T02:55:40.359807Z -> 2026-11-03T02:56:03.324593Z (frames 2-2030)
- Requests: 109 ({'read': 109}); rules fired: {'MAC_MISMATCH': 109}
- Attempted changes: 0; **accepted by the PLC: 0**

### 192.168.8.99 (NOT AUTHORIZED)

- MAC: 00:e0:4c:1d:3d:70
- Active: 2026-11-03T02:55:44.911868Z -> 2026-11-03T02:55:44.919071Z (frames 394-398)
- Requests: 3 ({'read': 2, 'write': 1}); rules fired: {'SRC_NOT_ALLOWLISTED': 3, 'VALUE_OUT_OF_RANGE': 1}
- Attempted changes: 1; **accepted by the PLC: 1**
  - frame 396 2026-11-03T02:55:44.916280Z: FC5 Write Single Coil addr=4 qty=1 values=[1] -> ACCEPTED_BY_PLC

## 5. Timeline of notable events

Authorized reads (normal polling) are omitted; first contact by each host on the Modbus port is included.

| Time (UTC) | Frame | Source | Action | Event | Verdict | PLC outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-03T02:55:40.359807Z | 2 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE [first contact] | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:40.414925Z | 9 | 192.168.8.10 (HMI (Pro-face)) | FC1 Read Coils addr=2 qty=4 | NORMAL_READ [first contact] | ALLOW | OK |
| 2026-11-03T02:55:40.767379Z | 29 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:40.773758Z | 41 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:41.183856Z | 65 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:41.192246Z | 77 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:41.605147Z | 101 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:41.614169Z | 113 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:42.024103Z | 139 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:42.048990Z | 152 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:42.456662Z | 177 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:42.466528Z | 189 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:42.875493Z | 211 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:42.882632Z | 222 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:43.292201Z | 249 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:43.304695Z | 260 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:43.712002Z | 288 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:43.731837Z | 301 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:44.142614Z | 322 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:44.150232Z | 334 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:44.559112Z | 363 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:44.568412Z | 375 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:44.911868Z | 394 | 192.168.8.99 (NOT AUTHORIZED) | FC1 Read Coils addr=4 qty=1 | UNAUTHORIZED_READ [first contact] | BLOCK (SRC_NOT_ALLOWLISTED) | OK |
| 2026-11-03T02:55:44.916280Z | 396 | 192.168.8.99 (NOT AUTHORIZED) | FC5 Write Single Coil addr=4 qty=1 values=[1] | UNAUTHORIZED_CHANGE | BLOCK (SRC_NOT_ALLOWLISTED, VALUE_OUT_OF_RANGE) | ACCEPTED_BY_PLC |
| 2026-11-03T02:55:44.919071Z | 398 | 192.168.8.99 (NOT AUTHORIZED) | FC1 Read Coils addr=4 qty=1 | UNAUTHORIZED_READ | BLOCK (SRC_NOT_ALLOWLISTED) | OK |
| 2026-11-03T02:55:44.997037Z | 414 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:45.005380Z | 425 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:45.423347Z | 446 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:45.455319Z | 464 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:45.863158Z | 485 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:45.882434Z | 498 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:46.288802Z | 523 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:46.298752Z | 535 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:46.710635Z | 562 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:46.721209Z | 574 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:47.129848Z | 596 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:47.137387Z | 608 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:47.545545Z | 636 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:47.578967Z | 649 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:47.991734Z | 672 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:47.998056Z | 684 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:48.431429Z | 708 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:48.440551Z | 723 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:48.848942Z | 746 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:48.855174Z | 758 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:49.263392Z | 784 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:49.271087Z | 796 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:49.694331Z | 823 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:49.725058Z | 837 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:50.134485Z | 858 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:50.142854Z | 869 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:50.552772Z | 898 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:50.561294Z | 910 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:50.976848Z | 934 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:50.986871Z | 946 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:51.396489Z | 968 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:51.404131Z | 980 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:51.812593Z | 1008 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:51.819567Z | 1020 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:52.226161Z | 1044 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:52.234159Z | 1056 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:52.664339Z | 1080 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:52.673188Z | 1091 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:53.092629Z | 1118 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:53.097644Z | 1129 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:53.504432Z | 1155 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:53.515519Z | 1168 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:53.923380Z | 1189 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:53.933037Z | 1201 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:54.344680Z | 1227 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:54.357486Z | 1238 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:54.765308Z | 1268 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:54.774241Z | 1279 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:55.184936Z | 1300 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:55.191240Z | 1312 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:55.623840Z | 1341 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:55.655158Z | 1353 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:56.063226Z | 1378 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:56.070393Z | 1390 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:56.479311Z | 1416 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:56.486731Z | 1427 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:56.918695Z | 1452 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:56.951178Z | 1466 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:57.374937Z | 1490 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:57.379562Z | 1500 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:57.800451Z | 1530 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:57.808845Z | 1541 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:58.226539Z | 1566 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:58.233106Z | 1576 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:58.639332Z | 1601 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:58.669582Z | 1614 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:59.076886Z | 1639 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:59.084622Z | 1651 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:59.511807Z | 1680 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:59.542208Z | 1694 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:59.950999Z | 1715 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:55:59.956804Z | 1729 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:00.224199Z | 1748 | 192.168.8.10 (HMI (Pro-face)) | FC15 Write Multiple Coils addr=2 qty=1 values=[0] | AUTHORIZED_CHANGE | ALLOW | ACCEPTED_BY_PLC |
| 2026-11-03T02:56:00.363961Z | 1757 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:00.388619Z | 1770 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:00.796117Z | 1797 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:00.802975Z | 1809 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:01.209989Z | 1833 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:01.215416Z | 1844 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:01.623580Z | 1869 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:01.630414Z | 1880 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:02.040647Z | 1907 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:02.047214Z | 1919 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:02.475439Z | 1946 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:02.483116Z | 1957 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:02.899938Z | 1980 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:02.909273Z | 1992 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:03.315995Z | 2018 | 192.168.8.50 (Engineering laptop) | FC1 Read Coils addr=0 qty=200 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |
| 2026-11-03T02:56:03.324593Z | 2030 | 192.168.8.50 (Engineering laptop) | FC3 Read Holding Registers addr=0 qty=2 | SPOOFED_SOURCE | BLOCK (MAC_MISMATCH) | OK |

## 6. Authorized changes

- frame 1748 2026-11-03T02:56:00.224199Z 192.168.8.10 (HMI (Pro-face)): FC15 Write Multiple Coils addr=2 qty=1 values=[0] -> ACCEPTED_BY_PLC

## 7. Method and limitations

- Each TCP flow to/from the Modbus port was reassembled by sequence number; Ethernet padding was excluded using the IP total length; retransmissions were skipped.
- Authorization is decided from the source IP (and MAC, where configured) against `config.json`; an attacker on the same segment who spoofs both IP and MAC of an authorized host would not be caught by the allowlist rule alone (the MAC-mismatch and multiple-MAC checks catch the common case).
- PLC outcome is taken from the PLC's response with the same Modbus transaction ID on the same TCP connection. 'ACCEPTED_BY_PLC' means the PLC acknowledged the write; it does not prove the physical process changed.
- Timestamps come from the capture file and are only as accurate as the capturing host's clock.
