# S-004 · Modbus census of the two Modbus captures
_Generated 2026-10-21 (S-004) with tshark (Wireshark install, `C:\Program Files\Wireshark`). Read-only: the captures were only read (`sha256sum`, `capinfos`, `tshark -r`), never written._

Per-frame data: `S-004_practice_mbtcp.csv`, `S-004_pm3_mbtcp.csv` (same folder). Each row is one frame matching display filter `mbtcp`.

## 1. Capture inventory

| | modbus_capture_practice.pcapng | Port_mirroring_test_3.pcapng |
|---|---|---|
| Path | `./` | `guardian/test_runs/port_mirroring_test_3/` (working copy) |
| SHA-256 | `ad9cc550da93da0d702651a6b0d3a20f7ddb55a2a39cb5858238e4fd4786b630` | `2b26f8ab64741daababc81373ec5e4ca891579a35cb73dd3d8b018c715620bba` |
| Matches `06_REFERENCE` inventory | Yes | Yes |
| Packets | 8 | 592 |
| Duration | 0.0216 s | 12.566 s |
| First / last packet (capture host local time) | 2026-10-12 18:06:00.605668 / 18:06:00.627295 | 2026-10-14 18:09:41.967510 / 18:09:54.533099 |
| TCP 502 conversations | 192.168.8.50:53099 ↔ 192.168.8.11:502 (8 frames) | 192.168.8.10:10291 ↔ 192.168.8.11:502 (351 frames) |
| `mbtcp` frames | 2 (1 req, 1 rsp) | 300 (150 req, 150 rsp) |

Other traffic in PM3 (not port 502): 192.168.8.99:65365 ↔ 192.168.8.10:80, 216 frames (HMI web API, see R-004).

## 2. Modbus requests grouped by source, unit, FC and address

| Capture | Source → Dest | Unit | FC | Start addr | Qty | Count | First / last frame | Meaning |
|---|---|---|---|---|---|---|---|---|
| practice | .50 → .11 | 1 | 3 Read Holding Registers | 0 | 10 words | 1 | 4 / 4 | Holding registers 0–9 |
| PM3 | .10 → .11 | 255 | 1 Read Coils | 2 | 4 bits | 50 | 2 / 586 | Coils 2–5 = `%M2`–`%M5` |
| PM3 | .10 → .11 | 255 | 90 (Schneider UMAS) | n/a | n/a | 50 | 4 / 588 | Payload `00 74 01 82 00 00 00 01` (UMAS sub-function 0x74; meaning `[UNVERIFIED]`) |
| PM3 | .10 → .11 | 255 | 3 Read Holding Registers | 0 | 2 words | 50 | 6 / 590 | Holding registers 0–1 = `%MW0`–`%MW1` |

- **No write function codes** (FC 5, 6, 15, 16, 23) and **no exception responses** in either capture.
- Every request has a matching response (`modbus.request_frame`); no unanswered requests.
- PM3 cycles FC1 → FC90 → FC3 in sequence (frames 2, 4, 6, then 9, …), 50 times in ~12.45 s.
- Transaction ID is always 0 in PM3 (300 frames) and 1 in practice.

## 3. Responses

| Capture | FC | Responses | Byte count | Note |
|---|---|---|---|---|
| practice | 3 | 1 (fr. 5) | 20 | 10 registers |
| PM3 | 1 | 50 | 1 | 4 coils packed into 1 byte |
| PM3 | 3 | 50 | 4 | 2 registers |
| PM3 | 90 | 50 | n/a | `00 fe 01 00 00` ×39; `00 fe 01 00 03` ×10 (fr. 12, 39, 46, 87, 94, 142, 245, 252, 348, 375); `00 fe 01 00 02` ×1 (fr. 101) |

`0xFE` in the second byte is generally read as the UMAS "OK" reply code; what the last byte means is `[UNVERIFIED]`.

## 4. Points to note for the report
- The two captures use **different unit IDs**: 1 for the pymodbus test client (.50), 255 for the HMI (.10). This supports `plc.unit_ids = [1, 255]` (A-011).
- PM3's FC3 reads **2 words from address 0**, so it covers `%MW0` and `%MW1`. This agrees with `06_REFERENCE`, which already lists `%MW1` (always 0, meaning `[UNVERIFIED]`).
- None of the FC 90 traffic is a write, as far as the observed sub-function shows. Decoding 0x74 still needs a source before it is cited.

## 5. Reproduce
```sh
sha256sum <file>
capinfos -c -u -a -e -t <file>
tshark -r <file> -q -z conv,tcp,tcp.port==502
tshark -r <file> -Y mbtcp -T fields -E header=y -E separator=, -E quote=d \
  -e frame.number -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
  -e mbtcp.trans_id -e mbtcp.unit_id -e modbus.func_code -e modbus.request_frame \
  -e modbus.reference_num -e modbus.word_cnt -e modbus.bit_cnt -e modbus.byte_cnt \
  -e modbus.exception_code -e modbus.data
```
Grouping in §2 and §3 was done in Python over the CSVs: requests are frames with `tcp.dstport == 502`, responses are frames with `tcp.srcport == 502`.
