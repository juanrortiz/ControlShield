# 06 · Reference
_Stable facts. Add lines as they're learned; change a line only to correct it. Mark unconfirmed values [UNVERIFIED]._

## Lab setup
| Device | Model | IP | MAC | Notes |
|---|---|---|---|---|
| PLC | Schneider M221 | 192.168.8.11 | 00:80:f4:54:1d:67 | Modbus/TCP server on 502. Answers unit ID 1 (pymodbus test, `modbus_capture_practice.pcapng` fr. 4–5) **and unit ID 255 (used by the HMI, `Port_mirroring_test_3.pcapng` fr. 2–7)**, filter `mbtcp` |
| HMI | Pro-face web panel [model UNVERIFIED] | 192.168.8.10 | 00:00:54:0b:c5:9a | Web UI on TCP 80 · `test_connection.pcapng` fr. 4–5+, filter `tcp.port == 80`. Modbus client of the PLC: polls every ~250 ms, unit 255, TID always 0 (`Port_mirroring_test_3.pcapng`) |
| Capture host / engineering laptop | [fill in] | 192.168.8.50 | a0:ce:c8:62:e9:e1 | Wireshark; both captures |
| Guardian host | [fill in] | 192.168.8.12 [planned] | | Inline needs 2nd NIC (D-003, A-004) |
| Team HMI laptop (updated HMI project) | [fill in] | 192.168.8.2 | 00:e0:4c:1d:3d:70 | Runs the HMI project in sim/online mode; polls the PLC like the panel (unit 255, FC1/FC90 0x74/FC3) + extra FC90 0x02 model read. Allowlisted in `config.json` (S-005, Test1 2026-10-21) |
| Attacker (simulated) | [fill in] | 192.168.8.99 | 00:e0:4c:1d:3d:70 | **Shares the `.2` laptop's MAC** (same USB-Ethernet dongle) → MAC rules can't separate them (A-021). Attacks: HMI web API (`POST /services/variable/hmi/1`, Exp3 Attack A) and direct Modbus FC5 `%M4`=1 (Attack B). NOT allowlisted → BLOCK by source IP. Detection never relies on address distance |
| Not the PLC | — | 192.168.8.20 | | Early wrong guess; ignore |

## Simulated process
- Simulated tank fill. HMI Start (`%M2`) starts filling; the level counter `%C0.V` is copied to `%MW0`. Stop (`%M3`) engages at level 80. Maintenance bypass (`%M4`) ON defeats the stop, so the level climbs past 80 (overflow). Reset = `%M5`. Source: `plc-guardian-open-items.md` §2 ("Wireshark tank values PLC" chat).
- Interlock confirmed on the wire in `Port_mirroring_test_3.pcapng`: with level > 80, `%MW0` rises only while `%M4` = 1 and holds while `%M4` = 0 (FC1 rsp fr. 3/147/236/291/339/394 vs FC3 rsp fr. 7–591). See `guardian/test_runs/port_mirroring_test_3/README.md` §2.3.

## Modbus map
| Address | Type (coil / discrete / holding / input) | Meaning | Evidence (file, frame) |
|---|---|---|---|
| 0–9 (%MW0–%MW9 [UNVERIFIED mapping]) | holding | [UNVERIFIED] read by .50 in test; all values 0 | `modbus_capture_practice.pcapng` fr. 4 (FC3 addr 0 qty 10) / fr. 5 (20 bytes, all 0), filter `mbtcp` |
| coil 2 = `%M2` | coil | Start (HMI writes with FC 15 per open-items doc) | open-items §2; read by HMI FC1 addr 2 qty 4, `Port_mirroring_test_3.pcapng` fr. 2/3 (value 1 throughout) |
| coil 3 = `%M3` | coil | Stop, engages at level 80 | open-items §2; `Port_mirroring_test_3.pcapng` (value 1 throughout, level > 80) |
| coil 4 = `%M4` | coil | Maintenance bypass (ON defeats the stop) | open-items §2; `Port_mirroring_test_3.pcapng` toggles at fr. 3, 147, 236, 291, 339, 394 with **no Modbus write** (I-004) |
| coil 5 = `%M5` | coil | Reset | open-items §2; `Port_mirroring_test_3.pcapng` (value 0 throughout); reset not yet seen on the wire |
| 0 = `%MW0` | holding | Tank level = counter `%C0.V` | open-items §2; HMI FC3 addr 0 qty 2, `Port_mirroring_test_3.pcapng` fr. 6/7 (122) → fr. 398 (148) |
| 1 = `%MW1` | holding | Unknown, always 0 | `Port_mirroring_test_3.pcapng` fr. 7–591 [UNVERIFIED meaning] |
| FC 90, sub-code 0x74 | Schneider proprietary | HMI status poll, req data `00 74 01 82 00 00 00 01`, reply `00 FE 01 00 0x` (x = 00 ×39, 03 ×10 at fr. 12/39/46/87/94/142/245/252/348/375, 02 ×1 at fr. 101; S-004 census) | `Port_mirroring_test_3.pcapng` fr. 4/5, filter `modbus.func_code==90` · meaning [UNVERIFIED] |

## Capture inventory (evidence, never modify originals)
| File | Date | Captured by | Scenario | Duration / packets | SHA-256 |
|---|---|---|---|---|---|
| test_connection.pcapng | 2026-10-13 00:40:40–00:45:14 UTC (10-12 local) | [fill in] | Initial connection test: HTTP between .50 and HMI web UI (.10:80); **no Modbus** | 274 s / 3,118 frames | 4294e505f4f4178b50094b8759a2f009fd06d31d45b53125c12da869b64b5b55 |
| modbus_capture_practice.pcapng | 2026-10-13 01:06:00 UTC (10-12 local) | [fill in] | One pymodbus FC3 read .50 → .11:502 (handshake, request, response, teardown) | 0.022 s / 8 frames | ad9cc550da93da0d702651a6b0d3a20f7ddb55a2a39cb5858238e4fd4786b630 |
| Port_mirroring_test_3.pcapng | 2026-10-15 01:09:41–01:09:54 UTC (10-14 local) | [fill in] | Mirror test (PLC port 4 → Guardian port 5). HMI polling only (FC1/90/3, unit 255), **no writes**; process in bypass/overflow state (level 122→148, `%M4` toggling); `.99` polls HMI web API only. Original in claude.ai project files; working copy in `guardian/test_runs/port_mirroring_test_3/` | 12.6 s / 592 frames | 2b26f8ab64741daababc81373ec5e4ca891579a35cb73dd3d8b018c715620bba |
| Experiment3_capture.pcapng | 2026-10-22 01:32:24–01:35:27 UTC (18:32–18:35 PDT) | [fill in] | Exp 3 Attack A: `.99` nmap-scans HMI `.10`, finds port 80, writes `%M4` bypass ON via HMI web API (`POST /services/variable/hmi/1 newVal=1`, fr. 1549). **No traffic to PLC `.11`** — Guardian blind (R-004). See `claude/experiment3-findings.md` | 183 s / 1,857 frames | f7ea52d57cd319997804a9ac13f8b609f17c71e06b66c4039c78d8167b550cd0 |
| Experiment_4.pcapng | 2026-10-22 02:02:39–02:03:20 UTC (19:02–19:03 PDT) | [fill in] | Exp 3 Attack B (direct Modbus): `.99` → `.11:502` FC5 coil 4 = ON (`%M4` bypass), unit 1, fr. 50, ACCEPTED_BY_PLC (passive mirror, not blocked). Guardian detects + attributes: BLOCK UNAUTHORIZED_CHANGE. Attacker-only (no HMI traffic). **NAME COLLISION — rename vs the row below** | 41 s / 114 frames | a575fc622e679f08d8a73bda0917ad2d51b68c10e98e370818451d3a33b13704 |
| Experiment_4.pcapng (mixed; **rename**, e.g. `exp3_attack_overflow`) | 2026-10-22 02:05:07–02:05:44 UTC (19:05 PDT) | [fill in] | Exp 3 / Iteration-1: bypass OFF beforehand → `.99` FC5 `%M4`=1 (fr. 39, t+10.8s) → **tank overflows**, HMI web level climbs 87→134 past the 80 stop. Guardian BLOCK UNAUTHORIZED_CHANGE names `%M4`. Best attack+effect evidence; still no authorized Modbus (A-020) | 37 s / 348 frames | 6656268bf24ab2a7b4b4f5b64af7878471c311da57b98d641098a0d4bde6ef36 |

Hashes of `modbus_capture_practice.pcapng` and `Port_mirroring_test_3.pcapng` (working copy) re-verified 2026-10-21 (S-004): `analysis/S-004_modbus_census.md`.

Hash in PowerShell: `Get-FileHash .\<file>.pcapng -Algorithm SHA256`

## Useful Wireshark filters
| Filter | Use |
|---|---|
| `mbtcp` | All Modbus TCP |
| `tcp.port == 502` | Modbus port traffic |
| `modbus.func_code == 5 \|\| modbus.func_code == 6 \|\| modbus.func_code == 15 \|\| modbus.func_code == 16` | Writes (coil/register) |
| `modbus.func_code >= 128` | Exception responses |
| `modbus.func_code == 90` | Schneider FC 90 (HMI poll sub 0x74 is normal; any other sub-code or source = config activity) |
| `modbus.func_code == 1 && tcp.srcport == 502` | Coil-state replies (`%M2`–`%M5` in one byte: bit0 = `%M2` … bit3 = `%M5`) |
| `eth.type == 0x8899` | Switch loop-detection broadcasts (noise, exclude) |

## Modbus function codes (quick ref)
| Code | Name |
|---|---|
| 1 / 2 | Read coils / discrete inputs |
| 3 / 4 | Read holding / input registers |
| 5 / 6 | Write single coil / register |
| 15 / 16 | Write multiple coils / registers |
| 90 (0x5A) | Schneider proprietary (engineering, and the HMI's status poll sub 0x74) |

## Glossary
- **HMI**: Human-Machine Interface · **PLC**: Programmable Logic Controller · **Unit ID**: Modbus slave address in the MBAP header

## Known traps
- Short Ethernet frames are padded to 60 bytes; scapy shows the padding as TCP payload. Take the payload length from the IP total length (`modbus_capture_practice.pcapng` fr. 2 shows 2 padding bytes on a SYN-ACK).
- 192.168.8.20 is NOT the PLC; the PLC is .11.
- pymodbus 3.16: `slave=` keyword is deprecated; use `read_holding_registers(addr, count=N)`.
- The HMI uses **unit ID 255** and **Transaction ID 0** on every request: pair requests/responses by TCP stream order, and allow unit 255 in Guardian (`Port_mirroring_test_3.pcapng`).
- The HMI's routine poll includes **FC 90 sub 0x74**. Treating all FC 90 as "config" makes Guardian block the HMI (I-002).
- The HMI's clock is wrong: HTTP `Date:` = 31 Dec 1999 (`Port_mirroring_test_3.pcapng` fr. 22). Use capture-host timestamps only.
- A PLC bit can change with no network write (`%M4`, I-004). Network monitoring can't see local/physical changes.
- Guardian v0.1 reads classic `.pcap` as raw bytes and reports nothing (I-003). Use `.pcapng` until the fix is applied.

## Software
- PLC Guardian (Python): `guardian/` · design reference `docs/GUARDIAN_DESIGN.md` · report material `project-log/07_REPORT_NOTES.md`
