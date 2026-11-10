# 06 · Reference
_Stable facts. Add lines as they're learned; change a line only to correct it. Mark unconfirmed values [UNVERIFIED]._

## Lab setup
| Device | Model | IP | MAC | Notes |
|---|---|---|---|---|
| PLC | Schneider M221 | 192.168.8.11 | 00:80:f4:54:1d:67 | Modbus/TCP server on 502. Answers unit ID 1 (pymodbus test, `modbus_capture_practice.pcapng` fr. 4–5) **and unit ID 255 (used by the HMI, `Port_mirroring_test_3.pcapng` fr. 2–7)**, filter `mbtcp` |
| HMI | Pro-face web panel [model UNVERIFIED] | 192.168.8.10 | 00:00:54:0b:c5:9a | Web UI on TCP 80 · `test_connection.pcapng` fr. 4–5+, filter `tcp.port == 80`. Modbus client of the PLC: polls every ~250 ms, unit 255, TID always 0 (`Port_mirroring_test_3.pcapng`) |
| Capture host / engineering laptop | [fill in] | 192.168.8.50 | 00:e0:4c:68:00:f4 | Wireshark; both captures. MAC corrected S-006 (A-029) — confirmed via `Get-NetAdapter` against the NIC actually in use; the old `a0:ce:c8:62:e9:e1` was stale and caused spurious SPOOFED_SOURCE/MAC_MISMATCH flags on `.50`'s own traffic |
| Guardian host | [fill in] | 192.168.8.12 [planned] | | Inline needs 2nd NIC (D-003, A-004) |
| Team HMI laptop (updated HMI project) | [fill in] | 192.168.8.2 | 00:e0:4c:1d:3d:70 | Runs the HMI project in sim/online mode; polls the PLC like the panel (unit 255, FC1/FC90 0x74/FC3) + extra FC90 0x02 model read. Allowlisted in `config.json` (S-005, Test1 2026-10-21) |
| Attacker (simulated) | [fill in] | 192.168.8.99 | 00:e0:4c:1d:3d:70 | **Shares the `.2` laptop's MAC** (same USB-Ethernet dongle) → MAC rules can't separate them (A-021). Attacks: HMI web API (`POST /services/variable/hmi/1`, Exp3 Attack A) and direct Modbus FC5 `%M4`=1 (Attack B). NOT allowlisted → BLOCK by source IP. Detection never relies on address distance |
| Not the PLC | — | 192.168.8.20 | | Early wrong guess; ignore |
| Switch | TP-Link managed switch [model TBD] | 192.168.0.1 [factory default; separate mgmt subnet from the lab's 192.168.8.0/24, needs a secondary IP on the capture host's NIC to reach] | cc:ba:bd:43:f2:ab (seen on `eth.type==0x8899` loop-detection broadcasts) | **Port mirror config (confirmed working 2026-11-02, S-006): PLC=port 2 (mirrored, ingress+egress enable), HMI=port 3, attacker=port 4, Guardian/capture host=port 5 (mirroring/destination port).** Mirroring the PLC's own port captures all its traffic regardless of partner. **Physical port assignment changed since the original "PLC port 4 → Guardian port 5" note (S-005) — always verify with the sanity check (`wireshark-analyze` skill) before trusting a capture, don't assume the port numbers below are current** |

## Simulated process
- Simulated tank fill. HMI Start (`%M2`) starts filling; the level counter `%C0.V` is copied to `%MW0`. Stop (`%M3`) engages at level 80. Maintenance bypass (`%M4`) ON defeats the stop, so the level climbs past 80 (overflow). Reset = `%M5`. Source: `plc-guardian-open-items.md` §2 ("Wireshark tank values PLC" chat).
- Interlock confirmed on the wire in `Port_mirroring_test_3.pcapng`: with level > 80, `%MW0` rises only while `%M4` = 1 and holds while `%M4` = 0 (FC1 rsp fr. 3/147/236/291/339/394 vs FC3 rsp fr. 7–591). See `guardian/test_runs/port_mirroring_test_3/README.md` §2.3.

## Modbus map
| Address | Type (coil / discrete / holding / input) | Meaning | Evidence (file, frame) |
|---|---|---|---|
| 0–9 (%MW0–%MW9 [UNVERIFIED mapping]) | holding | [UNVERIFIED] read by .50 in test; all values 0 | `modbus_capture_practice.pcapng` fr. 4 (FC3 addr 0 qty 10) / fr. 5 (20 bytes, all 0), filter `mbtcp` |
| coil 2 = `%M2` | coil | Start (HMI writes with FC 15 per open-items doc) | open-items §2; read by HMI FC1 addr 2 qty 4, `Port_mirroring_test_3.pcapng` fr. 2/3 (value 1 throughout) |
| coil 3 = `%M3` | coil | Stop, engages at level 80 | open-items §2; `Port_mirroring_test_3.pcapng` (value 1 throughout, level > 80) |
| coil 4 = `%M4` | coil | Maintenance bypass (ON defeats the stop) | open-items §2; `Port_mirroring_test_3.pcapng` toggles at fr. 3, 147, 236, 291, 339, 394 with **no Modbus write** (I-004). **A-012 investigation (S-006):** no write-shaped traffic of any protocol found within ±2s of any toggle; ON/OFF intervals (~3.00, 1.75, 1.25, 1.00, 1.25s) aren't a fixed period, so a single PLC-internal timer is unlikely. Best-supported, not confirmed: `%M4` is driven locally on the PLC (physical input or local program action), invisible to network monitoring. Genuinely undecidable from a pcap alone — would need the PLC program's `%M4` assignment or a logged physical-input/Machine-Expert-monitor session alongside a new capture |
| coil 5 = `%M5` | coil | Reset | open-items §2; `Port_mirroring_test_3.pcapng` (value 0 throughout); reset not yet seen on the wire |
| coil 6 = `%M6` | coil | DIGI_OVERLOAD. New point (S-006, 2026-11-02): mirrors `%Q0.2`/TANK_OVERLOAD (the same Rung4 condition, `%C0.V` compared against the overload threshold, team-stated >100) onto an `%M` bit so it's visible over standard Modbus FC1 without needing a Modbus-TCP network-object mapping for `%Q0.2` (which the PLC's program, as of `ControlShield_PLC.pdf` 2026-10-22, had not configured). `%Q0.2` itself also still exists and drives a physical indicator lamp on the PLC; not confirmed Modbus-reachable | **CONFIRMED** two ways: (1) `q0.2_m6_overload_confirm_2026-11-02.pcapng` fr. 783 (`[1,1,1,0,0]` at coils 2-6, t=14.985s, level=98) → fr. 795 (`[1,1,1,0,1]`, t=15.231s) — coil 6 turns on within 21ms of the level crossing 100 (fr. 793, level=101); stays on through end of capture (t=18.74s, level=109). (2) Independent live FC1 poll via `guardian/tools/modbus_client.py`, same session: `set_coils=[3,4,6]` with level=109 |
| 0 = `%MW0` | holding | Tank level = counter `%C0.V` | open-items §2; HMI FC3 addr 0 qty 2, `Port_mirroring_test_3.pcapng` fr. 6/7 (122) → fr. 398 (148) |
| 1 = `%MW1` | holding | Unknown, always 0 | `Port_mirroring_test_3.pcapng` fr. 7–591 [UNVERIFIED meaning] |
| FC 90, sub-code 0x74 | Schneider proprietary | HMI status poll, req data `00 74 01 82 00 00 00 01`, reply `00 FE 01 00 0x` (x = 00 ×39, 03 ×10 at fr. 12/39/46/87/94/142/245/252/348/375, 02 ×1 at fr. 101; S-004 census) | `Port_mirroring_test_3.pcapng` fr. 4/5, filter `modbus.func_code==90` · meaning [UNVERIFIED] |

## Capture inventory (evidence, never modify originals)
| File | Date | Captured by | Scenario | Duration / packets | SHA-256 |
|---|---|---|---|---|---|
| test_connection.pcapng | 2026-10-13 00:40:40–00:45:14 UTC (10-12 local) | [fill in] | Initial connection test: HTTP between .50 and HMI web UI (.10:80); **no Modbus** | 274 s / 3,118 frames | 4294e505f4f4178b50094b8759a2f009fd06d31d45b53125c12da869b64b5b55 |
| modbus_capture_practice.pcapng | 2026-10-13 01:06:00 UTC (10-12 local) | [fill in] | One pymodbus FC3 read .50 → .11:502 (handshake, request, response, teardown) | 0.022 s / 8 frames | ad9cc550da93da0d702651a6b0d3a20f7ddb55a2a39cb5858238e4fd4786b630 |
| Port_mirroring_test_3.pcapng | 2026-10-15 01:09:41–01:09:54 UTC (10-14 local) | [fill in] | Mirror test (PLC port 4 → Guardian port 5). HMI polling only (FC1/90/3, unit 255), **no writes**; process in bypass/overflow state (level 122→148, `%M4` toggling); `.99` polls HMI web API only. Original in claude.ai project files; working copy in `guardian/test_runs/port_mirroring_test_3/` | 12.6 s / 592 frames | 2b26f8ab64741daababc81373ec5e4ca891579a35cb73dd3d8b018c715620bba |
| Experiment3_capture.pcapng | 2026-10-22 01:32:24–01:35:27 UTC (18:32–18:35 PDT) | [fill in] | Exp 3 Attack A: `.99` nmap-scans HMI `.10`, finds port 80, writes `%M4` bypass ON via HMI web API (`POST /services/variable/hmi/1 newVal=1`, fr. 1549). **No traffic to PLC `.11`** — Guardian blind (R-004). See `claude/experiment3-findings.md`. **[FILE NOT FOUND, S-006]** — not present in `captures/` or project root; appears to exist only wherever `claude/experiment3-findings.md` lives (not this local folder, unlike `Port_mirroring_test_3.pcapng`'s working copy). Locate/restore before citing frame numbers from it in the report | 183 s / 1,857 frames | f7ea52d57cd319997804a9ac13f8b609f17c71e06b66c4039c78d8167b550cd0 |
| Experiment_4.pcapng | 2026-10-22 02:02:39–02:03:20 UTC (19:02–19:03 PDT) | [fill in] | Exp 3 Attack B (direct Modbus): `.99` → `.11:502` FC5 coil 4 = ON (`%M4` bypass), unit 1, fr. 50, ACCEPTED_BY_PLC (passive mirror, not blocked). Guardian detects + attributes: BLOCK UNAUTHORIZED_CHANGE. Attacker-only (no HMI traffic). **NAME COLLISION — rename vs the row below.** **[FILE NOT FOUND, S-006]** — same as above, not present locally | 41 s / 114 frames | a575fc622e679f08d8a73bda0917ad2d51b68c10e98e370818451d3a33b13704 |
| Experiment_4.pcapng (mixed; **rename**, e.g. `exp3_attack_overflow`) | 2026-10-22 02:05:07–02:05:44 UTC (19:05 PDT) | [fill in] | Exp 3 / Iteration-1: bypass OFF beforehand → `.99` FC5 `%M4`=1 (fr. 39, t+10.8s) → **tank overflows**, HMI web level climbs 87→134 past the 80 stop. Guardian BLOCK UNAUTHORIZED_CHANGE names `%M4`. Best attack+effect evidence; still no authorized Modbus (A-020). **[FILE NOT FOUND, S-006]** — same as above, not present locally | 37 s / 348 frames | 6656268bf24ab2a7b4b4f5b64af7878471c311da57b98d641098a0d4bde6ef36 |
| 2026-10-21_mirror_check_99.pcapng | 2026-10-21 17:56:39–17:57:20 UTC (10:56 PDT) [UNVERIFIED who captured] | [fill in] | [UNVERIFIED purpose] Mirror sanity check using `.99` as test client: 354 FC90 request/response pairs, `.99` ↔ `.11` only, no other hosts' Modbus traffic. Likely an early mirror-port verification predating the Exp 3/4 attack captures | 41.0 s / 891 frames | 258b6e7f46f2dcdf80cc00adc19db50c974071f3cca26bb2d648a72a174ee967 |
| 2026-11-02_174454_hmi_q02_overload_flag.pcapng | 2026-11-03 01:44:54–01:45:54 UTC (2026-11-02 17:44 PDT) [UNVERIFIED who captured] | [fill in] | First `%Q0.2`/overload-flag check, before the point was mapped to `%M6`. Only FC90/UMAS traffic (`.2`↔`.11`), no standard FC1/FC3 — no standard-Modbus confirmation of the flag in this capture | 59.7 s / 1379 frames, 1249 on port 502 | 0d25406f55cce54cd5f8ff93e612cf514d4d34dcdc94aa7bdf792eb9346c391a |
| 2026-11-02_174737_hmi_q02_overload_flag.pcapng | 2026-11-03 01:47:37–01:48:37 UTC (2026-11-02 17:47 PDT) [UNVERIFIED who captured] | [fill in] | Second `%Q0.2` check, same result as above: FC90/UMAS only, no standard coil traffic | 59.8 s / 1094 frames, 954 on port 502 | 162a7bcaa303e1de82baae5c3af91d731df3bf6ab12b5201b7f50883bb7be2fe |
| 2026-11-02_175533_hmi_q02_overload_flag.pcapng | 2026-11-03 01:55:33–01:56:33 UTC (2026-11-02 17:55 PDT) [UNVERIFIED who captured] | [fill in] | Third `%Q0.2` check: `.10` web API HTTP polling (`/services/variable/hmi/values`) alongside `.2`'s FC90 traffic; revealed the port-mirror outage (I-007) was about to be investigated. Also the capture that showed the switch was mirroring port 4 (attacker), not the PLC's port | 59.8 s / 2381 frames, 989 on port 502 | 7d76d309d1c9ee7389c8ca747378c4f2e77ef3ac24b8b338f3003d287d8d3f8f |

| mixed_hmi_attacker_2026-11-02.pcapng | 2026-11-02 18:55:40–18:56:04 UTC (10:55 PDT) [UNVERIFIED who captured] | [fill in] | True mixed capture (A-020): HMI `.10` normal polling (FC1/FC3/FC90, ALLOW) + engineering laptop `.50`'s own test polling (flagged SPOOFED_SOURCE/MAC_MISMATCH — stale MAC in `config.json` for the `.50` adapter in use, not a real attacker) + `.99` direct-Modbus attack (FC5 `%M4`=1, UNAUTHORIZED_CHANGE, BLOCK, ACCEPTED_BY_PLC). Forensic report: `analysis/exp4_mixed_hmi_attacker_2026-11-02_forensic_report.md` | 23.3 s / 2047 frames | 14bcd3a33f5e7c5970411e9e53d8f4200e14be34861d8f20006fdc3284409997 |

| q0.2_m6_overload_confirm_2026-11-02.pcapng | 2026-11-02 19:09:34–19:09:53 UTC (11:09 PDT) [UNVERIFIED who captured] | [fill in] | Confirms new `%M6`/DIGI_OVERLOAD coil: HMI `.10` FC1 reads coils 2-6; coil 6 turns on at fr. 795 (t=15.231s) within 21ms of `%MW0` crossing 100 (fr. 793, level=101, fr. 15 level=28 start). Normal operation, no attack | 18.9 s / 986 frames | 28f306c761cbebdeed2dba80360e991c6f9b7fa1eecacc4c90642e27db025a91 |

| exp2_m4_flip_m6_overload_2026-11-02.pcapng | 2026-11-02 19:21:58–19:24:03 UTC (11:21 PDT) [UNVERIFIED who captured] | [fill in] | **Experiment 2** (new numbering, `07_REPORT_NOTES` S-006): `.99` FC5 write `%M4`=ON at fr. 3255 (t=102.811s) → tank climbs unchecked → `%MW0` crosses 100 at fr. 3520 (t=111.161s) → `%M6`/DIGI_OVERLOAD asserts at fr. 3525 (t=111.397s, 236ms after crossing, 8.6s after the attack). Guardian: UNAUTHORIZED_CHANGE, rules SRC_NOT_ALLOWLISTED+VALUE_OUT_OF_RANGE, attributed to `.99`. Forensic report: `analysis/exp2_m4_flip_m6_overload_2026-11-02_forensic_report.md` | 124.3 s / 3928 frames | 6cafd763ddd0b97d63bf2c9f62e00e1fc54f25d78a444bc18e423398fe241f70 |

| exp3_active_response_success_2026-11-04.pcapng | 2026-11-04 18:51:57–18:52:07 PDT [UNVERIFIED who captured] | [fill in] | **D-007 success demonstration.** `.99` FC5 write `%M4`=ON at fr. 94 (t=2.590s), BLOCKed (SRC_NOT_ALLOWLISTED, VALUE_OUT_OF_RANGE); Guardian's own lockout write (coil 7) lands at fr. 105 (t=2.596s) — ~6ms later. `%MW0` was climbing 37→50 (fr. 6–83) and **freezes at exactly 50 for the rest of the capture** (fr. 119–325, through t=9.55s) despite `%M4` staying electrically ON — ladder logic correctly overrides the output rather than fighting the bypass bit. Forensic report: `analysis/exp3_active_response_success_2026-11-04_forensic_report.md` | 9.8 s / 327 frames | 4025110a9692c1ae06ccc73448251ca9d3b262351e66a12f0841b6bb8feea7c9 |

| `Port 80 Test.pcapng` (proposed: `2026-11-09_port80_test.pcapng`) | 2026-11-09, S-007 | David Jessup | `.99` browses/polls the HMI's web UI directly (`192.168.8.10:80`) — `GET /services/variable/hmi/values` repeatedly plus a full page-load sequence. Confirms the HTTP gate (D-008) is not yet in the traffic path (A-033 open). Not yet moved into `captures/` — blocked by the `.pcapng` write deny rule for Claude; pending a manual copy from Downloads | 1916 fr. / 24.2 s | `c567ebf7d5452cce6f02f4b038ea400b4e80082c92f563aa2cc067325d0d1fe2` |
| `Port 80 IPS.pcapng` (proposed: `2026-11-09_port80_ips_live.pcapng`) | 2026-11-09/10, S-007 | David Jessup | **D-009 live demonstration.** `.99` connects to the HMI's web port (fr. 339, `03:24:13.047Z`); `http_watch` detects it and `active_response` fires a real FC5 lockout write to `%M7` (fr. 349/351), accepted by the PLC 3.4ms later — matches Guardian's evidence log to the microsecond. Analysis: `analysis/S-007_port80_ips_live_test.md`. Not yet moved into `captures/` — same deny-rule block as above | 726 fr. / 14.1 s | `4619452f229185c052330f5159ae52db976421acc8dbdbb3a67f832f239d541c` |
| `Black Box Test.pcapng` (proposed: `2026-11-09_blackbox_discovery.pcapng`) | 2026-11-09/10, S-007 | David Jessup | **Experiment 5 / A-022.** Black-box discovery (port scan, FC43 fingerprint, FC1-4 enumeration 0-19 × 21 samples) against the real PLC from `.99` — zero writes confirmed (D-005 read-only scope honored). 1682 BLOCKed reads trigger `active_response` only 5×, cooldown correctly suppresses 1677 — first real validation of the cooldown under sustained load. Also contains a recurrence of the port-80 HTTP test. Analysis: `analysis/S-007_blackbox_discovery_live_test.md`. Not yet moved into `captures/` — same deny-rule block as above | ~15,000 fr. / 293.4 s | `c0655920c0a521f3b6652d93ae8c131022d4fd1e3cbac55582d1129c2ffba521` |

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
