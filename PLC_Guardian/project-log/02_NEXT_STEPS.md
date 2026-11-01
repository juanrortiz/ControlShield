# 02 · Next Steps
_Live list. CAP: 15 open items; if over, push the lowest to the Parking lot. Last updated: S-005_

Priority: P1 = blocks progress · P2 = needed for current milestone · P3 = nice to have

## Open
| ID | P | Action | Owner | Due | Source | Done when |
|---|---|---|---|---|---|---|
| A-001 | P1 | Fill in `00_PROJECT_BRIEF` (team, deliverables, due dates, rubric) | David | | S-001 | Brief has no [fill in] left in Team and Deliverables |
| A-004 | P1 | Decide inline topology: 2nd NIC (USB-Ethernet) on Guardian, PLC behind it, addressing | Team | | S-002 | Topology recorded in `06_REFERENCE` + decision record |
| A-019 | P1 | **Advance Guardian from IDS to NIPS:** wire the inline proxy (Guardian in the PLC path) and verify it actually DROPS the attacker's `%M4` write on hardware (Iteration 2), HMI still operating | Team | | S-005 | Live capture: attacker `.99` write blocked (Modbus exception / no change at PLC) while HMI keeps working; result in session log |
| A-020 | P2 | Capture a true mixed Exp-4 file: authorized HMI Modbus control AND the `.99` attack in one window, so Guardian shows ALLOW/ALERT next to BLOCK | Team | | S-005 | Capture in inventory; forensic report separates authorized vs unauthorized |
| A-021 | P3 | Give the attacker its own adapter so `.99`'s MAC differs from the allowlisted `.2` HMI laptop | Team | | S-005 | Attack capture shows a distinct attacker MAC |
| A-006 | P2 | Capture Exp. 1 normal HMI↔PLC traffic with a run sheet; run `guardian.py baseline` | | | S-002 | Capture in inventory with SHA-256; baseline.json saved |
| A-007 | P2 | Test Guardian on Windows: proxy (firewall rule TCP 502) and `monitor` (Npcap) | | | S-002 | Both modes run on the Guardian laptop; result in session log |
| A-008 | P3 | Update `00_PROJECT_BRIEF` to reflect Python (D-002) and inline blocking (D-003) | David | | S-002 | Brief scope/tools match decisions |
| A-010 | P2 | Confirm IEEE report format (conference vs journal, page limit) with instructor | | | S-002 | Noted in `07_REPORT_NOTES` |
| A-012 | P2 | Find what drives `%M4` without a Modbus write (ladder logic, physical input, animation table over USB?) (I-004) | Team | | S-003 | Cause recorded in `06_REFERENCE` |
| A-014 | P2 | Copy `Port_Mirroring_Baseline.pcapng` and `Port_mirroring_test_2.pcapng` into the project folder, hash them, add to inventory; run `baseline` on the clean one | Team | | S-003 | Both in inventory; baseline.json from the bypass-OFF capture |
| A-016 | P3 | Fix forensic report gaps and proxy SESSION_END on SIGTERM (I-005) | David | | S-003 | Re-run on `mixed_pm3_synthetic.pcap` shows S6 in Findings, no polls in §6 |
| A-018 | P3 | Find a source for FC 90 sub 0x74 and its reply's last byte (00 ×39 / 03 ×10 / 02 ×1 at fr. 101, `Port_mirroring_test_3.pcapng`) | Team | | S-004 | Meaning cited in `06_REFERENCE` FC 90 row, or left `[UNVERIFIED]` with a note |

## Waiting on others
| ID | Action | Waiting on | Since | Follow-up date |
|---|---|---|---|---|

## Parking lot (ideas, not committed)
| ID | Idea | Value | Source |
|---|---|---|---|
| A-009 | Delete leftover test log `guardian/logs/practice_events.jsonl` (owner David; moved from Open at cap) | Tidy repo | S-002 |

## Recently closed (keep last ~10)
| ID | Action | Closed in | Outcome |
|---|---|---|---|
| A-002 | Record existing captures with SHA-256 | S-002 | Both rows in `06_REFERENCE` capture inventory |
| A-003 | Identify PLC/HMI IPs, unit ID, FCs | S-002 | PLC .11, HMI .10, unit 1, FC3 only (practice fr. 4–5); recorded in `06_REFERENCE` |
| A-005 | PLC logic + register map | S-005 | Map confirmed in `06_REFERENCE`; `protected_points` enabled (D-004) |
| A-011 | Apply Guardian fixes 1–4 | S-005 | Applied + committed; PM3 150/150 ALLOW |
| A-013 | Protected-points policy | S-005 | D-004: enabled; HMI bypass ALERTs, attacker BLOCKs |
| A-015 | Capture a real direct-Modbus attack | S-005 | `Experiment_4.pcapng`; Guardian BLOCK UNAUTHORIZED_CHANGE on `%M4` |
| A-017 | Does the HMI web API accept writes? | S-005 | Yes — `%M4` ON via `POST /services/variable/hmi/1`; R-004 CONFIRMED |
