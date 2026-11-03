# 02 · Next Steps
_Live list. CAP: 15 open items; if over, push the lowest to the Parking lot. Last updated: S-006_

Priority: P1 = blocks progress · P2 = needed for current milestone · P3 = nice to have

## Open
| ID | P | Action | Owner | Due | Source | Done when |
|---|---|---|---|---|---|---|
| A-001 | P1 | Fill in `00_PROJECT_BRIEF` (team, deliverables, due dates, rubric) | David | | S-001 | Brief has no [fill in] left in Team and Deliverables |
| A-004 | P1 | Decide inline topology: 2nd NIC (USB-Ethernet) on Guardian, PLC behind it, addressing | Team | | S-002 | Topology recorded in `06_REFERENCE` + decision record |
| A-019 | P1 | **Advance Guardian from IDS to NIPS:** wire the inline proxy (Guardian in the PLC path) and verify it actually DROPS the attacker's `%M4` write on hardware (Iteration 2), HMI still operating | Team | | S-005 | Live capture: attacker `.99` write blocked (Modbus exception / no change at PLC) while HMI keeps working; result in session log |
| A-024 | P3 | ~~Rename capture~~ — blocked by `.claude/settings.json`'s deny rule on `.pcapng` writes (correct: protects evidence chain-of-custody even for working copies); keeping `mixed_hmi_attacker_2026-11-02.pcapng` as-named. Still open: confirm who captured it; cite `analysis/exp4_mixed_hmi_attacker_2026-11-02_forensic_report.md` in `07_REPORT_NOTES.md` Table II/forensic section | Team | | S-006 | Report evidence section cites frame numbers from the forensic report |
| A-021 | P3 | Give the attacker its own adapter so `.99`'s MAC differs from the allowlisted `.2` HMI laptop | Team | | S-005 | Attack capture shows a distinct attacker MAC |
| A-006 | P2 | Capture Exp. 1 normal HMI↔PLC traffic with a run sheet; run `guardian.py baseline` | | | S-002 | Capture in inventory with SHA-256; baseline.json saved |
| A-007 | P2 | Test Guardian on Windows: proxy (firewall rule TCP 502) and `monitor` (Npcap) | | | S-002 | Both modes run on the Guardian laptop; result in session log |
| A-010 | P2 | Confirm IEEE report format (conference vs journal, page limit) with instructor | | | S-002 | Noted in `07_REPORT_NOTES` |
| A-018 | P3 | Find a source for FC 90 sub 0x74 and its reply's last byte (00 ×39 / 03 ×10 / 02 ×1 at fr. 101, `Port_mirroring_test_3.pcapng`) | Team | | S-004 | Meaning cited in `06_REFERENCE` FC 90 row, or left `[UNVERIFIED]` with a note |
| A-022 | P2 | Run black-box Experiment 5 with `tools/plc_blackbox.py` (nmap + read-only sweep/inference) against the lab PLC; capture, hash, analyze with Guardian; compare discovered map vs `06_REFERENCE`'s known map | Team | | D-005 | Capture in inventory; blackbox_summary.md compared against the known register map in session log |
| A-025 | P3 | Close the residual I-006(3): route the *first* SIGINT through `_stop` (same handler loop as SIGTERM/SIGBREAK) so a second Ctrl+C before the outer `finally` can't corrupt the evidence-log chain while a client write is in flight; fix the `GUARDIAN_DESIGN.md:285` claim; new check with FC5 traffic during the two signals | David | | S-006 | New check (traffic in flight) passes + chain `verify` OK; docs claim matches behavior |

## Waiting on others
| ID | Action | Waiting on | Since | Follow-up date |
|---|---|---|---|---|

## Parking lot (ideas, not committed)
| ID | Idea | Value | Source |
|---|---|---|---|

## Recently closed (keep last ~10)
| ID | Action | Closed in | Outcome |
|---|---|---|---|
| A-014 | Copy baseline/test_2 captures, hash, inventory, run `baseline` on the clean one | S-006 | Both in `captures/`, hashed (857cab54.../f177f3e4...); `baseline_port_mirroring.json` from `Port_Mirroring_Baseline.pcapng` (261 req, unit 255, FC1/3/90) |
| A-016 | Fix forensic report gaps and proxy SESSION_END on SIGTERM (I-005) | S-006 | `_cat()` effective-category fix + §4 authorized-source subsection + cancellable-task signal handling; architect PASS round 2; PM3 150/150 ALLOW unchanged. Residual edge cases → A-023/I-006 |
| A-020 | Capture a true mixed Exp-4 file: authorized HMI control AND the `.99` attack in one window | S-006 | `mixed_hmi_attacker_2026-11-02.pcapng` (2047 fr., 23.3s): HMI `.10` ALLOW reads + `.99` FC5 `%M4` UNAUTHORIZED_CHANGE/BLOCK, same window. In inventory (`06_REFERENCE`); forensic report in `analysis/`. Cleanup (rename, report citation) → A-024 |
| A-008 | Update `00_PROJECT_BRIEF` to reflect Python (D-002) and inline blocking (D-003) | S-006 | In-scope/tools sections now cite D-002/D-003 and name Guardian's actual approach; remaining `[fill in]`s (term, instructor, team, deadlines, rubric, out-of-scope) are factual info only the team has → stays on A-001 |
| A-009 | Delete leftover test log `guardian/logs/practice_events.jsonl` | S-006 | Confirmed with David, deleted |
| A-012 | Find what drives `%M4` without a Modbus write (I-004) | S-006 | No write traffic found near any toggle; interval not fixed-period. Inferred (not confirmed): driven locally on the PLC, invisible to network monitoring. Finding recorded in `06_REFERENCE` |
| A-023 | Fix I-006 residual signal/shutdown edge cases from A-016 round 2 | S-006 | (1)/(2) fixed: no shutdown hang with a live client (0.0s, `hang_check.py`), RuntimeError race wrapped. (3) narrowed not closed: double-SIGINT safe only from the outer `finally` onward, not before. Architect round 2: VERDICT PASS with residual noted → A-025 |
