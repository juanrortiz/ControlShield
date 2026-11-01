# 04 · Session Log
_Append-only. Newest at the bottom. ≤ 8 lines per entry._

---

### S-001 · 2026-10-21 · Project log setup
- **Goal:** Set up the documentation kit for PLC Guardian
- **Done:** Created `project-log/` (00–06), `CLAUDE.md`, and four Claude Code skills
- **Verified:** Files present in the Group Project folder
- **Decisions:** D-001
- **RAID:** R-001, AS-001 opened
- **Next:** A-001, A-002, A-003 created

### S-002 · 2026-10-21 · Guardian build + documentation
- **Goal:** Build PLC Guardian detection/logging/blocking in Python and document it for the IEEE report
- **Done:** `guardian/` (decoder, policy, hash-chained log, inline proxy, analyzer, baseline, forensics, CLI, mock PLC/client); `docs/GUARDIAN_DESIGN.md`; `07_REPORT_NOTES.md`; 06 lab/capture data
- **Verified:** practice capture fr. 4–5 decoded + policy correct; capture hash unchanged; log tamper detected; proxy forwards to mock PLC. Not on hardware yet
- **Decisions:** D-002 (Python replaces C), D-003 (inline proxy blocking)
- **RAID:** R-002, R-003, AS-002, I-001, X-001, X-002 opened; AS-001 partly confirmed
- **Next:** A-002, A-003 closed; A-004 to A-010 created
- **Notes:** Synthetic attack-capture generator not built; Exp. 2–4 use real lab captures

### S-003 · 2026-10-21 · Port_mirroring_test_3 analysis + Guardian test
- **Goal:** Analyze `Port_mirroring_test_3.pcapng` against the register map and test Guardian v0.1 on it
- **Done:** Decoded poll cycle and process state; ran analyze/baseline/forensics/proxy; built SYNTHETIC mixed capture (S1–S6); proposed fixes; write-up in `guardian/test_runs/port_mirroring_test_3/README.md`
- **Verified:** interlock on the wire (`%MW0` rises only while `%M4`=1); current Guardian flags 150/150 normal requests and blocks the HMI's FC 90 poll; with fixes 150/150 ALLOW and 6/6 synthetic scenarios correct; log chains PASS; capture hash unchanged
- **Decisions:** none (fixes and protected points are proposals: A-011, A-013)
- **RAID:** R-004, I-002–I-005 opened; AS-001 confirmed; AS-002 noted; I-001 partly resolved
- **Next:** A-011 to A-017 created
- **Notes:** Guardian source not modified. Synthetic traffic marked with TTL 99; never cite it as lab evidence. Write-up also in claude.ai project (`claude/port-mirroring-test-3-findings.md`); working copy of the capture (same SHA-256, not the original) in `guardian/test_runs/port_mirroring_test_3/`

### S-004 · 2026-10-21 · tshark Modbus census of practice + PM3 captures
- **Goal:** Inventory `modbus_capture_practice.pcapng` and `Port_mirroring_test_3.pcapng` with tshark: SHA-256, packets, duration, port 502 hosts, FCs/units/addresses with frames
- **Done:** `analysis/S-004_modbus_census.md` + `S-004_practice_mbtcp.csv`, `S-004_pm3_mbtcp.csv` (all `mbtcp` frames)
- **Verified:** both SHA-256 match the inventory; practice 1 req/1 rsp (fr. 4/5, unit 1, FC3 addr 0 qty 10); PM3 150 req/150 rsp, unit 255, FC1 addr 2 qty 4 / FC90 sub 0x74 / FC3 addr 0 qty 2 ×50 each (fr. 2–590); no writes, no exceptions, none unanswered (filter `mbtcp`)
- **Decisions:** none
- **RAID:** none
- **Next:** A-018 created; A-009 moved to Parking lot (cap)
- **Notes:** Read-only; captures not modified. Results agree with `06_REFERENCE` (no new register facts)

### S-005 · 2026-10-21 · Experiment 3 attacks (HMI web + direct Modbus) + Guardian fixes
- **Goal:** Live test: baseline/authorized/attacker runs; detect, log and block an unauthorized change
- **Done:** Applied fixes 1–4 (A-011); enabled `%M`/`%MW0` protected points in `config.json` (D-004); added `.2` HMI laptop to allowlist; added `write-coil` FC5 mode to `tools/plc_lab_client.py`; captured both attack paths; generated forensic reports (`analysis/`, `claude/experiment3-findings.md`, `claude/exp3-attackB-forensic-report.md`)
- **Verified:** fixes → PM3 150/150 ALLOW; `write-coil` end-to-end vs mock PLC; Guardian on real captures → attacker `.99` BLOCK UNAUTHORIZED_CHANGE naming `%M4` (`Experiment_4.pcapng` fr. 50/39); Iteration-1 overflow: `%M4`=1 (t+10.8s) → HMI level 87→134 past the 80 stop (`Experiment_4` mixed `6656268b…`)
- **Decisions:** D-004 (enable protected points; HMI maintenance bypass ALERTs not blocks)
- **RAID:** R-004 → **CONFIRMED** (HMI web API writes: `POST /services/variable/hmi/1 newVal=1` = `%M4` ON, `Experiment3_capture.pcapng` fr. 1549; Guardian saw 0 PLC requests)
- **Next:** closed A-011/A-013/A-015/A-017; opened A-019 (verify proxy BLOCK on laptop — Iteration 2), A-020 (true mixed Exp-4 capture), A-021 (attacker own adapter/MAC)
- **Notes:** `[REPORTED]` not re-verified here: proxy BLOCK *action* (passed S-003; cloud env blocks listening sockets). Two different captures both named `Experiment_4.pcapng` — rename one.

<!-- Template
### S-### · YYYY-MM-DD · <topic>
- **Goal:**
- **Done:**
- **Verified:** what was checked against a capture/test, or "not yet"
- **Decisions:** D-### or none
- **RAID:** opened/closed R/AS/I/X-### or none
- **Next:** A-### created/closed
- **Notes:** (optional)
-->
