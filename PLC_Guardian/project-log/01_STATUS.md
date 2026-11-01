# 01 · Status
_State file. Rewritten at each session close. CAP: one screen. Last updated: S-005 · 2026-10-21_

## Current milestone
M1: Baseline capture and Modbus understanding · ~90%
M2: Guardian working end-to-end on lab hardware — **IDS done, NIPS (inline block) next**

## What works now
- Port mirroring PLC → Guardian verified live (S-005); captures hashed in `06_REFERENCE`
- PLC `.11:502` (units 1/255); HMI `.10`; team HMI laptop `.2` (updated project, allowlisted); attacker `.99`. Register map `%M2`–`%M5`, `%MW0` in `06_REFERENCE`
- **Guardian fixes 1–4 applied** (A-011): unit 255, FC90 0x74 as read, FC90 signature, `.pcap` link-type → PM3 150/150 ALLOW
- **Protected points enabled** (D-004): `%M4` bypass / `%MW0` read-only named in verdicts; HMI maintenance bypass ALERTs, attacker BLOCKs
- **Experiment 3 captured, both attack paths:**
  - Attack A (HMI web API): `.99` writes `%M4` ON via `POST /services/variable/hmi/1` — bypasses Guardian (port 502 only). Confirms R-004
  - Attack B (direct Modbus): `.99` FC5 `%M4`=1 → Guardian BLOCK UNAUTHORIZED_CHANGE, attributed to `.99`/MAC; Iteration-1 overflow shown (level 87→134 past the 80 stop)
- `tools/plc_lab_client.py` has a guarded `write-coil` (FC5) attack mode (verified vs mock PLC)
- Guardian v0.1 (`guardian/`): decode, policy, hash-chained evidence log, inline proxy, baseline, forensic report. Detection/logging verified on real captures; **inline block verified on loopback/mock only** (S-003)

## In progress
- **IDS → NIPS:** wire the inline proxy so Guardian actually drops the attacker's write on hardware (A-019, A-004, X-001)

## Active blockers
- No inline topology yet (USB-Ethernet 2nd NIC, PLC behind Guardian) — X-001/A-004
- No true mixed Exp-4 capture (authorized + unauthorized Modbus in one file) — A-020
- Attacker `.99` shares `.2`'s MAC, so MAC rules can't separate them — A-021

## Current focus (next session)
- A-019 (inline NIPS block on hardware), A-004 (inline topology), A-020 (mixed Exp-4), A-021 (attacker adapter)
