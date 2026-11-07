# 01 · Status
_State file. Rewritten at each session close. CAP: one screen. Last updated: S-006 · 2026-11-02_

## Current milestone
M1: Baseline capture and Modbus understanding · ~95%
M2: Guardian working end-to-end on lab hardware — **IDS done, NIPS (inline block) next**

## What works now
- Port mirroring PLC → Guardian verified live (S-005); captures hashed in `06_REFERENCE`. **Physical port map changed (S-006): PLC=switch port 2, HMI=3, attacker=4, Guardian/capture=5 (was 4→5) — a switch reconfig silently broke mirroring for ~40 min (I-007, resolved); always sanity-check before trusting a capture**
- PLC `.11:502` (units 1/255); HMI `.10`; team HMI laptop `.2` (updated project, allowlisted); attacker `.99`. Register map `%M2`–`%M5`, `%MW0` in `06_REFERENCE`
- **Guardian fixes 1–4 applied** (A-011): unit 255, FC90 0x74 as read, FC90 signature, `.pcap` link-type → PM3 150/150 ALLOW
- **Protected points enabled** (D-004): `%M4` bypass / `%MW0` read-only named in verdicts; HMI maintenance bypass ALERTs, attacker BLOCKs
- **Experiment 3 captured, both attack paths:**
  - Attack A (HMI web API): `.99` writes `%M4` ON via `POST /services/variable/hmi/1` — bypasses Guardian (port 502 only). Confirms R-004
  - Attack B (direct Modbus): `.99` FC5 `%M4`=1 → Guardian BLOCK UNAUTHORIZED_CHANGE, attributed to `.99`/MAC; Iteration-1 overflow shown (level 87→134 past the 80 stop)
- `tools/plc_lab_client.py` has a guarded `write-coil` (FC5) attack mode (verified vs mock PLC)
- Guardian v0.1 (`guardian/`): decode, policy, hash-chained evidence log, inline proxy, baseline, forensic report. Detection/logging verified on real captures; **inline block verified on loopback/mock only** (S-003)
- **A-016 fixed (S-006):** forensic report §3/§4/§6 use effective category (FC90 0x74 polls no longer count as changes), new §4 authorized-source ALERT/BLOCK subsection; proxy SESSION_END now survives SIGTERM/SIGBREAK via a cancellable task, not a raised exception. Architect PASS (round 2). Residual edge cases (SIGINT unprotected, possible shutdown hang with a live client) open as I-006/A-023
- **A-014 done (S-006):** `Port_Mirroring_Baseline.pcapng` (1066 frames, clean: unit 255, FC1/3/90 only, no writes) and `Port_mirroring_test_2.pcapng` (1630 frames, one FC15 pair) now in `captures/`, hashed; `baseline_port_mirroring.json` generated from the clean one. Inventory rows + duration/scenario still need adding to `06_REFERENCE` (dates/captured-by `[UNVERIFIED]`)
- **A-012 (I-004):** no write traffic found near any `%M4` toggle in `Port_mirroring_test_3.pcapng`; toggle intervals aren't a fixed period. Inferred, not confirmed: `%M4` is driven locally on the PLC (physical input / local program action), not over the network. Undecidable from this capture alone
- **A-018:** still `[UNVERIFIED]`. Kaspersky's UMAS writeup confirms the 0x5A/session/function framing and 0xFE/0xFD status convention, but documents no function/subfunction `0x74` and nothing about the trailing reply byte
- **D-005 / A-022:** black-box Experiment 5 decided and scripted (`tools/plc_blackbox.py` — nmap discovery + read-only pymodbus sweep/inference, no writes). Not yet run against the lab PLC
- **A-020 done (S-006):** `mixed_hmi_attacker_2026-11-02.pcapng` (2047 fr., 23.3s) has HMI `.10` ALLOW reads and `.99`'s FC5 `%M4` attack (UNAUTHORIZED_CHANGE, BLOCK) in one window. Forensic report in `analysis/`. Cleanup (rename, cite in report) → A-024
- **New point `%M6`/DIGI_OVERLOAD — RESOLVED (S-006):** `%Q0.2`/TANK_OVERLOAD (real ladder-logic output, `ControlShield_PLC.pdf` Rung4) was never mapped to a Modbus-addressable point (its Network Objects table was empty); team duplicated the same overload condition onto a new memory bit `%M6`, which — like `%M2`–`%M5` — needs no extra Modbus mapping. Confirmed live two ways after redownload: capture `q0.2_m6_overload_confirm_2026-11-02.pcapng` (coil 6 turns on within 21ms of `%MW0` crossing 100) and an independent direct FC1 poll (`set_coils=[3,4,6]` at level=109). Added to `guardian/config.json` as a read-only protected point; PM3 regression still 150/150 ALLOW. `%Q0.2` itself still drives a physical lamp on the PLC but is not confirmed Modbus-reachable — not needed now that `%M6` works

## In progress
- **IDS → NIPS:** wire the inline proxy so Guardian actually drops the attacker's write on hardware (A-019, A-004, X-001)

## Active blockers
- No inline topology yet (USB-Ethernet 2nd NIC, PLC behind Guardian) — X-001/A-004
- Attacker `.99` shares `.2`'s MAC, so MAC rules can't separate them — A-021

## Current focus (next session)
- A-019 (inline NIPS block on hardware), A-004 (inline topology), A-021 (attacker adapter), A-022 (run black-box Experiment 5), A-023 (I-006 signal-handling edge cases), A-024 (mixed-capture cleanup)
