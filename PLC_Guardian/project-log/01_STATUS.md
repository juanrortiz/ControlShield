# 01 · Status
_State file. Rewritten at each session close. CAP: one screen. Last updated: S-007 · 2026-11-10_

## Current milestone
M1: Baseline capture and Modbus understanding · ~95%
M2: Guardian detection working end-to-end on lab hardware. True inline blocking (D-003) still deferred (hardware, A-004). **Two reactive compensating controls now demonstrated working live against real hardware**: D-007 (Modbus-side lockout, since S-006) and D-009 (HTTP-side lockout, this session) — same `%M7` lockout mechanism, two independent trigger paths. D-008 (inline HTTP gate, connection-level) is architect-PASSed and code-correct but **not yet in the real traffic path** (A-033, confirmed empirically this session).

## What works now
- PLC `.11:502` (units 1/255, switch port 2); HMI `.10:80` (port 3, also now mirrored for `http_watch`); attacker `.99` (port 4, shares `.2`'s MAC — A-021); team laptop `.2` (allowlisted, full read/write/config); Guardian/capture host `.50` (port 5, MAC corrected A-029). Register map `%M2`–`%M7`, `%MW0` in `06_REFERENCE`
- **D-007 + D-009, both demonstrated live this session/last:** an unauthorized Modbus write OR an unauthorized HTTP connection to the HMI both trigger Guardian's own FC5 lockout write to `%M7`, independently confirmed by packet capture cross-correlated to the microsecond against Guardian's evidence log. D-009's first live test failed once (`active_response` timeout) — traced to the operator's own host IP being misconfigured, not a code defect; three subsequent fires all SUCCEEDED. Cooldown mechanism validated under real sustained load for the first time: a 1682-request black-box scan produced only 5 actual lockout writes, not 1682 (A-022/Experiment 5)
- **D-008 (`httpgate.py`):** connection-level inline gate for the HMI's port 80, partial mitigation for R-004. Architect review: round 1 FAIL (2 blockers), round 2 FAIL (1 blocker), round 3 **PASS**. Not yet in the real traffic path — `.99` hitting the HMI directly during live testing bypassed it completely, confirming A-033 (HMI-side inline topology) is still the real gap, same as A-004 for the Modbus leg
- Black-box discovery tool (open PR, `plc_blackbox_test.py`) confirmed good both by code review and by live capture: zero writes across 1682 real reads against the PLC, exactly the documented fingerprint → port-scan → enumeration sequence
- Switch mirror (TL-SG105E) now mirrors **both** Port 2 (PLC) and Port 3 (HMI) → Port 5 (Guardian) — a second occurrence of the switch's silent mirror-config-loss failure mode happened and was resolved this session (I-010); the switch needs a full Port-Mirror disable→re-enable toggle to reliably commit changes, not just editing the port list
- Guardian's evidence-log locking reworked to a sidecar file (`path + ".lock"`), fixing a Windows read-blocking issue found during D-008's review rounds
- Project pushed to GitHub: `MetalStarfish24/plc-guardian` main branch, commit `8d10ecc` (101 files, D-007 live confirmation through tonight's work); PR #2 (open, unmerged) still pending on the team's shared `juanrortiz/ControlShield` repo

## In progress
- **A-033 (HTTP-leg inline topology):** same category of problem as A-004 — needs the HMI reachable only through Guardian's gate. Not started; two options identified (ARP-based redirection vs. an IP-allowlist setting on the HMI's own admin UI, not yet checked)
- **True inline prevention (D-003, A-004/A-019):** unchanged from S-006 — still needs the PLC re-cabled onto Guardian's 2nd NIC

## Active blockers
- No inline topology for either leg yet (Modbus: X-001/A-004/A-019; HTTP: A-033)
- A-031 (active-response Modbus-side hardening residuals), A-035 (http_watch residuals), A-036 (config validation hardening) — all open, none blocking current results
- Three new captures not yet moved into `captures/` — blocked for Claude by the `.pcapng` write deny rule (A-037), needs a manual copy
- Two pre-D-006 evidence files still not found locally (A-026)
- Attacker `.99` shares `.2`'s MAC (A-021)

## Current focus (next session)
- A-033 (HTTP inline topology — check the HMI's own admin UI for an IP-allowlist option before reaching for ARP redirection)
- A-037 (move the 3 pending captures into `captures/`)
- A-031/A-035/A-036 (hardening residuals, not urgent but needed before calling those controls "finished" for the report)
- A-004/A-019 (Modbus inline topology, for the three-way before/after/inline comparison)
