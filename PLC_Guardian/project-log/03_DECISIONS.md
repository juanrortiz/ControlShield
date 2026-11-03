# 03 · Decision Log
_Append-only. Never edit a past decision; supersede it with a new one and mark the old one "Superseded by D-###"._

Status values: Proposed · Accepted · Superseded · Rejected

---

## D-001 · Use a project log kit to track the group project
- **Date / session:** 2026-10-21 · S-001
- **Status:** Accepted
- **Context:** Team project with multiple contributors and deadlines; needs traceable progress, decisions and open items for the final report.
- **Options considered:**
  1. Ad-hoc notes / chat history: no setup, but lossy and hard to report from
  2. Structured log files updated by Claude Code each session: small upfront setup, full paper trail
- **Decision:** Option 2.
- **Rationale:** The session log and decision log feed directly into the final report's methodology section.
- **Consequences:** End each work session with "close session".
- **Approved / informed:** David

---
<!-- Template
## D-### · <short title>
- **Date / session:** YYYY-MM-DD · S-###
- **Status:** Accepted
- **Context:**
- **Options considered:**
  1.
  2.
- **Decision:**
- **Rationale:**
- **Consequences:**
- **Approved / informed:**
-->

## D-002 · Python replaces C as the core Guardian implementation language
- **Date / session:** 2026-10-21 · S-002
- **Status:** Accepted
- **Context:** The brief named C for the analysis tool; the team wants faster development and a demo-ready tool.
- **Options considered:**
  1. Python prototype, port the parser to C later
  2. Python as the official core tool
- **Decision:** Option 2.
- **Rationale:** One codebase covers the parser, policy, evidence log, inline proxy and forensic report; it runs on Windows and Linux.
- **Consequences:** The brief/report must say the tool is in Python; the C requirement is superseded.
- **Approved / informed:** David

## D-003 · Blocking via an inline Modbus/TCP proxy
- **Date / session:** 2026-10-21 · S-002
- **Status:** Accepted
- **Context:** A mirror/SPAN port can only detect. The brief requires real prevention for Iteration 2.
- **Options considered:**
  1. Inline Modbus proxy on Guardian
  2. Switch-assisted port shutdown
  3. Log-only
- **Decision:** Option 1.
- **Rationale:** Real prevention in pure Python, with no dependency on the switch model. `enforcement.mode` toggles monitor (Iteration 1) and block (Iteration 2).
- **Consequences:** The PLC must be reachable only through Guardian (second NIC); this is fail-closed. Physical topology still to be confirmed.
- **Approved / informed:** David

## D-004 · Enable the `%M`/`%MW0` protected points; HMI maintenance bypass alerts, not blocks
- **Date / session:** 2026-10-21 · S-005
- **Status:** Accepted (resolves A-013)
- **Context:** The register map is confirmed on the wire. Without protected points, Guardian catches an unauthorized `%M4` write only as "unknown source," not as the bypass. The HMI legitimately turns `%M4` ON for maintenance.
- **Options considered:**
  1. Enable protected points; authorized out-of-range writes ALERT only (`block_out_of_range_from_authorized=false`)
  2. Enable and block even authorized out-of-range writes
  3. Leave protected points disabled (source-allowlist only)
- **Decision:** Option 1. Protected points enabled in `guardian/config.json`: `%M2/%M3/%M5` 0..1, `%M4` 0..0, `%MW0` read-only.
- **Rationale:** Names the attack (`VALUE_OUT_OF_RANGE: %M4 bypass`) and protects the computed tank level (`%MW0` read-only), while letting the HMI perform real maintenance (its bypass ALERTs, isn't blocked). An unauthorized source is still BLOCKed by the source rule regardless.

## D-005 · Add a black-box Experiment 5 alongside the gray-box Experiments 3/4
- **Date / session:** 2026-11-02
- **Status:** Accepted
- **Context:** Experiments 3 and 4 were gray-box — the attacker (`.99`) already knew the register map (`%M4` maintenance bypass, `%MW0` tank level) from `06_REFERENCE.md` before attacking. The team wants a test where the attacker starts from only the PLC's IP, to see whether Guardian still detects/attributes the activity and whether the attacker can rediscover the map on its own.
- **Options considered:**
  1. Reuse the gray-box attack script with no map knowledge fed in. Rejected — doesn't exercise real discovery tooling.
  2. Build a discovery → enumeration → inference pipeline: nmap for port/service discovery (matches how a real external attacker recons), then a read-only pymodbus sweep and classification stage for the Modbus-specific inference.
- **Decision:** Option 2, implemented as `tools/plc_blackbox.py` (adapted from a reference script). Read-only only — no FC5/FC6/FC15/FC16 write probing is in scope; a write-capable black-box test needs its own decision. Runs only against the lab PLC (`192.168.8.11`) on the isolated lab network, by the team, per the evidence/attack-testing rules (CLAUDE.md; D-003, D-004).
- **Rationale:** Matches the brief's forensics focus — contrasting gray-box and black-box attacker knowledge is a stronger report finding than gray-box alone, and nmap-based discovery is realistic attacker tradecraft.
- **Consequences:** New action A-022 (run Experiment 5: capture with `wireshark-capture`, hash + inventory, analyze with Guardian, compare the discovered map against `06_REFERENCE`'s known map).
- **Open question:** whether the black-box run goes through the inline proxy (depends on A-019/A-004, not yet built) or only the port mirror — defaults to port-mirror until the inline topology exists.
- **Approved / informed:** David
- **Consequences:** `%MW1` left unprotected until its meaning is known. If the team wants authorized bypass blocked too, flip `block_out_of_range_from_authorized`.
- **Approved / informed:** David
