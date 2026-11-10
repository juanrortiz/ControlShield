# EXP_4 — Intrusion detection and prevention

**Goal:** Demonstrate Guardian classification and enforcement against unauthorized
HTTP (HMI, TCP 80) and Modbus TCP (PLC, TCP 502) access.

Unlike EXP_1–EXP_3 (attacker-side scripts with a single run procedure), EXP_4 is
Guardian's own detection/response pipeline, built and validated over several
sessions. The authoritative build history, architect-review record, and
evidence citations live in `PLC_Guardian/project-log/` (decision records
D-007/D-008/D-009, session logs S-006/S-007) and `PLC_Guardian/analysis/`.
This README summarizes what was actually built and demonstrated; it is not a
run-once script like the other experiments.

## Why two controls instead of one inline gateway

True inline blocking (`D-003`) needs Guardian physically in the traffic path on
both legs — a second NIC ahead of the PLC (Modbus, `A-004`/`A-019`) and the HMI
reachable only through a gate (HTTP, `A-033`). Neither is wired yet: both
remain open items. In the meantime, Guardian implements a **reactive
compensating control** on each leg — it can't drop the attacker's packet, but
it detects the unauthorized write/connection and asserts a PLC-side lockout
coil (`%M7`/PLCGUARD) within milliseconds, independent of the attack's trigger
path.

| Leg | Trigger | Module | Status |
|---|---|---|---|
| Modbus (PLC, 502) | Unauthorized FC5/6/15/16/23 write | `active_response.py` (D-007) | Demonstrated live on hardware (S-006) |
| HTTP (HMI, 80) | Unauthorized TCP connection, passive | `http_watch.py` (D-009) | Demonstrated live on hardware (S-007) |
| HTTP (HMI, 80) | Connection-level inline gate | `httpgate.py` (D-008) | Architect-PASSed, code-correct, **not yet in the real traffic path** — bypassed when the attacker hits the HMI directly (A-033) |

## What was demonstrated

- **Modbus lockout (D-007):** attacker `.99` writes `%M4` directly to the PLC;
  Guardian's `active_response` detects the unauthorized write and asserts
  `%M7` in ~6ms, holding the tank level flat despite `%M4` staying ON.
  Evidence: `exp3_active_response_success_2026-11-04.pcapng` vs.
  `exp3_no_inline_baseline_2026-11-04.pcapng` (no lockout, level overflows).
- **HTTP lockout (D-009):** attacker `.99` opens a TCP connection to the HMI's
  port 80; the passive `http_watch` sniffer fires `active_response`'s same
  lockout coil. Confirmed live 3× with the SYN-to-lockout-write latency
  cross-correlated to the microsecond against Guardian's own evidence log
  (~54ms). Evidence/write-up: `PLC_Guardian/analysis/S-007_port80_ips_live_test.md`.
- **Cooldown under sustained load:** a 1682-request black-box discovery scan
  (EXP_3) produced only 5 real lockout writes, not 1682 — `active_response`'s
  cooldown correctly suppressed 1677 duplicate triggers. Evidence/write-up:
  `PLC_Guardian/analysis/S-007_blackbox_discovery_live_test.md`.
- **Inline HTTP gate (D-008):** `httpgate.py` is a connection-level relay for
  the HMI's port 80 (authorizes by source IP, no HTTP parsing), architect-
  reviewed to a clean PASS over 3 rounds. When actually placed in the traffic
  path it works; the live test confirmed it does **not** yet sit in that path
  — `.99` reached the HMI directly, bypassing it. This is the same gap D-003
  has on the Modbus leg, now also open for the HTTP leg (`A-033`).

## Evidence

Guardian's own hash-chained evidence log (`guardian/logs/*.jsonl`, each entry
chained by SHA-256) plus packet captures cross-correlated frame-by-frame
against it. See the forensic write-ups in `PLC_Guardian/analysis/` for exact
frame numbers, filters, and timestamps; `PLC_Guardian/project-log/06_REFERENCE.md`
for the capture inventory and hashes.

## Known gaps

- Neither leg has true inline enforcement yet (`A-004`/`A-019` for Modbus,
  `A-033` for HTTP) — both controls today are reactive, not preventive.
- Hardening residuals tracked but not blocking: `A-031` (Modbus active-response),
  `A-035` (HTTP watch), `A-036` (config validation).
