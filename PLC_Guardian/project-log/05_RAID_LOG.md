# 05 · RAID Log
_Risks · Assumptions · Issues · Dependencies. Append rows; change only the Status cell of existing rows._

## Risks
| ID | Risk | Likelihood | Impact | Mitigation | Owner | Status |
|---|---|---|---|---|---|---|
| R-001 | Limited lab time with the physical PLC/HMI delays captures | M | H | Capture several scenarios per lab visit; keep a capture plan ready | Team | Open |
| R-002 | Inline Guardian is fail-closed: a crash or misconfig stops HMI↔PLC traffic during the demo | M | H | Rehearse; keep a direct-cable fallback; `monitor` mode as safe default | Team | Open |
| R-003 | Inaccurate host clock weakens forensic timeline | M | M | Sync Guardian/capture host time before each lab session; note clock source in report | Team | Open |
| R-004 | HMI web API (`.10:80`, `/services/variable/hmi/...`) is a path to the process that Guardian (port 502 only) doesn't see; if it accepts writes, an attacker can change the PLC through the HMI | M | H | Check whether the web API can write (A-017); if yes, monitor/restrict port 80 to the HMI or note as a limitation | Team | **CONFIRMED (S-005, `Experiment3_capture.pcapng`): `.99` scanned the HMI, found port 80 open, and wrote `%M4` maintenance bypass ON via `POST /services/variable/hmi/1  action=change&newVal=1` (fr. 1549, 18:35:12 PDT). Guardian logged 0 PLC requests — the attack never touched `.11:502`. A PLC-port monitor cannot see HMI-mediated attacks. Report this as a limitation + recommend monitoring/locking the HMI web API. See `claude/experiment3-findings.md`** |

## Assumptions
| ID | Assumption | How we'll confirm | Status |
|---|---|---|---|
| AS-001 | HMI ↔ PLC traffic is Modbus TCP on port 502 | Check captures with filter `tcp.port == 502` / `mbtcp` | Confirmed: HMI .10 → PLC .11:502, FC1/90/3, unit 255 (`Port_mirroring_test_3.pcapng` fr. 2–7, S-003) |
| AS-002 | M221 engineering traffic uses FC 90 with UMAS-like sub-codes | Capture a Machine Expert Basic connect/download | Open. Note: the HMI also uses FC 90 (sub 0x74) as a routine poll (`Port_mirroring_test_3.pcapng` fr. 4/5), so FC 90 ≠ engineering by itself |

## Issues
| ID | Issue | Impact | Owner | Opened | Status / resolution |
|---|---|---|---|---|---|
| I-001 | `test_connection.pcapng` contains only HTTP (.50↔HMI .10:80), no Modbus | No HMI↔PLC baseline yet | Team | S-002 | Partly resolved S-003: HMI↔PLC Modbus captured in `Port_mirroring_test_3.pcapng`, but in bypass/overflow state; clean baseline still A-006/A-014 |
| I-002 | Guardian v0.1 flags all normal HMI traffic: unit ID 255 not allowed (100 ALERT) and the FC 90 0x74 poll treated as config (50 BLOCK); in block mode the proxy blocks the HMI's poll | Iteration 2 demo breaks the HMI | David | S-003 | Open → A-011. Fix tested: 150/150 ALLOW (`guardian/test_runs/port_mirroring_test_3/`) |
| I-003 | Guardian v0.1 decodes classic `.pcap` files as raw bytes → 0 requests, "No unauthorized activity" | Silent false negative in forensics (Exp. 4) | David | S-003 | Open → A-011. One-line fix tested |
| I-004 | `%M4` (maintenance bypass) toggles 6 times in `Port_mirroring_test_3.pcapng` with no Modbus write on the wire | Cause unknown; local/physical changes are invisible to Guardian | Team | S-003 | Open → A-012 |
| I-005 | Forensic report: §6 lists the HMI's FC 90 polls as "authorized changes"; a BLOCK from an authorized source shows only in the timeline, not §4 Findings; proxy writes no SESSION_END on SIGTERM | Noisy/incomplete Exp. 4 report | David | S-003 | Open → A-016 |

## Dependencies
| ID | Depends on | For | Owner | Status |
|---|---|---|---|---|
| X-001 | USB-Ethernet adapter for Guardian | Inline blocking (D-003) | Team | Open |
| X-002 | PLC logic + register map | Value-range rules, Exp. 1–3 | Team | Open |
