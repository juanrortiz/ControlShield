# 00 · Project Brief: PLC Guardian
_Reference file. Edit rarely. Last updated: S-001_

## Goal
Capture, analyze and monitor HMI ↔ PLC network traffic for a Schneider M221 PLC running an HMI-driven simulated process, and detect abnormal or malicious activity using network forensics techniques.

## Course
ECE4311 · Network Forensics · Cal Poly Pomona · Term: [fill in] · Instructor: [fill in]

## Team
| Name | Role / focus | Contact |
|---|---|---|
| David Jessup | [fill in] | |
| [teammate] | | |
| [teammate] | | |

## Deliverables & deadlines
| Deliverable | Due | Owner | Notes |
|---|---|---|---|
| [proposal / checkpoint] | | | |
| [final report] | | | |
| [presentation / demo] | | | |

## In scope
- Wireshark capture of HMI ↔ PLC traffic (Modbus TCP)
- Baseline of normal traffic; identification of anomalies
- Detection approach: PLC Guardian (D-002), a Python tool with rule-based policy detection (source allowlist, protected-point value/read-only rules, FC90 signature checks), a hash-chained evidence log, and inline blocking via a Modbus/TCP proxy (D-003) — monitor mode (Iteration 1) and block mode (Iteration 2)
- Gray-box (Experiments 3–4, register map known) and black-box (Experiment 5, D-005, `tools/plc_blackbox.py`) attacker scenarios

## Out of scope
- Anything outside the isolated lab network
- [fill in]

## Success criteria (how the project is graded / judged done)
- [fill in from the assignment rubric]

## Constraints
- Lab hardware access: [when/where]
- Tools allowed: Wireshark (tshark/dumpcap/capinfos), Python 3 + pymodbus/scapy, nmap (Experiment 5 discovery), [fill in anything course-specific]
