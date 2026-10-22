# ControlShield: Intrusion Detection and Prevention System

**ECE4311 — PLC Network Forensics | Group 7**

ControlShield is a laboratory-scale industrial control system (ICS) security and network-forensics project. It uses a Schneider Electric TM221CE24T PLC, an HMIS5T HMI, a TP-Link TL-SG105E managed switch, and a Windows-based **PLC Guardian** to study normal operation, unauthorized network activity, intrusion detection, and prevention.

The simulated process is a **water storage tank**. During normal operation, an operator starts the fill cycle through the HMI, and the PLC stops filling when the tank reaches **80%**. A deliberately introduced, lab-only `maint_bypass` variable represents a vulnerable maintenance override. The attack scenarios investigate whether unauthorized network access can change this variable and produce a **simulated** high-level/overload event. No real pump, valve, or water plant is required.

> **Safety and scope:** All tests are authorized and confined to an isolated lab network. The overload is a simulated process state, not a command to damage physical equipment. Keep independent safety interlocks active if any real outputs are connected. Do not expose the HMI diagnostic portal or PLC services to public or campus production networks.

## Objectives

- Establish a baseline of normal HMI-to-PLC communication.
- Capture and analyze traffic associated with operator actions and PLC state changes.
- Investigate unauthorized discovery of HTTP and Modbus TCP services.
- Detect suspicious access and unauthorized changes to the maintenance-bypass state.
- Record timestamps, source/destination addresses, protocol activity, alerts, and PCAP evidence.
- Evaluate prevention controls and reconstruct the sequence of events from forensic evidence.
- Compare guided **grey-box** testing with a future **black-box** assessment.

## Hardware and network topology

| Component | Model / platform | IP address | Switch port | Role |
|---|---|---|---|---|
| PLC | Schneider Electric TM221CE24T | `192.168.8.11` | 2 | Tank control and simulated process logic |
| HMI | Schneider Electric HMIS5T | `192.168.8.10` | 3 | Operator controls and HTTP diagnostic portal |
| Attacker workstation | Authorized lab test machine | `192.168.8.99` | 4 | Controlled adversarial testing |
| PLC Guardian | Windows computer | `192.168.8.50` | 5 | IDS, traffic capture, forensics, and prevention orchestration |
| Switch | TP-Link TL-SG105E, 5-port managed | Management IP: TBD | — | Connectivity and traffic mirroring |

```text
                     TP-Link TL-SG105E
                      Managed Switch
                  +--------------------+
                  | Port 1: Available  |
                  | Port 2: PLC        |---- 192.168.8.11 (TM221CE24T)
                  | Port 3: HMI        |---- 192.168.8.10 (HMIS5T)
                  | Port 4: Attacker   |---- 192.168.8.99 (Test PC)
                  | Port 5: Mirror dst |---- 192.168.8.50 (PLC Guardian)
                  +--------------------+
```

**Traffic monitoring:** Configure switch port mirroring so that relevant traffic from ports **2, 3, and 4** is copied to destination port **5**, subject to the TL-SG105E's firmware and mirroring capabilities. Verify that bidirectional PLC/HMI and attacker traffic is visible in Wireshark; mirror settings and oversubscription can affect completeness. If port 5 is used as a mirror destination, confirm whether it can simultaneously provide ordinary management connectivity. A separate management interface may be necessary.

**Prevention limitation:** Port mirroring is passive. A Guardian connected only to the mirror destination **cannot drop packets already being forwarded between ports 2–4**. Experiment 4 requires a verified enforcement path (for example, supported switch port controls, a firewall, or an inline gateway). Do not claim successful NIPS blocking until the control has been implemented and tested. Confirm the exact switch hardware revision, firmware, and supported features before choosing the enforcement mechanism.

## Simulated water tank

The PLC maintains a simulated tank level and pump state. The HMI provides the operator's **Start** and **Reset** controls. Under normal operation, filling stops at **80%**. The `maint_bypass` variable is deliberately included as an experimental vulnerability and is not an appropriate production safety design.

| State or event | Expected lab behavior |
|---|---|
| Operator presses Start | Simulated fill cycle begins |
| Tank reaches 80%, bypass disabled | PLC stops the simulated pump |
| Operator presses Reset | Simulation returns to its defined initial state |
| `maint_bypass` enabled | Demonstration logic bypasses the normal 80% stop condition |
| Simulated level exceeds 100% | An **overload** alarm/event is recorded; no physical overflow occurs |

**Implementation note:** Define and document the actual PLC variable addresses, HMI tags, reset behavior, simulation update rate, and any independent safety limits in `PLC/`. The network-visible representation of `maint_bypass` must be verified from the deployed PLC/HMI configuration; Modbus TCP does not inherently provide a named-tag listing interface.

## Experiments

### EXP_1 — Normal operation and baseline

**Goal:** Characterize authorized operation without raising intrusion alerts.

1. Start a packet capture on PLC Guardian.
2. Use the HMI to start the virtual water tank filling process.
3. Observe the PLC stop filling at **80%**.
4. Reset the process using the HMI.
5. Record the expected IPs, ports, protocols, communication patterns, and process events.
6. Confirm that Guardian reports **no intrusion** for this authorized sequence.

**Evidence:** Baseline PCAP, operator action timeline, PLC state log, and Guardian results.

### EXP_2 — Guided discovery and maintenance-bypass scenarios

**Goal:** Evaluate detection of unauthorized reconnaissance and attempted changes to the lab-only maintenance bypass.

Two controlled entry paths are evaluated:

- **HTTP diagnostic portal:** From the authorized test workstation, assess the exposed HMI diagnostic service on TCP **80**. Record service discovery, access attempts, and whether the deliberately configured lab interface permits a maintenance-bypass change.
- **Modbus TCP:** Assess the PLC's TCP **502** service and evaluate an authorized, lab-scoped test of access to the documented maintenance-bypass register. Correlate any attempted state change with Guardian alerts and the simulated tank behavior.

The attacker has limited prior knowledge of the environment (grey-box). Service discovery can be performed with Nmap within the isolated lab. Any Modbus register mapping must come from the test configuration or a separately documented discovery mechanism; a generic Modbus script cannot automatically enumerate arbitrary PLC tag names.

**Expected observation:** If the vulnerable lab configuration accepts the unauthorized bypass change, the simulated tank may exceed the 80% threshold and trigger the overload event above 100%. Guardian should capture the relevant traffic and flag the unauthorized activity. Keep physical outputs isolated.

**Evidence:** Discovery results, relevant PCAP, bypass state transition, tank-level timeline, and alerts.

### EXP_3 — Automated attack-chain simulation

**Goal:** Assess whether Guardian detects a repeatable automated sequence of discovery, unauthorized bypass-change attempt, and simulated process impact.

A lab test harness performs the same approved sequence used in EXP_2, with clear start/end timestamps and no attempts outside the isolated test subnet. Record each stage separately: service discovery, control-change attempt, resulting process state, and Guardian detection.

**Evidence:** Test-harness logs, PCAP, Guardian alert timeline, and simulated overload result. Automation should be repeatable and rate-limited to avoid destabilizing the PLC or HMI.

### EXP_4 — Intrusion detection and prevention

**Goal:** Demonstrate Guardian classification and enforcement against unauthorized HTTP and Modbus TCP access.

1. Define an allowlist for authorized HMI/PLC and engineering communications.
2. Detect unapproved sources attempting to reach the HMI's TCP **80** service or the PLC's TCP **502** service.
3. Generate alerts with source/destination IP, port, timestamp, and supporting PCAP reference.
4. Apply blocking through a **separate, verified enforcement point**; the mirrored monitoring port alone is insufficient.
5. Re-run authorized operator activity and unauthorized test attempts.
6. Verify that authorized HMI-to-PLC operation still works and that blocked requests fail at the enforcement point.

**Evidence:** Before/after PCAPs, alert logs, enforcement logs, and successful authorized-operation tests.

## Grey-box and black-box testing

The primary assessment is **grey-box**: the test operator knows basic information about the environment but must discover exposed services and validate the attack surface. A **stretch goal** is a black-box assessment in which the operator receives no device addresses, service information, or register mappings in advance. Both modes remain restricted to the explicitly authorized, isolated lab environment.

## PLC Guardian design

```text
Mirrored traffic / PCAP
         |
         v
Packet capture and protocol parsing
         |
         v
Baseline and detection rules
  |-- Expected HMI/PLC communication
  |-- Unknown or unauthorized source
  |-- Unexpected HTTP/Modbus access
  |-- Suspicious control-change attempt
         |
         +--> Event logs and forensic PCAPs
         |
         +--> Alerts and dashboard
         |
         +--> Enforcement controller --> Verified switch/firewall/gateway
```

The IDS should not infer a successful PLC state change from a network connection alone. Correlate packet evidence with PLC/HMI state logs, application events, or an explicitly documented register readback. Distinguish **detected**, **attempted**, **accepted**, and **blocked** events in reports.

### Suggested detection fields

- Timestamp and experiment ID
- Source/destination IP and TCP port
- Protocol and event classification
- Authorized/unauthorized source status
- Observed process-state change (when independently confirmed)
- Alert severity and enforcement outcome
- Associated PCAP filename and evidence notes

## Repository layout

```text
ControlShield-Intrusion-Detection-and-Prevention-System/
├── ControlShield/          # Guardian IDS/NIPS application and configuration
├── docs/
│   └── ECE4311 - Group 7 Project Proposal.pdf
├── EXP_1/                  # Normal-operation baseline and captures
├── EXP_2/                  # HTTP/Modbus discovery and bypass tests
├── EXP_3/                  # Automated lab attack-chain tests
├── EXP_4/                  # Detection and prevention validation
├── LaTex/                  # Technical report source and build outputs
├── PLC/                    # PLC program, HMI configuration, tag map
└── README.md
```

Recommended per-experiment artifacts include a short procedure, capture files, timestamps, test results, and screenshots or exported logs. Avoid committing passwords, credentials, or sensitive device configurations. Large PCAPs and generated LaTeX build artifacts may be better excluded from Git and referenced through documented storage locations.

## Tools

| Tool | Purpose |
|---|---|
| EcoStruxure Machine Expert – Basic | TM221CE24T programming and observation |
| Vijeo Designer v6.2.12.2102| Operator controls and diagnostic-service configuration |
| Wireshark / TShark | Packet capture and protocol analysis |
| Python | Guardian detection, logging, and test harnesses |
| Nmap | Authorized lab service discovery |
| Git | Version control and experiment documentation |
| LaTeX | Final technical report |

The exact HMI software, Python dependencies, and Guardian startup commands will be added after the implementation is committed.

## Evaluation criteria

| Test | Success criterion |
|---|---|
| EXP_1 | Authorized Start/Reset cycle completes with no intrusion alerts |
| EXP_2 | Discovery and bypass attempts are captured and classified; process effects are corroborated |
| EXP_3 | Automated sequence produces a reproducible, timestamped forensic trail |
| EXP_4 | Unauthorized requests are blocked by a verified enforcement point while authorized control continues |

Additional measurements: detection latency, false positives, false negatives, packet-capture completeness, and prevention reliability.

## Project deliverables

In accordance with the project proposal:

1. **Ten-minute demonstration video** showing network architecture, baseline, authorized/unauthorized activity, detection, blocking where feasible, and forensic investigation.
2. **Source code and Git repository** containing Guardian code, configuration, test materials, and documentation.
3. **Technical report** describing design, implementation, experimental results, evidence, limitations, and future work.

## Current status and next steps

- [x] PLC, HMI, attacker workstation, and Guardian assigned lab IP addresses and switch ports.
- [x] TP-Link TL-SG105E managed switch selected.
- [ ] Verify mirror configuration and bidirectional capture on port 5.
- [ ] Commit PLC/HMI simulation code and a documented tag/register map.
- [ ] Capture and analyze EXP_1 baseline.
- [ ] Implement Guardian detection rules and forensic logging.
- [ ] Validate EXP_2 and EXP_3 in the isolated simulation.
- [ ] Select and verify an EXP_4 enforcement mechanism.
- [ ] Collect measurements, prepare the report, and record the demonstration.

## Disclaimer

ControlShield is an educational ICS cybersecurity project. Its deliberately vulnerable maintenance-bypass scenario is intended only for a controlled virtual process. Detection on a mirrored switch port does not itself provide packet prevention, and network monitoring does not replace independent industrial safety controls.
