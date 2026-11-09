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
- Compare guided **grey-box** testing with automated discovery and behavioral inference.

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

**Implementation note:** Define and document the actual PLC variable addresses, HMI tags, reset behavior, simulation update rate, and any independent safety limits alongside the project files in `ICS/`. The network-visible representation of `maint_bypass` must be verified from the deployed PLC/HMI configuration; Modbus TCP does not inherently provide a named-tag listing interface.

## Experiments

The current attacker-side numbering is **EXP_1: Nmap reconnaissance**,
**EXP_2: maintenance-bypass write**, and **EXP_3: PLC discovery and fingerprinting**.
Older Guardian runsheets, captures, and analysis may use earlier experiment
numbers; retain their original names and identify the scenario explicitly when
citing historical evidence.

Before each attack trial, capture normal HMI Start/Stop-at-80%/Reset operation
as a separate baseline and verify the initial bypass state. Reconnaissance is
not part of the normal-operation baseline.

### EXP_1 — Network reconnaissance with Nmap

**Goal:** Identify exposed TCP services on the PLC and HMI and evaluate Guardian's
response to scanning from the attacker workstation.

Use the four documented scan variants, recording the exact command, source
interface/address, privileges, timing, and targets for each trial.
See [EXP_1 run instructions](EXP_1/README.md).

**Evidence:** Nmap output, associated PCAP, UTC timeline, and Guardian alerts.

### EXP_2 — Maintenance-bypass write

**Goal:** Evaluate detection of a direct Modbus TCP write to the lab-only
maintenance bypass, and corroborate any resulting simulated process effect.

The supplied lab client writes coil address `4` (`%M4`) to `1` on
`192.168.8.11:502`. Verify the deployed mapping and initial state, capture the
trial, observe the process, and restore bypass OFF afterward.
See [EXP_2 code and run instructions](EXP_2/README.md).

**Expected observation:** If the vulnerable lab configuration accepts the write
and the simulated fill cycle is active, the level may pass the normal 80% stop
and trigger overload above 100%. Confirm this in PLC/HMI observations.

**Evidence:** Client JSONL log, write response/readback, PCAP, bypass and tank-level
timeline, restoration observations, and Guardian alerts.

### EXP_3 — PLC discovery and fingerprinting

**Goal:** Assess automated service discovery, device identification, address-space
enumeration, and behavioral inference against the known PLC target.

`plc_discovery.py` (supplied as `plc_blackbox_test.py`) probes the PLC's ICS ports,
requests Modbus device identification, reads coils/registers, and infers candidate
signal behavior. It does not perform the EXP_2 bypass write. Supplying a known
target IP makes this a partial black-box assessment.
See [EXP_3 code and run instructions](EXP_3/README.md).

**Evidence:** Console report, enumerated addresses, inference candidates,
unsupported/failed responses, PCAP, and Guardian alert timeline.

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

EXP_2 is **grey-box**: the operator knows the target and bypass mapping. EXP_3
infers exposed address behavior without receiving a register map, but still
receives the target IP and protocol port. A full black-box assessment with no
device addresses or register mappings provided remains a stretch goal. All
modes remain restricted to the explicitly authorized, isolated lab environment.

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
ControlShield/
├── EXP_1/                  # Nmap reconnaissance
│   ├── README.md           # Setup, commands, evidence instructions
│   └── results/            # One UTC-named directory per run
├── EXP_2/                  # Maintenance-bypass write
│   ├── README.md
│   ├── requirements.txt
│   ├── scripts/plc_lab_client.py
│   └── results/
├── EXP_3/                  # PLC discovery and fingerprinting
│   ├── README.md
│   ├── requirements.txt
│   ├── scripts/plc_discovery.py
│   └── results/
├── EXP_4/                  # Detection and prevention validation
├── ICS/                    # PLC program, HMI project, exported configuration
├── PLC_Guardian/           # Guardian application, analysis, historical evidence
├── LaTex/                  # Technical report source and build outputs
├── docs/                   # Proposal and supporting documents
└── README.md
```

Keep `EXP_1`, `EXP_2`, and `EXP_3` as stable folder names; use descriptive README
titles and script names to explain each scenario. For a new project, equivalent
names could be `exp_01_network_reconnaissance`, `exp_02_maintenance_bypass`, and
`exp_03_plc_discovery`. Retaining the existing paths avoids disrupting references.

Each run uses `results/YYYYMMDDTHHMMSSZ/` (UTC). Put commands, UTC start/end times,
source/target addresses, software versions, initial/final PLC state, Guardian
configuration, observations, and evidence paths in a `notes.md` there. Store
captures/logs alongside it or link to central evidence under `PLC_Guardian/`.
Record baseline, detection, and prevention runs distinctly; an alert is not proof
of enforcement. Review generated evidence before committing it. Large PCAPs may
be stored externally with a documented path and checksum.

The experiment scripts are standalone snapshots of the supplied attacker tools.
Guardian's existing `tools/` files and historical evidence remain in place;
changes to one copy do not automatically update another.

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

Python dependencies and attacker commands are documented per experiment.
See [Guardian's README](PLC_Guardian/guardian/README.md) for its own setup and use.

## Evaluation criteria

| Test | Success criterion |
|---|---|
| Baseline prerequisite | Authorized Start/Reset cycle completes with no intrusion alerts |
| EXP_1 | Nmap scan results and associated traffic/Guardian response are recorded per scan variant |
| EXP_2 | Bypass write is captured and classified; process effects and restoration are corroborated |
| EXP_3 | Discovery pipeline output, limitations/failures, and Guardian response are recorded reproducibly |
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
- [ ] Capture and analyze normal-operation baseline and EXP_1 reconnaissance.
- [ ] Implement Guardian detection rules and forensic logging.
- [ ] Validate EXP_2 and EXP_3 in the isolated simulation.
- [ ] Select and verify an EXP_4 enforcement mechanism.
- [ ] Collect measurements, prepare the report, and record the demonstration.

## Disclaimer

ControlShield is an educational ICS cybersecurity project. Its deliberately vulnerable maintenance-bypass scenario is intended only for a controlled virtual process. Detection on a mirrored switch port does not itself provide packet prevention, and network monitoring does not replace independent industrial safety controls.
