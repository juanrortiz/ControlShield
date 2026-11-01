# 07 · IEEE Report Notes
_Working material for the final IEEE-format report. Add as results come in; keep evidence citations (file, frames, filter). Last updated: S-004 · 2026-10-21_

Legend: **[CONFIRMED]** backed by a capture/test cited here · **[PENDING]** waiting on an experiment · **[UNVERIFIED]** assumption to check · **[VERIFY]** reference details to confirm before citing.

Format target: IEEE conference template (two-column, 10 pt Times), sections numbered with Roman numerals, numbered references in order of first citation [n]. Template: IEEE "Manuscript Templates for Conference Proceedings" (LaTeX `IEEEtran` or Word). [VERIFY: confirm the instructor wants conference vs. journal style and the page limit; brief A-001]

---

## Title (draft options)
- "PLC Guardian: Network-Based Detection, Forensic Logging and Inline Blocking of Unauthorized Modbus/TCP Commands"
- "Network Forensics for an Industrial Control System: Monitoring and Protecting a Schneider M221 PLC"

## Authors
David Jessup, [teammates] · Department of Electrical and Computer Engineering, California State Polytechnic University, Pomona · [fill in emails]

---

## Abstract (seed, ~150–250 words when final)
Industrial controllers commonly speak Modbus/TCP, a protocol with no authentication: any host that can reach TCP port 502 can read or overwrite process values. We built PLC Guardian, a Python tool that decodes Modbus/TCP traffic to a Schneider Modicon M221 PLC controlling a simulated tank process, decides whether each request comes from an authorized source and is permitted for that source, writes a tamper-evident (SHA-256 hash-chained) evidence log, and—deployed inline as a Modbus proxy—blocks unauthorized requests before they reach the PLC. Four experiments evaluate it: baseline characterization of normal HMI traffic, an authorized change, an unauthorized change from a rogue host, and forensic reconstruction of a mixed capture. [PENDING: one sentence of quantitative results — detection rate, false positives, added latency.]

## Index Terms (keywords)
Industrial control systems, Modbus/TCP, network forensics, intrusion prevention, programmable logic controller, SCADA security.

---

## I. Introduction
Points to make:
- ICS/OT networks increasingly reachable from IT networks; legacy protocols such as Modbus were designed for closed serial networks and carry no authentication or integrity protection [1], [3].
- Consequence: a host on the control network can change setpoints/outputs → physical effects (our stand-in: tank overflow).
- Problem statement: detect process/configuration changes on the wire, attribute them to a source, decide authorized vs. unauthorized, preserve evidence, and prevent unauthorized changes.
- Contributions (bullet list in the paper):
  1. A Modbus/TCP decoder and per-source authorization policy (read/write/config granularity).
  2. A tamper-evident evidence log designed for forensic reconstruction.
  3. An inline proxy that enforces the policy (monitor vs. block mode).
  4. Evaluation on a physical M221 testbed through four experiments and a two-iteration demo.
- Paper organization paragraph.

## II. Background and Related Work
- **Modbus/TCP framing** (cite [1], [2]): MBAP header (TID, Protocol ID = 0, Length, Unit ID) + PDU (function code + data). Table of function codes used (copy from `docs/GUARDIAN_DESIGN.md` §4.1). Exceptions: FC with high bit set + exception code.
- **No authentication in Modbus/TCP**: any client accepted; Modbus Security (TLS-based) exists but is not supported on our device [VERIFY whether the M221 supports Modbus/TCP Security — likely not].
- **Schneider engineering traffic**: programming software uses Modbus FC 90 (0x5A) [VERIFY source; UMAS literature for M340/M580; M221 sub-protocol [UNVERIFIED]].
- **ICS security guidance**: NIST SP 800-82 Rev. 3 [3] (network segmentation, monitoring, allowlisting).
- **Forensic process**: NIST SP 800-86 [4] (collection, examination, analysis, reporting; preserving integrity with hashes).
- Related work to look up and summarize (2–4 items): Modbus IDS (e.g., Snort/Suricata Modbus preprocessors, Zeek Modbus analyzer), Modbus DPI firewalls. [PENDING: literature search; cite only what we actually read]

## III. Testbed
[CONFIRMED unless marked]
| Element | Detail | Evidence |
|---|---|---|
| PLC | Schneider Modicon M221, `192.168.8.11`, MAC `00:80:f4:54:1d:67`, Modbus/TCP server on 502, unit ID 1 (test client) / 255 (HMI) | `modbus_capture_practice.pcapng` frames 1–5; `Port_mirroring_test_3.pcapng` fr. 2–7, filter `mbtcp` |
| HMI | Pro-face web panel, `192.168.8.10`, MAC `00:00:54:0b:c5:9a`, web UI on TCP 80 | `test_connection.pcapng` (frames 4–5 onward, filter `tcp.port == 80`) |
| Engineering / test laptop | `192.168.8.50`, MAC `a0:ce:c8:62:e9:e1` | both captures |
| Attacker (simulated) | `192.168.8.99`, MAC `00:e0:4c:1d:3d:70` (currently also the HMI-config laptop) | On the network, but only HMI web traffic so far (`Port_mirroring_test_3.pcapng`); [PENDING: attack capture, A-015] |
| Guardian host | `192.168.8.12` planned; inline needs second NIC | [PENDING: A-004] |
| Network | `192.168.8.0/24`, isolated lab network, managed switch [model TBD] | open-items doc |
| Programming software | EcoStruxure Machine Expert – Basic (V1.4 release notes in project files [5]) | [VERIFY: version actually installed] |
| Simulated process | Tank fill: Start `%M2`, Stop `%M3` at level 80, maintenance bypass `%M4` (defeats stop → overflow), Reset `%M5`, level `%MW0` = `%C0.V` | Map: open-items doc §2. Interlock confirmed on the wire: `Port_mirroring_test_3.pcapng` (level rises only while `%M4`=1) |
| Tools | Wireshark [6], Python 3.10+/3.13, scapy 2.8.0 [7], pymodbus 3.16.1 (testing) | |
| Figure to draw | **Fig. 1** Testbed topology (both passive mirror and inline layouts) | |

## IV. System Design (PLC Guardian)
Source: `docs/GUARDIAN_DESIGN.md` (keep in sync). Points for the paper:
- **Design goals:** separate detection, logging and enforcement; external editable config; evidence soundness; same engine for live and offline analysis.
- **Language decision:** Python replaced C (D-002) — faster development; asyncio for the proxy; scapy for capture parsing.
- **Fig. 2** Architecture/data flow (§2.2 of design doc).
- **Decoder:** MBAP parsing, frame splitting over TCP streams, request/response decoding; anomaly flags.
  - Implementation detail worth reporting: TCP payload length taken from IP total length because Ethernet minimum-frame padding appears as payload (observed in practice capture frame 2).
- **Policy (Table I):** rule list from design doc §4.3 with decision levels; monotonic escalation ALLOW < ALERT < BLOCK. Allowlist based on source identity, not address distance.
- **Evidence log:** JSON Lines, per-record SHA-256 chain `h_i = SHA256(h_{i-1} ‖ JSON(r_i))`; session record with config hash and evidence-file hash; verification tool. Discuss tamper-evident vs. tamper-proof.
- **Inline proxy (D-003):** per-connection parse → evaluate → forward or reply with Modbus exception 01 / reset; response correlation by TID; hot-reloaded config (monitor ↔ block for the two demo iterations). Fail-closed trade-off.
- **Forensic report generator:** sections, outcome correlation (did the PLC accept the write?).

## V. Methodology (experiments)
For each: setup, procedure, what is captured, success criterion, metrics. Record every capture in `06_REFERENCE` with SHA-256.

| Exp. | Procedure | Guardian mode | Success criterion | Metrics to record |
|---|---|---|---|---|
| 1 Normal | Operators use HMI normally for N minutes; capture on mirror/inline | `baseline` | Profile of sources, FCs, addresses, polling interval | requests/s, FCs, signatures, # false alerts on a second normal capture |
| 2 Authorized change | Operator changes setpoint via HMI (and engineering laptop) | `proxy` block | Logged `AUTHORIZED_CHANGE`, forwarded, `ACCEPTED_BY_PLC` | detection = 1/1, no block, added latency |
| 3 Unauthorized change | Rogue host `.99` sends the same write directly | `proxy` monitor (iter. 1) then block (iter. 2) | Iter. 1: logged "would block", tank malfunctions; Iter. 2: `BLOCKED`, PLC value unchanged | detection rate, block rate, time to detect |
| 4 Forensics | Mixed capture with authorized + unauthorized activity, analyzed blind | `forensics` | Report identifies attacker IP/MAC, timeline, which changes the PLC accepted | correct attribution, timeline accuracy vs. ground-truth notes |

Ground truth: keep a written run sheet (who did what, wall-clock time) for every capture so results can be scored.
Metrics to define formally in the paper: true/false positive rate per request; proxy added latency = response time via proxy − direct (measure with `latency_ms` and a direct baseline); log verification result.

## VI. Results
- [CONFIRMED] Practice capture validation (V-1…V-5 in design doc §7): correct decode of FC3 read (frames 4–5), ALLOW for authorized source, BLOCK verdict for same frame from an unlisted source, hash-chain tamper detection, evidence hash unchanged.
- [CONFIRMED] Proxy forwards authorized reads to a mock PLC (V-6).
- [CONFIRMED] **First real HMI↔PLC capture** (`Port_mirroring_test_3.pcapng`, 592 fr., 12.6 s): HMI poll cycle FC1 (`%M2`–`%M5`), FC90 sub 0x74, FC3 (`%MW0`–`%MW1`) every ~250 ms, unit 255, TID 0; 150 requests, 0 exceptions, 0 writes. Seed for **Table II** (provisional; process was in bypass state): `.10`, FC1×50 / FC3×50 / FC90×50, 12.2 req/s. Details: `guardian/test_runs/port_mirroring_test_3/README.md`.
- [CONFIRMED] Interlock observed on the wire: with level > 80, `%MW0` rises only while bypass `%M4`=1 (+14, +4, +5) and holds while `%M4`=0 (fr. 3–591). Good figure: `%MW0` and `%M4` vs time.
- [CONFIRMED] False-positive finding that shaped the design: v0.1 flagged 150/150 normal requests (unit 255 not expected; FC 90 poll treated as configuration → BLOCK). Per-source FC 90 sub-code allowlist + unit fix → 0/150. Lesson for §IV/VII: a vendor-proprietary FC can't be classified by function code alone.
- [CONFIRMED] Proxy block-mode replay (loopback + mock PLC): unfixed v0.1 blocks the HMI's real FC 90 poll and lets an HMI write to `%MW0` through; with fixes + map-based protected points, the HMI poll and Start are forwarded, bypass ON from the HMI raises an ALERT, and all attacker writes and `%MW0` writes are BLOCKED.
- [SYNTHETIC, not lab evidence] Exp. 4 rehearsal on real capture + 6 injected scenarios (TTL 99): 6/6 classified correctly (authorized Start, HMI bypass alert, 3 attacker writes, IP spoof via MAC mismatch, FC 90 STOP, write to read-only level). Report the method only, or replace with a real mixed capture (A-015).
- [CONFIRMED] Forensic soundness bug found and fixed in test: classic `.pcap` input produced "no unauthorized activity" (silent false negative, I-003). Worth one sentence on validating tools against known-answer inputs.
- [PENDING] Exp. 1 baseline table (**Table II**).
- [PENDING] Exp. 2 log excerpt (**Fig./Listing**).
- [PENDING] Exp. 3 iteration 1 vs. 2 comparison (**Table III**: commands sent / reached PLC / blocked / process outcome).
- [PENDING] Exp. 4 forensic timeline excerpt (**Table IV**) and attribution accuracy.
- [PENDING] Performance: latency overhead, throughput.

## VII. Discussion
- Limitations (design doc §8): topology dependency and fail-closed; IP+MAC spoofing; no Modbus authentication on the wire so identity = network identity; tamper-evident not tamper-proof log; timestamp accuracy; FC 90 interpretation unverified.
- [CONFIRMED] Changes made locally at the PLC leave no network trace: `%M4` toggled 6× with no Modbus write (`Port_mirroring_test_3.pcapng`, I-004). Network forensics must be paired with PLC-side logs.
- [CONFIRMED] Side channel: the HMI's web API (`.10:80`) exposes process values to any host (`.99` polled it every 1 s); Guardian watches only port 502 (R-004).
- [CONFIRMED] HMI clock set to 1999 (HTTP Date header, fr. 22): device timestamps are unreliable; use the capture host's clock.
- Real-world deployment notes: fail-open vs. fail-closed choice for safety; pairing with switch ACLs / segmentation per NIST SP 800-82 [3]; Modbus Security (TLS) as a long-term fix [1]/[VERIFY].
- Forensic soundness: original captures never modified, hashes recorded at collection, analysis on read-only input, chain-head hash in report.

## VIII. Conclusion and Future Work
- Summary of results [PENDING].
- Future: switch-assisted blocking as fallback, register-map-aware value limits, rate/timing anomaly detection from the baseline, signed/remote log storage, ARP-spoofing detection, porting to an embedded inline device.

---

## Figures and tables checklist
| ID | Content | Source | Status |
|---|---|---|---|
| Fig. 1 | Testbed topology (mirror and inline) | design doc §2.3 + open items | to draw |
| Fig. 2 | Guardian architecture / data flow | design doc §2.2 | to draw |
| Fig. 3 | Wireshark screenshot of a Modbus FC3 request/response | `modbus_capture_practice.pcapng` frames 4–5 | to capture |
| Fig. 4 | HMI tank screen during Iteration 1 vs. 2 | demo | pending |
| Table I | Detection rules and decisions | design doc §4.3 | ready |
| Table II | Baseline profile | Exp. 1 | pending |
| Table III | Iteration 1 vs. 2 outcomes | Exp. 3 | pending |
| Table IV | Forensic timeline excerpt | Exp. 4 | pending |
| Listing 1 | Example evidence record (JSON) | any run | ready after Exp. 2 |

## Evidence index (for citations in the paper)
| File | SHA-256 | Notes |
|---|---|---|
| `test_connection.pcapng` | `4294e505f4f4178b50094b8759a2f009fd06d31d45b53125c12da869b64b5b55` | 3,118 frames, HTTP between `.50` and HMI `.10`; no Modbus |
| `modbus_capture_practice.pcapng` | `ad9cc550da93da0d702651a6b0d3a20f7ddb55a2a39cb5858238e4fd4786b630` | 8 frames, one FC3 read `.50 → .11` |
| `Port_mirroring_test_3.pcapng` | `2b26f8ab64741daababc81373ec5e4ca891579a35cb73dd3d8b018c715620bba` | 592 frames, HMI poll cycle, bypass/overflow state, no writes; `.99` HTTP to HMI |
| `mixed_pm3_synthetic.pcap` (SYNTHETIC) | `4c530d642b08cc38e162d29e68b63f64693f8b7afaa73a0d2c830ebe618d9b50` | Test input only: real capture + 40 injected frames (TTL 99). Not evidence |
| `analysis/S-004_modbus_census.md` + `S-004_*_mbtcp.csv` | n/a (derived) | Modbus traffic characterization (Exp. 1 / Results): FCs, unit IDs, addresses, frame ranges for practice + PM3; tshark commands in §5 |

---

## References (IEEE style — every entry [VERIFY] before submission)
[1] Modbus Organization, "MODBUS Application Protocol Specification V1.1b3," Apr. 2012. [Online]. Available: https://modbus.org
[2] Modbus Organization, "MODBUS Messaging on TCP/IP Implementation Guide V1.0b," Oct. 2006. [Online]. Available: https://modbus.org
[3] K. Stouffer *et al.*, "Guide to Operational Technology (OT) Security," NIST Special Publication 800-82 Rev. 3, Sep. 2023.
[4] K. Kent, S. Chevalier, T. Grance, and H. Dang, "Guide to Integrating Forensic Techniques into Incident Response," NIST Special Publication 800-86, Aug. 2006.
[5] Schneider Electric, "EcoStruxure Machine Expert – Basic V1.4 Release Notes," RN0000000012.05, Oct. 2025.
[6] Wireshark Foundation, "Wireshark," [Online]. Available: https://www.wireshark.org
[7] P. Biondi and the Scapy community, "Scapy," v2.8.0. [Online]. Available: https://scapy.net
[8] Python Software Foundation, "asyncio — Asynchronous I/O," Python 3 documentation. [Online]. Available: https://docs.python.org/3/library/asyncio.html
[9] Schneider Electric, "Modicon M221 Logic Controller — Programming Guide," [VERIFY document number/date].
