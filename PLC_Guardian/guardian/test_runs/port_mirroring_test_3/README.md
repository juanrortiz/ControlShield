# Port_mirroring_test_3: capture analysis and PLC Guardian test run

_Analysis date: 2026-10-21 (session S-003). Analyst: David Jessup with Claude. Register map source: `plc-guardian-open-items.md` §2 ("PLC Register Map (CONFIRMED on the wire)"), from the "Wireshark tank values PLC" chat._

Tags: **[CONFIRMED]** = shown in the capture or a test run cited here · **[SYNTHETIC]** = from injected test traffic, not lab evidence · **[UNVERIFIED]** = inference still to check.

---

## 1. Evidence

| Item | Value |
|---|---|
| File | `Port_mirroring_test_3.pcapng` (original kept in the claude.ai project files; working copy in this folder) |
| SHA-256 | `2b26f8ab64741daababc81373ec5e4ca891579a35cb73dd3d8b018c715620bba` (identical before and after analysis) |
| Frames / duration | 592 frames, 12.566 s |
| First / last packet | 2026-10-15 01:09:41.968 UTC → 01:09:54.533 UTC (2026-10-14 18:09 PDT) |
| Capture point | Guardian laptop on switch port 5, mirroring PLC port 4, both directions (TL-SG105E) |
| Captured by | [fill in] |
| Tools | Python 3, scapy (decode); PLC Guardian `guardian.py` (analysis). The display filters below reproduce each finding in Wireshark |

### Register map used (from the other chat)

| PLC address | Modbus | Meaning |
|---|---|---|
| `%M2` | coil 2 | Start (HMI writes it with FC 15) |
| `%M3` | coil 3 | Stop (engages at level 80) |
| `%M4` | coil 4 | Maintenance bypass (when ON, the level-80 stop is defeated) |
| `%M5` | coil 5 | Reset |
| `%MW0` | holding register 0 | Tank level (= counter `%C0.V`) |
| `%MW1` | holding register 1 | Unknown, always 0 so far |
| `%Q0.0` | none | Not visible on Modbus |

---

## 2. What the capture shows

### 2.1 Traffic composition [CONFIRMED]

| Conversation | Frames | Content | Wireshark filter |
|---|---|---|---|
| HMI `.10` → PLC `.11:502` | 201 | Modbus requests + ACKs | `ip.src==192.168.8.10 && tcp.dstport==502` |
| PLC `.11:502` → HMI `.10` | 150 | Modbus responses | `ip.src==192.168.8.11 && tcp.srcport==502` |
| `.99` ↔ HMI `.10:80` | 216 | HTTP GET `/services/variable/hmi/values?page=1&rp=13` once per second | `tcp.port==80` |
| Switch broadcast, EtherType 0x8899 | 25 | Realtek loop detection (noise) | `eth.type==0x8899` |

- **No Modbus writes in the whole capture.** Filter `modbus.func_code in {5 6 15 16 23}` → 0 frames. Function codes present: 1, 3, 90 only.
- **No traffic from `.99` to the PLC.** `.99` (MAC `00:e0:4c:1d:3d:70`) only talks to the HMI web server. The attacker path is still not exercised.
- TCP session to the PLC was already open when capture started (no SYN; HMI client port 10291).

### 2.2 Normal HMI poll cycle [CONFIRMED]

Every ~250 ms, always **Unit ID 255** and **Transaction ID 0**:

| Step | Request PDU | Map meaning | First example (req / rsp frame) |
|---|---|---|---|
| 1 | FC 1, addr 2, qty 4 | read `%M2`–`%M5` | 2 / 3 |
| 2 | FC 90 (0x5A), data `00 74 01 82 00 00 00 01` | Schneider proprietary, sub-code byte 0x74 | 4 / 5 |
| 3 | FC 3, addr 0, qty 2 | read `%MW0`–`%MW1` | 6 / 7 |

50 cycles in 12.5 s (150 requests, 150 responses, 0 exceptions). The FC 90 reply is always `00 FE 01 00 0x` with the last byte cycling 00/02/03 (frames 5, 12, 101). Its meaning is [UNVERIFIED]; it behaves like a read/status poll.

### 2.3 Process state: overflow condition with the bypass cycling [CONFIRMED values; cause UNVERIFIED]

- `%M2` Start = 1 and `%M3` Stop = 1 throughout (level is above 80, so the stop is engaged). `%M5` Reset = 0.
- `%MW0` tank level goes from **122** (frame 7) to **148** (frame 398), already far past the 80 stop point. `%MW1` = 0 throughout.
- `%M4` maintenance bypass **toggles 6 times**, and the level rises **only while `%M4` = 1**:

| `%M4` | From (FC1 response frame) | `%MW0` over the interval (frames) | Change |
|---|---|---|---|
| 1 | t+0.16 s (fr 3) | 122 → 136 (fr 7 → 144) | +14 |
| 0 | t+3.16 s (fr 147) | 136 → 136 (fr 151 → 233) | 0 |
| 1 | t+4.91 s (fr 236) | 137 → 141 (fr 240 → 288) | +4 |
| 0 | t+6.16 s (fr 291) | 142 → 142 (fr 295 → 336) | 0 |
| 1 | t+7.16 s (fr 339) | 142 → 147 (fr 343 → 391) | +5 |
| 0 | t+8.41 s (fr 394) | 148 → 148 (fr 398 → 591) | 0 |

Coil byte in the FC1 reply: `0x07` = `%M2,%M3,%M4` ON; `0x03` = `%M2,%M3` ON. Filter: `modbus.func_code==1 && tcp.srcport==502`.

**This confirms the interlock from the register map on the wire:** above 80 the stop holds the level unless the maintenance bypass is ON. The capture is a live **overflow/unsafe-operation** example, not a clean baseline.

**Open question (I-004):** `%M4` changes state six times but **no Modbus write appears anywhere in the capture**, and the mirror covers every packet to and from the PLC port. So `%M4` was driven inside the PLC (ladder logic, a physical input copied to `%M4`, or someone in Machine Expert's animation table over USB). Which one is [UNVERIFIED]; whoever ran the lab session should confirm. Forensic consequence: **a state change made locally at the PLC leaves no network evidence, so Guardian cannot attribute or block it.** That limitation belongs in the report.

### 2.4 HMI web page polled by `.99` [CONFIRMED values; field mapping UNVERIFIED]

Each HTTP reply carries 5 values, e.g. frame 32: `[['1',0],['1',0],['0',0],['1',0],['124',0]]`.
- Field 5 equals `%MW0` each second (124, 128, 133, 136, 136, 139, 142, 144, 148…; frames 32 → 560).
- Field 2 follows `%M4` in every sample (1 while the bypass is on, 0 while off).
- Field 4 is constantly 1, consistent with `%M3`.
- Fields 1 and 3 are [UNVERIFIED].

Per the address map, `.99` is currently the team's HMI-config laptop **and** the planned attacker. This traffic is the config software or a browser monitoring the HMI, but Guardian only watches port 502, so it is blind to this channel. If the HMI web API accepts writes, it's a path to the PLC that goes around Guardian (R-004).

### 2.5 Other forensic notes
- **HMI clock is wrong:** HTTP `Date:` headers show `Fri, 31 Dec 1999 17:43:53 GMT` (frame 22). Use capture-host timestamps only; note it in the report (R-003).
- **Unit ID:** the HMI uses 255. `06_REFERENCE` listed unit 1, which came from the pymodbus test (`modbus_capture_practice.pcapng` fr. 4). The M221 answers both.
- **Transaction ID is always 0**, so requests and responses can only be paired by TCP stream order. Guardian pairs by (client IP, port, TID), which works here because the HMI waits for each reply before sending the next request.

---

## 3. PLC Guardian test results

Code tested: `guardian/` as of 2026-10-21 (files staged from the Group Project folder). Proposed fixes are in `proposed_fixes.patch`. **The source in `guardian/` has NOT been changed.**

### 3.1 Normal traffic (Experiment 1 material), real capture [CONFIRMED]

| Run | Config | Result |
|---|---|---|
| A | current code + current `config.json` (unit 1, FC 90 = config) | **150/150 requests flagged:** 100 ALERT `UNEXPECTED_UNIT_ID`, 50 BLOCK `ACTION_NOT_PERMITTED_FOR_SOURCE` (HMI's FC 90 poll counted as "config") |
| B | current code + unit IDs `[255]` | 100 ALLOW, 50 BLOCK (FC 90 poll) |
| C | fixes + `config_mapped.json` (unit IDs `[1,255]`, `fc90_read_subcodes:[116]` on the HMI, map-based protected points) | **150/150 ALLOW**, 0 false positives |

Baseline from run C (`baseline_pm3.json`): source `.10`, MAC `00:00:54:0b:c5:9a`, unit 255, FC1 ×50 / FC3 ×50 / FC90 ×50, signatures `1:2:4`, `3:0:2`, `90:sub116`, 12.2 req/s. Use this as a **provisional** baseline: the process was in the bypass/overflow state, so it isn't a clean "normal" run.

### 3.2 Inline proxy, block mode (Iteration 2 behaviour) [CONFIRMED on loopback + mock PLC]

The HMI's real poll PDUs from the capture plus map-based writes were replayed through `guardian.py proxy` → `tools/mock_plc.py`. `127.0.0.1` stood in for the HMI and `127.0.0.2` for the attacker. Decisions are from the proxy's evidence logs (`proxy_shipped.jsonl`, `proxy_final.jsonl` in this folder; hash chain PASS).

| Sender | Request | Current code + shipped config (unit ID set to 255) | With fixes + mapped config |
|---|---|---|---|
| HMI | FC1 read `%M2..%M5` (real) | forwarded | forwarded |
| HMI | FC90 0x74 poll (real) | **BLOCKED → HMI loses its status poll in the demo** | forwarded* |
| HMI | FC3 read `%MW0..%MW1` (real) | forwarded | forwarded |
| HMI | FC15 `%M2`=1 Start | forwarded | forwarded (ALLOW) |
| HMI | FC5 `%M4`=1 bypass ON | forwarded, ALLOW (no alert: protected points disabled) | forwarded, **ALERT** `VALUE_OUT_OF_RANGE` |
| HMI | FC6 `%MW0`=0 | **forwarded, ALLOW** (tank-level register overwritten) | **BLOCKED** `WRITE_TO_READ_ONLY_POINT` |
| HMI | FC90 0x41 (STOP_PLC in UMAS, [UNVERIFIED] for M221) | BLOCKED | BLOCKED `ACTION_NOT_PERMITTED_FOR_SOURCE` |
| Attacker | FC5 `%M4`=1, FC5 `%M2`=1, FC6 `%MW0`=0, FC1 read | BLOCKED | BLOCKED `SRC_NOT_ALLOWLISTED` (+ point rules) |

\* The mock PLC doesn't implement FC 90 and answers with exception 01 itself. The proxy log shows Guardian forwarded the request, so the real M221 would answer.

### 3.3 Forensic reconstruction of a mixed capture (Experiment 4 rehearsal) [SYNTHETIC]

`mixed_pm3_synthetic.pcap` (SHA-256 `4c530d642b08cc38e162d29e68b63f64693f8b7afaa73a0d2c830ebe618d9b50`) = the real capture + 40 injected frames (all with **IP TTL 99** so they can be told apart; injected PLC replies are fabricated echoes). Report: `forensics_report_mixed.md`.

| Injected scenario | Guardian verdict | Correct? |
|---|---|---|
| S1 HMI FC15 `%M2`=1 Start | AUTHORIZED_CHANGE, ALERT (baseline deviation only) | yes |
| S2 HMI FC5 `%M4`=1 bypass ON | AUTHORIZED_CHANGE, ALERT `VALUE_OUT_OF_RANGE` | yes |
| S3 `.99`: `%M4`=1, `%M2`=1, `%MW0`=0 | UNAUTHORIZED_CHANGE ×3, BLOCK | yes |
| S4 `.99` NIC spoofing HMI IP: `%M3`=0 | SPOOFED_SOURCE, BLOCK `MAC_MISMATCH`; host table flags 2 MACs on `.10` | yes |
| S5 `.99` FC90 0x41 | UNAUTHORIZED_CONFIG_CHANGE, BLOCK | yes |
| S6 HMI FC6 `%MW0`=0 | BLOCK `WRITE_TO_READ_ONLY_POINT` | verdict yes; report gap (below) |

6/6 scenarios classified correctly, with 0 false positives on the 150 real polls. Evidence log hash chain: PASS.

### 3.4 Defects found in Guardian

| # | Defect | Effect | Fix (in `proposed_fixes.patch` / config) |
|---|---|---|---|
| 1 | `config.json` `plc.unit_ids = [1]`; the HMI uses 255 | every HMI request ALERTs | `[1, 255]` |
| 2 | FC 90 always = "config"; HMI is allowed read/write only | the HMI's normal poll is BLOCKED in block mode, so the HMI breaks in Iteration 2 | per-source `fc90_read_subcodes` (HMI: `[116]` = 0x74); every other FC 90 sub-code stays "config" |
| 3 | Baseline signature for FC 90 was `90:None:None` | any FC 90 (incl. STOP) matched the baseline | signature now `90:sub<code>` |
| 4 | Classic `.pcap` files decoded as raw bytes (scapy link types not registered before opening) | **0 requests, "No unauthorized activity"**: a silent false negative in forensics | import scapy layers first (1 line in `analyzer.py`) |
| 5 | Forensic report §6 "Authorized changes" lists the 0x74 polls; a BLOCK from an authorized source (S6) appears only in the timeline, not in §4 Findings | noisy / incomplete report | not yet fixed |
| 6 | Proxy stopped by SIGTERM writes no SESSION_END record | log ends without a close record | not yet fixed (Ctrl+C works) |
| 7 | README says `--baseline`/`--log` work on any command, but they must come before the sub-command | usage error | doc fix |

Proposed protected points (in `config_mapped.json`; **team decision needed**, see A-013): `%M2`, `%M3`, `%M5` 0..1; `%M4` 0..0 (turning the bypass ON always alerts, and blocks if the sender isn't authorized); `%MW0` read-only. `%MW1` not protected until its meaning is known.

---

## 4. What this means for the experiments

- **Exp. 1:** This capture shows the poll cycle and the interlock, but it's an overflow state. Run the baseline on `Port_Mirroring_Baseline.pcapng` (bypass OFF, level holds at 80) for the clean Table II. That file isn't in this folder yet.
- **Exp. 2/3:** Before any demo in block mode, apply fixes 1 and 2 or the HMI's own poll gets blocked. Still need a real capture of `.99` writing to the PLC.
- **Exp. 4:** The forensic pipeline works end to end on a mixed capture (synthetic). Repeat with a real mixed capture and a written run sheet as ground truth.
- **Report (limitations):** local/physical PLC changes are invisible to network monitoring (I-004); the HMI web channel is not monitored (R-004); the HMI clock is wrong (R-003).

## 5. Files in this folder

| File | What |
|---|---|
| `Port_mirroring_test_3.pcapng` | working copy of the evidence (hash above; never edit) |
| `proposed_fixes.patch` | code fixes 2–4 (not applied) |
| `config_mapped.json` | config with fixes 1–2 and the map-based protected points |
| `config_fixed.json` | superseded by `config_mapped.json` (first pass, before the register map was applied) |
| `baseline_pm3.json` | provisional baseline from this capture |
| `make_mixed_pcap.py` | builds the synthetic mixed capture (scenarios S1–S6) |
| `mixed_pm3_synthetic.pcap` | SYNTHETIC test capture, not evidence |
| `forensics_report_mixed.md` | Guardian forensic report on the mixed capture |
| `proxy_replay.py`, `proxy_replay_results.txt` | proxy block-mode test and its console output |
| `proxy_shipped.jsonl`, `proxy_final.jsonl` | proxy evidence logs: current code vs fixes |
| `pm3_mapped.jsonl`, `forensics_mixed_events.jsonl` | evidence logs for run C and the mixed-capture report |

Re-run (from this folder, after applying the patch to a copy of `guardian/`):

    python make_mixed_pcap.py Port_mirroring_test_3.pcapng mixed_pm3_synthetic.pcap
    python ..\..\guardian.py --config config_mapped.json analyze -q Port_mirroring_test_3.pcapng
    python ..\..\guardian.py --config config_mapped.json --baseline baseline_pm3.json forensics mixed_pm3_synthetic.pcap -o ..\..\reports\mixed_pm3
    python proxy_replay.py config_mapped.json Port_mirroring_test_3.pcapng ..\.. pm3
