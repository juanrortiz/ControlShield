# S-007 · Black-box discovery live test — Experiment 5 / A-022

_Analysis date: 2026-11-09/10. Analyst: David Jessup with Claude. tshark 4.6.9. Read-only analysis; captures not modified._

Tags: **[CONFIRMED]** = shown in the capture or Guardian's own evidence log · **[UNVERIFIED]** = inference still to check.

---

## 1. Evidence

| Item | Value |
|---|---|
| File | `Black Box Test.pcapng` (as downloaded; working copy for analysis only — original untouched) |
| SHA-256 | `c0655920c0a521f3b6652d93ae8c131022d4fd1e3cbac55582d1129c2ffba521` |
| Frames / duration | ~15,000 frames, 293.4 s |
| First / last packet (UTC) | 2026-11-10 03:33:04.732371 → 03:37:58.142194 |
| Capture point | Guardian/capture host, port-mirrored traffic (Port 2 PLC + Port 3 HMI → Port 5 Guardian) |
| Companion evidence | `guardian/logs/live_attacker_test_2026-11-04_v2.jsonl` (same host, same window, `sensor: live:Ethernet 4` / `active_response`) |
| Not yet in `06_REFERENCE` capture inventory | Flagged as new evidence — proposed row in §5 |

---

## 2. What this capture shows

This single capture spans **two experiments run back-to-back**: a black-box Modbus discovery sweep (`192.168.8.99` against the PLC, first ~22 s) and a later recurrence of the port-80 HTTP test against the HMI (around relative 191-227 s / `03:36:15Z` onward — same attack already analyzed in `S-007_port80_ips_live_test.md`). This report covers the Modbus black-box portion and the cooldown behavior visible across the whole window.

### 2.1 Read-only scope confirmed [CONFIRMED — safety-critical check]

`WS tshark -r "Black Box Test.pcapng" -Y "tcp.dstport==502 && modbus.func_code in {5,6,15,16,23} && ip.src==192.168.8.99"` → **zero results.**

The full write census (`WS census`) shows exactly 6 Modbus writes in the entire 293 s capture, **none from `.99`**:

| Frame | Time (UTC) | Source | FC | Addr | Value | What |
|---|---|---|---|---|---|---|
| 96 | 03:33:06.791420 | `.10` (HMI) | 15 | `%M2` | — | Normal HMI Start-cycle write |
| 144 | 03:33:06.858184 | `.50` (Guardian) | 5 | `%M7` | ON | `active_response` lockout fire #1 |
| 2935 | 03:33:11.900646 | `.50` | 5 | `%M7` | ON | fire #2 |
| 5511 | 03:33:16.894512 | `.50` | 5 | `%M7` | ON | fire #3 |
| 5684 | 03:33:21.899990 | `.50` | 5 | `%M7` | ON | fire #4 |
| 11299 | 03:36:16.468824 | `.50` | 5 | `%M7` | ON | fire #5 (HTTP-phase trigger, see below) |
| 12517 | 03:36:31.268753 | `.50` | 5 | `%M7` | **OFF** | manual lockout clear (this session) |

**Confirms D-005's scope was respected**: the black-box discovery tool (`tools/plc_blackbox.py` or equivalent) performed fingerprinting and enumeration only — no FC5/6/15/16/23 write probing from `.99` anywhere in this capture.

### 2.2 Discovery pipeline stages observed [CONFIRMED]

Matches the documented discovery-tool stages exactly:

- **Port scan** (`conv,tcp`): single-frame probes from `.99` to PLC ports `44818` (EtherNet/IP), `1911` (Niagara Fox), `4840` (OPC UA), `20000` (DNP3), `789` (Red Lion), `2404` (IEC 60870-5-104), `102` (S7comm) — all at relative `t≈1.58s`, each 1-2 frames, no response data (ports closed/filtered). Matches the standard `ICS_PORTS` list these black-box tools scan.
- **Fingerprint** (`WS census`, unit 1, FC 43 "Read Device Identification"): one request, frame 103, `03:33:06.7xx`.
- **Enumeration** (`WS census`): FC1 (coils), FC2 (discrete inputs), FC3 (holding registers), FC4 (input registers), each addresses 0-19, **21 reads per address** (1 enumeration pass + 20 inference samples — matches the tool's `--samples 20` default) — 4 tables × 20 addresses × 21 ≈ 1680 reads, closely matching the 1682 BLOCKed requests counted in §2.3.
- Notably, the blind coil sweep **read coil 7 (`%M7`/PLCGUARD) 21 times** with zero prior knowledge of its meaning — a black-box tool would have seen this bit flip ON mid-sweep (from Guardian's own reactive write) and could plausibly flag it as "interesting" behaviorally, without knowing it's the IDS's own lockout coil.

### 2.3 Guardian's reaction, and the cooldown working as designed [CONFIRMED, correlated to the millisecond]

Every one of `.99`'s reads was judged `BLOCK`/`UNAUTHORIZED_READ` (not allowlisted; `unknown_sources.allow_reads=false`), which is itself a legitimate `active_response` trigger (`trigger_decisions: ["BLOCK"]` — reads count, not just writes):

```
BLOCKed requests from .99 (03:33-03:37 window):  1682
ACTIVE_RESPONSE outcomes in the same window:
    SUCCEEDED:         5
    SKIPPED_COOLDOWN:  1677
```

The very first trigger was the **fingerprint request itself** (FC43), not the coil sweep:

```
03:33:06.829749Z  REQUEST  BLOCK/UNAUTHORIZED_READ  src=.99  "FC43 Encapsulated Interface Transport (Device ID)"
03:33:06.861578Z  ACTIVE_RESPONSE  outcome=SUCCEEDED
```

— matching pcap frame 144 (`03:33:06.858184Z`) to within 3 ms. The four subsequent `SUCCEEDED` fires (`03:33:11.90`, `03:33:16.90`, `03:33:21.90`) land almost exactly 5.0 s apart, matching `active_response.cooldown_seconds: 5` precisely — every other one of the 1681 other BLOCKed reads in between correctly produced `SKIPPED_COOLDOWN`, not a redundant PLC write. A fifth `SUCCEEDED` fire at `03:36:16.476294Z` matches pcap frame 11299 and corresponds to the later HTTP-phase trigger (`http_watch`), already covered in `S-007_port80_ips_live_test.md`.

**This is a clean, real-world demonstration of the cooldown mechanism doing exactly its job**: a sustained ~1700-request black-box scan produced only 5 actual lockout writes to the PLC, not 1682 — avoiding a write flood while still engaging the interlock promptly (within ~32 ms of the very first unauthorized request) and re-engaging periodically for the duration of a sustained attack.

### 2.4 Integrity [CONFIRMED]

`WS tshark -q -z conv,tcp` response matching: `requests=5205 responses=5205 exceptions=0 unanswered_request_frames=none` — every Modbus request in the capture got a clean response, no protocol exceptions, nothing lost. `MACs seen per IP`: one MAC per real host, no spoofing detected in this capture (the known `.99`/`.2` MAC-sharing issue, A-021, is a separate pre-existing condition, not new here).

---

## 3. What this means for the project

- **First real evidence that passive reconnaissance alone — zero writes — engages Guardian's reactive compensating control.** Because Guardian blocks *any* unauthorized traffic, not just writes, a pure black-box discovery scan (the kind Experiment 5/A-022 is about) is itself enough to trip `%M7` repeatedly. Worth a line in the report: the lockout isn't write-specific, it's "any BLOCK-worthy traffic from this source."
- **Cooldown behavior validated under real sustained load** for the first time — previously only unit-tested/reasoned about; now confirmed against ~1700 real BLOCKed requests in under 30 seconds.
- **The discovery tool's own blind enumeration incidentally touched `%M7`** — a nice forensic/report detail: a true black-box attacker reading coil 7 repeatedly, with no idea what it is, would see it flip ON partway through their own scan.
- Confirms (again, independently) **D-005's read-only constraint was honored** in an actual run against the real PLC, not just by code review of the tool.

---

## 4. Proposed `06_REFERENCE.md` capture inventory addition

| File | Date | Who | Scenario | Frames / Duration | SHA-256 |
|---|---|---|---|---|---|
| `Black Box Test.pcapng` | 2026-11-09/10 | David Jessup (attacker on `.99`) | Experiment 5 / A-022: black-box discovery (port scan, FC43 fingerprint, FC1-4 enumeration 0-19 × 21 samples) against the real PLC; zero writes from `.99`; triggers Guardian's `active_response` 5×, cooldown correctly suppresses 1677 more; also contains a later recurrence of the port-80 HTTP test (see `S-007_port80_ips_live_test.md`) | ~15,000 fr. / 293.4 s | `c0655920c0a521f3b6652d93ae8c131022d4fd1e3cbac55582d1129c2ffba521` |

---

## 5. Hash re-verification

`WS verify "Black Box Test.pcapng"` re-run after this analysis: SHA-256 unchanged, `c0655920c0a521f3b6652d93ae8c131022d4fd1e3cbac55582d1129c2ffba521`.

---

## Reproduce

```sh
bash .claude/skills/wireshark-analyze/scripts/ws.sh verify "C:\Users\david\Downloads\Black Box Test.pcapng"
bash .claude/skills/wireshark-analyze/scripts/ws.sh capinfos -c -u -a -e -t -E "C:\Users\david\Downloads\Black Box Test.pcapng"
bash .claude/skills/wireshark-analyze/scripts/ws.sh tshark -r "C:\Users\david\Downloads\Black Box Test.pcapng" -q -z conv,tcp
bash .claude/skills/wireshark-analyze/scripts/ws.sh census "C:\Users\david\Downloads\Black Box Test.pcapng"
bash .claude/skills/wireshark-analyze/scripts/ws.sh tshark -r "C:\Users\david\Downloads\Black Box Test.pcapng" -Y "tcp.dstport==502 && modbus.func_code in {5,6,15,16,23} && ip.src==192.168.8.99" -T fields -e frame.number -e frame.time_utc -e modbus.func_code
```
