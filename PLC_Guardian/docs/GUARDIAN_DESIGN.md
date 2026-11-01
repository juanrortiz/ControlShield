# PLC Guardian: Software Design Reference

_Technical reference for the Python implementation in `guardian/`. Version 0.1.0 · written S-002 · 2026-10-21._
_Decisions behind this design: D-002 (Python replaces C), D-003 (inline Modbus proxy for blocking)._
_Anything marked [UNVERIFIED] has not been confirmed on the lab hardware or in a capture._

---

## 1. Purpose

PLC Guardian watches Modbus/TCP traffic to the Schneider M221 PLC and, for every request:

1. **Detects**: decodes the request and decides whether its source is authorized for that action.
2. **Logs**: writes a tamper-evident evidence record for forensic reconstruction.
3. **Blocks**: when running inline with enforcement on, stops unauthorized requests before they reach the PLC.

The three steps are separate modules on purpose, so each required experiment maps onto clear components (§9).

---

## 2. Architecture

### 2.1 Operating modes

| Mode | Command | Position on network | Can block? | Used for |
|---|---|---|---|---|
| Inline proxy | `guardian.py proxy` | Between clients and the PLC | **Yes** (`enforcement.mode = block`) | Exp. 2, 3, demo Iterations 1 & 2 |
| Passive live | `guardian.py monitor --iface X` | Mirror/SPAN port or any host that sees the traffic | No (logs "would block") | Exp. 1–3 monitoring |
| Offline | `guardian.py analyze / baseline / forensics <pcap>` | None (reads a capture file) | No | Exp. 1 baseline, Exp. 4 forensics |

### 2.2 Data flow

```
                ┌──────────────────────── Guardian ─────────────────────────┐
 packet/stream  │  analyzer.py / proxy.py      policy.py        events.py   │
 ─────────────► │  reassemble TCP  ─► modbus.py ─► Policy.evaluate ─► record │
                │  split MBAP frames   parse_frame   → Verdict       builder │
                │                                        │            │      │
                │                         proxy.py ◄─────┘            ▼      │
                │                    forward or BLOCK        evidence_log.py │
                │                    (exception / reset)     hash-chained    │
                │                                            JSONL           │
                └───────────────────────────────────────────────┬───────────┘
                                                                ▼
                                 forensics.py (report.md) · baseline.py (baseline.json)
                                 export_csv (events.csv) · verify (chain check)
```

### 2.3 Inline topology (required for real blocking) [UNVERIFIED: not built yet]

```
 HMI .10 ─┐                                   
 Eng .50 ─┼── lab switch ── NIC1 [Guardian] NIC2 ── PLC (own cable / own subnet)
 Atk .99 ─┘                 192.168.8.11?          e.g. 192.168.9.11 [UNVERIFIED]
```

The proxy prevents an attack only if the PLC cannot be reached except through Guardian. Proposed layout: the PLC on Guardian's second NIC, Guardian's first NIC taking the address clients already use. The design is **fail-closed**: if Guardian stops, the PLC is unreachable. Open item A-004.

---

## 3. File inventory

| Path | Type | Purpose |
|---|---|---|
| `guardian/guardian.py` | CLI entry point | Subcommands `proxy`, `monitor`, `analyze`, `baseline`, `forensics`, `verify`, `export` |
| `guardian/config.json` | Configuration | Allowlist, PLC address, protected points, enforcement mode, proxy and log settings |
| `guardian/README.md` | Quick start | Setup, commands, topology, evidence handling, test status |
| `guardian/plcguard/__init__.py` | Package | Version string (`0.1.0`) |
| `guardian/plcguard/modbus.py` | Decoder | MBAP + PDU parsing, function-code tables, exception builder |
| `guardian/plcguard/config.py` | Config loader | Loads/normalizes `config.json`, applies defaults, hot reload |
| `guardian/plcguard/policy.py` | **Detect** | Authorization decision → `Verdict` |
| `guardian/plcguard/evidence_log.py` | **Log** | Append-only JSONL with SHA-256 hash chain, verify, CSV export |
| `guardian/plcguard/events.py` | Record builder | Builds REQUEST/RESPONSE evidence records |
| `guardian/plcguard/proxy.py` | **Block** | asyncio inline Modbus/TCP proxy |
| `guardian/plcguard/analyzer.py` | Passive sensor | TCP reassembly + analysis for pcap and live sniffing |
| `guardian/plcguard/baseline.py` | Exp. 1 | Learns normal traffic profile from a clean capture |
| `guardian/plcguard/forensics.py` | Exp. 4 | Markdown forensic report (evidence, summary, hosts, findings, timeline) |
| `guardian/tools/mock_plc.py` | Test tool | Minimal Modbus server standing in for the PLC (FC 1, 3, 5, 6, 15, 16) |
| `guardian/tools/modbus_client.py` | Test tool | Minimal Modbus client (HMI/attacker stand-in for lab tests) |
| `guardian/baseline_practice.json` | Output | Baseline learned from `modbus_capture_practice.pcapng` |
| `guardian/reports/practice/` | Output | `report.md`, `events.jsonl`, `events.csv` for the practice capture |
| `guardian/logs/practice_events.jsonl` | Leftover test output | Safe to delete (A-009) |

Dependencies: Python ≥ 3.10; `scapy` (2.8.0 tested) for pcap/live modes only; the proxy, policy and log use the standard library only. Live sniffing needs Npcap (Windows) or root (Linux).

---

## 4. Module reference

### 4.1 `modbus.py` (decoder)

Wire layout handled (Modbus/TCP, big-endian):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | Transaction ID | Echoed in response; used to correlate request ↔ response |
| 2 | 2 | Protocol ID | Must be 0; non-zero → `PROTOCOL_ANOMALY` |
| 4 | 2 | Length | Bytes after this field; valid 2–254 |
| 6 | 1 | Unit ID | |
| 7 | 1 | Function code | High bit set in a response = exception |
| 8+ | n | Data | Function-specific |

| Name | Kind | What it does |
|---|---|---|
| `FC_NAMES`, `EXCEPTION_NAMES` | tables | Human-readable names for function and exception codes |
| `READ_FCS` / `WRITE_FCS` / `CONFIG_FCS` | sets | Classify FCs: read {1,2,3,4,7,11,12,17,20,24,43}, write {5,6,15,16,21,22,23}, config {8,90} |
| `FC_TABLE` | table | Which data table an FC touches (coil / discrete_input / holding / input) |
| `UMAS_HINTS` | table | FC 90 sub-code names from Schneider UMAS; **[UNVERIFIED] for the M221**, hint only |
| `fc_category(fc)` | function | Returns `read` / `write` / `config` / `exception` / `unknown` |
| `ModbusFrame` | dataclass | One decoded frame: header fields, category, address, quantity, values, exception, FC 90 sub-code, anomalies |
| `ModbusFrame.write_targets()` | method | Yields `(table, address, value)` for every point a write changes |
| `ModbusFrame.summary()` | method | One-line text, e.g. `FC6 Write Single Register addr=0 qty=1 values=[60]` |
| `parse_frame(buf, is_request)` | function | Decodes one complete frame; records anomalies (non-zero PID, exception bit in request, unknown FC, truncated PDU, byte-count mismatch, invalid coil value) |
| `split_frames(buf)` | function | Splits a TCP byte stream into complete frames; returns leftover bytes and an error for an invalid length field |
| `build_exception(req, code)` | function | Builds the Modbus exception reply Guardian sends when it blocks |

Request decoding is implemented for FC 1–6, 15, 16, 22, 23 and 90 (sub-code only); responses for exceptions, 1–6, 15, 16, 23, 90.

### 4.2 `config.py`

| Name | What it does |
|---|---|
| `Config(path)` | Loads JSON, normalizes MACs to `aa:bb:..` lower-case, fills defaults, stores the file's SHA-256 (`config.sha256`, written into every log session) |
| `Config.reload_if_changed()` | Re-reads the file if its modification time changed; keeps the last good config if the new file is invalid |
| `plc_ip`, `plc_port`, `sources` | Accessors |

### 4.3 `policy.py` (detect)

`Policy.evaluate(frame, src_ip, src_mac=None) → Verdict` runs four stages. Each rule can only **raise** the decision (ALLOW < ALERT < BLOCK); `Verdict.escalate()` enforces that.

| Stage | Rule ID | Fires when | Decision |
|---|---|---|---|
| 1 Source | `SRC_NOT_ALLOWLISTED` | Source IP not in `authorized_sources` | BLOCK (ALERT for reads if `unknown_sources.allow_reads`) |
| 1 Source | `MAC_MISMATCH` | Known IP seen with a different MAC (passive modes only) | BLOCK, event `SPOOFED_SOURCE` |
| 1 Source | `ACTION_NOT_PERMITTED_FOR_SOURCE` | Category (read/write/config) not in that source's `allow` list. An FC 90 sub-code listed in that source's `fc90_read_subcodes` counts as `read` (S-003 fix 2: the HMI's 0x74 status poll) | BLOCK |
| 2 Frame | `PROTOCOL_ANOMALY` | Any decoder anomaly | BLOCK |
| 2 Frame | `UNEXPECTED_UNIT_ID` | Unit ID not in `plc.unit_ids` | ALERT (BLOCK if `block_unexpected_unit_id`) |
| 3 Value | `WRITE_TO_READ_ONLY_POINT` | Write to a protected point marked `read_only` | BLOCK |
| 3 Value | `VALUE_OUT_OF_RANGE` | Written value outside a protected point's min..max | BLOCK if unauthorized, else ALERT (BLOCK if `block_out_of_range_from_authorized`) |
| 4 Baseline | `BASELINE_DEVIATION` | Authorized source sends an `fc:addr:qty` never seen in the baseline (FC 90 signature is `90:sub<code>`, S-003 fix 3) | ALERT only |

`Verdict` fields: `decision`, `authorized`, `event_type`, `rules`, `details`, `source_name`; `is_notable` is true for anything but an authorized read.

Event types: `NORMAL_READ`, `AUTHORIZED_CHANGE`, `AUTHORIZED_CONFIG_CHANGE`, `UNAUTHORIZED_READ`, `UNAUTHORIZED_CHANGE`, `UNAUTHORIZED_CONFIG_CHANGE`, `UNAUTHORIZED_ACCESS`, `SPOOFED_SOURCE`, `PROTOCOL_ANOMALY`.

Design rule (from the open-items doc): detection is on **"source not in allowlist"**, never on IP distance; `.99` being far from the others is only a visual aid for the demo.

### 4.4 `evidence_log.py` (log)

| Name | What it does |
|---|---|
| `EvidenceLog(path)` | Opens a log for append. If the file exists it is **verified first**; a broken chain refuses to append (preserve it, start a new file) |
| `EvidenceLog.write(record)` | Adds `seq`, `prev_hash`, `hash`; writes one canonical JSON line; `flush` + `fsync` |
| `EvidenceLog.write_session_start(sensor, config_sha256)` | First record of a run: host, OS, Python version, config hash |
| `verify(path)` | Recomputes the chain → `(ok, records, first_bad_seq, message)` |
| `export_csv(path, out)` | Flattens the log to CSV for spreadsheets/report tables |
| `utc_iso(ts)` | ISO-8601 UTC with microseconds (`...Z`) |

Hash: `hash = SHA-256(prev_hash ‖ canonical_json(record without hash))`, genesis `prev_hash` = 64 zeros. This makes tampering **evident** (any edit, deletion or reordering is detected from that record on) but not **impossible**: someone with write access can rebuild the whole chain. Mitigation: record the chain head hash in the case notes / report after each run.

### 4.5 `events.py`

| Function | Output |
|---|---|
| `request_record(frame, verdict, ...)` | REQUEST record (fields in §6) |
| `response_record(resp, req_rec, ...)` | RESPONSE record with `outcome` = `ACCEPTED_BY_PLC`, `REJECTED_BY_PLC (exception n: name)` or `OK`, plus `latency_ms` from request to response |

### 4.6 `proxy.py` (block)

`GuardianProxy(config, evlog, baseline)`:

| Method | What it does |
|---|---|
| `serve()` | `asyncio.start_server` on `proxy.listen_host:listen_port` |
| `handle_client()` | Per client connection: read one MBAP frame at a time → `parse_frame` → `Policy.evaluate` → log → block or forward. Connects to the PLC lazily on the first allowed request |
| `relay_upstream()` (inner) | Relays PLC responses to the client; correlates by transaction ID; logs the outcome of writes/config and any exception |
| `_read_frame()` | Reads exactly one MBAP frame; rejects invalid length (logged `MALFORMED`, connection closed) |
| `_maybe_reload()` | Hot-reloads `config.json`; logs `CONFIG_RELOADED` with new hash, mode, allowlist |

Block behaviour (`enforcement.block_response`): `exception` returns a Modbus exception (code `enforcement.exception_code`, default 01 Illegal Function) so the client fails cleanly; `reset` closes the TCP connection. If the PLC is unreachable the client gets exception 0x0B and an `UPSTREAM_ERROR` record is written.

Actions recorded: `FORWARDED`, `BLOCKED`, `FORWARDED (enforcement off: would block)`.

Limitation: in proxy mode the TCP connection ends at Guardian, so only the source **IP** is known (no MAC check).

### 4.7 `analyzer.py` (passive sensor)

| Name | What it does |
|---|---|
| `tcp_payload(pkt)` | Payload length from the IP total length, **not** `len(tcp.payload)`: short Ethernet frames are padded and scapy reports the padding as payload (seen in `modbus_capture_practice.pcapng` frame 2) |
| `Analyzer.process(pkt, frame_no)` | Per-flow TCP reassembly by sequence number; skips retransmissions; resyncs on capture gaps; marks a flow dead on invalid MBAP length |
| `Analyzer._handle_frame()` | Requests → policy + REQUEST record; responses → correlated by `(client ip, client port, TID)` → RESPONSE record; annotates the in-memory request with `_outcome` for reports |
| `analyze_pcap(path, ...)` | Runs the analyzer over a pcap/pcapng (read-only) |
| `sniff_live(iface, ...)` | scapy `sniff` with BPF `tcp port 502` |

Also tracks every IP's MAC set and first-seen time (used to flag multiple MACs per IP), and counters (`requests`, `req_<category>`, `decision_<X>`, `responses`, `exceptions`, `retransmissions_skipped`, `stream_gaps`, `malformed_streams`).

### 4.8 `baseline.py` (experiment 1)

`build_baseline(analyzer, pcap)` → per source: MACs, request count, categories, function codes, unit IDs, set of `fc:addr:qty` signatures (`90:sub<code>` for FC 90), min/max of written values per point, median polling interval, requests/s; plus the capture's SHA-256 and time window. `format_baseline()` prints it. Saved as JSON and fed back with `--baseline` to raise `BASELINE_DEVIATION`.

### 4.9 `forensics.py` (experiment 4)

`build_report()` writes Markdown with: 1 Evidence (file, SHA-256, size, frames, first/last packet UTC, config hash, log chain head); 2 Summary (counts by decision/event, unauthorized sources); 3 Hosts (IP, MACs with mismatch/multi-MAC flags, identity, requests by category); 4 Findings per unauthorized source (active window, frames, rules, attempted changes, **accepted by the PLC or not**); 5 Timeline (all notable events + first contact per host); 6 Authorized changes; 7 Method and limitations.

### 4.10 `guardian.py` (CLI)

| Command | Inputs | Outputs |
|---|---|---|
| `proxy [--listen h:p] [--upstream h:p] [--mode monitor\|block]` | config | live console alerts, evidence log |
| `monitor --iface NAME` | live NIC | console, evidence log |
| `analyze PCAP [-q]` | capture | `logs/<pcap>_events.jsonl` |
| `baseline PCAP [-o file]` | clean capture | `baseline.json` + printed profile |
| `forensics PCAP [-o dir]` | mixed capture | `reports/<pcap>/report.md`, `events.jsonl`, `events.csv` (refuses to overwrite) |
| `verify LOG` | log | PASS/FAIL, exit code 0/1 |
| `export LOG CSV` | log | CSV |

Global options: `--config`, `--baseline`, `--log`.

### 4.11 Test tools

* `tools/mock_plc.py --port 5020`: in-memory 100 coils / 100 holding registers; prints every write that reaches it (shows what got past Guardian).
* `tools/modbus_client.py HOST[:PORT] read-hr|read-coils|write-reg|write-regs|write-coil ...`: lab-only client used as HMI/attacker stand-in. Use only on the isolated lab network (CLAUDE.md evidence rules).

---

## 5. Configuration schema (`config.json`)

| Key | Meaning | Current value |
|---|---|---|
| `plc.ip` / `plc.port` / `plc.unit_ids` | PLC identity | `192.168.8.11` / 502 / `[1, 255]` (unit 1: pymodbus, practice capture frame 4; unit 255: HMI, Port_mirroring_test_3) |
| `authorized_sources.<ip>.name/mac/allow` | Allowlist | `.10` HMI (read, write), MAC `00:00:54:0b:c5:9a`; `.50` Eng laptop (read, write, config), MAC `a0:ce:c8:62:e9:e1` |
| `authorized_sources.<ip>.fc90_read_subcodes` | FC 90 sub-codes treated as reads for that source | `.10` HMI: `[116]` (0x74 status poll, Port_mirroring_test_3). Every other FC 90 sub-code stays `config` |
| `unknown_sources.allow_reads` | Let unknown hosts read? | `false` |
| `protected_points[]` | `name, table, start, end, min, max, read_only, enabled` | Confirmed `%M` coil map **enabled** (S-005): `%M2/%M3/%M5` 0..1, `%M4` 0..0 (bypass ON alerts/blocks), `%MW0` read-only |
| `enforcement.mode` | `monitor` or `block` | `block` |
| `enforcement.block_response` / `exception_code` | `exception` or `reset` / code | `exception` / 1 |
| `enforcement.block_out_of_range_from_authorized` | | `false` |
| `enforcement.block_unexpected_unit_id` | | `false` |
| `proxy.listen_host/listen_port/upstream_host/upstream_port/connect_timeout_s` | Inline proxy | `0.0.0.0:502` → `192.168.8.11:502`, 3 s |
| `log.path` / `log.log_allowed_reads` | | `logs/guardian_events.jsonl` / `false` (routine reads counted, not logged) |

---

## 6. Evidence record schema

Every line is one JSON object. Common fields: `seq`, `record`, `ts_utc`, `ts_source` (`pcap` / `host_clock`), `sensor` (`proxy`, `live:<iface>`, `pcap:<file>`), `prev_hash`, `hash`.

| `record` | Written when | Key fields |
|---|---|---|
| `SESSION_START` | Start of every run | host, platform, python, `config_sha256`, evidence file + SHA-256 (pcap modes), enforcement mode (proxy) |
| `REQUEST` | Notable request (or every request if `log_allowed_reads`) | `frame_no`, `src_ip/mac/port`, `dst_ip/mac/port`, `source_name`, `tid`, `unit`, `fc`, `fc_name`, `category`, `table`, `address`, `quantity`, `values` (writes), `subcode`, `summary`, `event_type`, `decision`, `authorized`, `rules`, `details`, `action`, `pdu_hex` |
| `RESPONSE` | PLC reply to a logged request, or any exception | `request_seq`, `tid`, `fc`, `summary`, `outcome`, `latency_ms` |
| `MALFORMED` | Invalid MBAP stream | `details`, `raw_hex`/frame, `action` |
| `CONFIG_RELOADED` | Proxy detects config change | `config_sha256`, `enforcement_mode`, `authorized_sources` |
| `UPSTREAM_ERROR` | Proxy cannot reach PLC | `details` |
| `SESSION_END` | Clean shutdown | `stats` |

---

## 7. Verification done (S-002, 2026-10-21)

| # | Test | Evidence | Result |
|---|---|---|---|
| V-1 | Decode real request/response | `modbus_capture_practice.pcapng` frames 4–5 (filter `mbtcp`): request `00010000000601030000000a` → FC3 addr 0 qty 10 unit 1; response 20 bytes, all zero | Pass |
| V-2 | Policy on real request | `.50` → ALLOW / NORMAL_READ; same frame from an unlisted IP → BLOCK / UNAUTHORIZED_READ / SRC_NOT_ALLOWLISTED | Pass |
| V-3 | Offline pipeline | `analyze`, `baseline`, `forensics` on the practice capture; report in `guardian/reports/practice/` | Pass |
| V-4 | Evidence not altered | SHA-256 of practice capture `ad9cc550…b630` identical before and after | Pass |
| V-5 | Log integrity | Copy of `events.jsonl` with one field edited → `FAIL line 2 (seq 2): content hash mismatch` | Pass |
| V-6 | Proxy forwarding | Authorized read via proxy (127.0.0.1:5021) → `mock_plc.py` (5020) returned `[0, 0, 0, 0]` | Pass |

Not yet verified: blocking on hardware; live sniffing on Windows/Npcap; real write traffic; real HMI polling pattern; FC 90 behaviour of the M221; proxy throughput/latency overhead.

---

## 8. Known limitations and open issues

1. **Topology dependency**: blocking only works if the PLC is reachable solely through Guardian (A-004). Fail-closed.
2. **No MAC in proxy mode**; a host spoofing both IP and MAC of an allowed host defeats the allowlist rule in passive mode.
3. **Register map undefined**: value-range protection is disabled (A-005).
4. **FC 90 sub-codes** use UMAS names that are [UNVERIFIED] for the M221.
5. **TCP reassembly is simple**: in-order only, retransmissions skipped, gaps resync (counted in stats).
6. **Proxy**: exceptions returned for unlogged routine reads are not logged; `SESSION_END` is written only on Ctrl+C (not on SIGTERM); pipelined requests with a reused transaction ID would overwrite each other in the pending table.
7. **Timestamps** depend on the Guardian/capture host clock; sync before the demo.
8. **No automated test suite or synthetic test captures** yet; experiments 2–4 rely on real lab captures.
9. Live `frame_no` counts packets matching the capture filter, so it does not equal Wireshark frame numbers.

---

## 9. Mapping to the required experiments and demo

| Experiment / demo step | Guardian components | Command | Output to keep for the report |
|---|---|---|---|
| 1 Normal traffic | analyzer, baseline | `baseline normal.pcapng -o baseline.json` | baseline profile (sources, FCs, signatures, polling interval) |
| 2 Authorized change | policy (AUTHORIZED_CHANGE), evidence_log, proxy forward | `proxy` (block) or `analyze` | REQUEST + RESPONSE `ACCEPTED_BY_PLC` records |
| 3 Unauthorized change | policy (UNAUTHORIZED_*), evidence_log, proxy block | `proxy --mode block` | REQUEST `BLOCKED` records, PLC values unchanged |
| 4 Forensic investigation | analyzer, forensics | `forensics mixed.pcapng` | `report.md` timeline, findings, hosts |
| Demo Iteration 1 | proxy | `proxy --mode monitor` | "would block" records, process malfunctions |
| Demo Iteration 2 | proxy | `proxy --mode block` | `BLOCKED` records, process normal |
