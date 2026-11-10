# PLC Guardian: Software Design Reference

_Technical reference for the Python implementation in `guardian/`. Version 0.1.0 · written S-002 · 2026-10-21._
_Decisions behind this design: D-002 (Python replaces C), D-003 (inline Modbus proxy for blocking), D-008 (connection-level inline gate for the HMI's web API, partial mitigation for R-004), D-009 (passive HTTP-connection trigger for the D-007 lockout, for deployments without `httpgate.py` inline)._
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
| HTTP gate | `guardian.py httpgate` | Between clients and the HMI's web API | **Yes, per source IP only** (`enforcement.mode = block`) | D-008, partial mitigation for R-004 |
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

The same dependency applies to `httpgate.py` (D-008) for the HMI's web API: it only prevents anything if `.10:80` is reachable solely through it. That topology isn't built either (A-033) — until it is, pointing a test client's HTTP requests directly at `http_gate.listen_port` is how to exercise the gate; it is not yet in the path of real attacker traffic aimed at the HMI's real address.

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
| `guardian/plcguard/httpgate.py` | **Block (partial)** | asyncio inline TCP-level gate for the HMI's web API — IP allowlist only, no HTTP parsing (D-008) |
| `guardian/plcguard/active_response.py` | **React (D-007)** | Guardian's own FC5 lockout-coil write, fired from a trusted trigger's BLOCK verdict |
| `guardian/plcguard/http_watch.py` | Passive sensor (D-009) | scapy sniffer for new TCP connections to the HMI's web port from an unauthorized source; feeds the SAME `ActiveResponder` as the Modbus sniffer |
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
| `EvidenceLog(path)` | Takes an OS-level exclusive lock FIRST, before touching the real log at all, then (if the file exists) **verifies it** and refuses to append on a broken chain (preserve it, start a new file), then opens it for append. The lock is on a tiny **sidecar** file (`path + ".lock"`), never on the real log's own bytes (D-008 round 2 should-fix 6 — locking the real file made Windows block even a read-only opener of a live log, and let `verify()`'s own read, happening before any lock existed, surface a raw `PermissionError` instead of a clean error); refuses to start (`RuntimeError`) if something else already holds that sidecar lock (round 1 BLOCKER 1 — two processes appending to one log split the hash chain with no error until the next `verify()`). Held for the life of the handle, released on `close()` |
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

### 4.6a `httpgate.py` (block, partial — D-008)

`HttpGate(config, evlog, on_reload=None)`:

| Method | What it does |
|---|---|
| `serve()` | `asyncio.start_server` on `http_gate.listen_host:listen_port` |
| `handle_client()` | Per connection: decide once from source IP against `authorized_sources` (source must be present AND have `"write"` in its `allow` list — round 1 should-fix 8) → write the `HTTP_CONNECTION` decision record immediately → block (close, nothing relayed) or connect upstream, write it, then relay both directions byte-for-byte |
| `_is_authorized()` | The one place the write-permission check lives; also used by `_revoke_now_unauthorized()` so a reload re-checks with the exact same rule a new connection would get |
| `_maybe_reload()` | Hot-reloads `config.json`; calls `on_reload(config)` first (so a caller like `cmd_httpgate` can re-apply CLI overrides `config.load()` just wiped — round 1 should-fix 4), then `_revoke_now_unauthorized()` |
| `_revoke_now_unauthorized()` | Closes any already-open, still-relaying connection a reload just made unauthorized (round 1 should-fix 5 — without this, proxy.py re-evaluates every frame but this gate only decided once, at connect time). Keys off a `relayed` flag, not `authorized` (round 2 should-fix 2 — a connection forwarded under `monitor` mode is `authorized=False` for its whole life by design, so checking that would wrongly skip revoking it if the mode later flips to `block`) |
| `_safe_write()` | Every `evlog.write()` call goes through this: catches `OSError` **and** `RuntimeError` (the latter from `EvidenceLog.write()` after `close()`) and prints `[ERROR]` instead of the exception propagating silently. On the ALLOW/FORWARDED path its return value is checked and the connection fails closed on `None` (round 2 BLOCKER — a log-write failure must never let a connection relay with no evidence record) |
| `flush_suppressed_blocks()` | Writes one final record for every source whose BLOCK/capacity-rejection logging was still rate-limited when the gate stopped, so that count isn't lost (round 2 should-fix 5); called from `cmd_httpgate`'s `finally` before `SESSION_END` |
| `_log_rate_limited()` / `_prune_block_log_entries()` | Shared per-source-IP rate limiting for BLOCK and `REJECTED_MAX_CONNECTIONS` records alike (round 2 nit 8), with a size-gated prune of the tracking dicts (round 2 nit 9) |
| a background task in `serve()` | Calls `_maybe_reload()` roughly once a second for the life of the server (round 2 should-fix 3 — revocation previously only ran when some *new* connection happened to arrive) |

Unlike `proxy.py`, this does **not** decode HTTP. The `HTTP_CONNECTION` decision record is written before the upstream connect is even attempted, so it exists unconditionally — round 1's BLOCKER 2 was that the original version only logged after peeking the first line, so a client that reset mid-peek (e.g. a bare `nmap -sT` with no payload) or sent an over-limit line with no newline (`readline()` raises `ValueError`, not `LimitOverrunError`, on overrun — the original code's `except` clause was dead code) could leave an ALLOWed connection with **no** evidence record at all while the session's own stats still counted it. The first-line peek is now a strictly separate, optional `HTTP_REQUEST_LINE` record, bounded to 256 bytes and `repr()`-escaped before it's ever logged or printed (round 1 should-fix 7 — unescaped attacker bytes on the console is an ANSI-injection vector). An unlisted (or read-only) source's connection is refused outright, with nothing relayed; an authorized source's traffic of any kind (including the exact `POST /services/variable/hmi/1` write from R-004) is forwarded unmodified. Same shutdown pattern as `proxy.py`'s `serve()` (doesn't await `server.wait_closed()`, for the same Python 3.12.1+ reason).

Other round-1 fixes: half-close support in the relay (`write_eof()` instead of a full `close()` on one direction's EOF, so a client that stops sending but still wants the reply — should-fix 3 — doesn't lose it); an idle timeout and a `max_connections` cap (should-fix 6, `http_gate.idle_timeout_s`/`max_connections`); BLOCK evidence writes are rate-limited per source IP (`_BLOCK_LOG_INTERVAL_S` = 2s) so a connect flood can't turn into an fsync flood; `http_gate.log_path` defaults to its **own** evidence log file, not `log.path` (BLOCKER 1 — two processes appending to the same log split the hash chain; `EvidenceLog` itself now also refuses to open a file something else already has open, see §4.4). Block behaviour and `enforcement.mode` reload are otherwise shared with `proxy.py`.

**On the `EvidenceLog` sidecar lock (§4.4):** because the lock is taken on `path + ".lock"` and never on the real log file's own bytes, a plain `verify`/`export`/`tail -f` of the real log works fine on both Windows and POSIX even while another process holds the write lock — this was the whole reason round 2 moved off locking the real file (an earlier version locked the real file directly, which made Windows block even a read-only opener of a live log; fixed before this design doc's current state).

**Reconciling the rate-limited counts:** because should-fix 8 shares one rate-limit bucket per source IP between BLOCK and `REJECTED_MAX_CONNECTIONS` (nit 8), `stats["blocked_suppressed"]` can include capacity rejections, not just BLOCKs, while `stats["blocked"]` only counts BLOCKs. The numbers that should reconcile are **logged BLOCK + REJECTED_MAX_CONNECTIONS records, plus `blocked_suppressed`**, against **`stats["blocked"] + stats["rejected_capacity"]`** — not `blocked_suppressed` against `blocked` alone.

### 4.6b `active_response.py` (react — D-007)

`ActiveResponder(config, evlog, extra_triggers=None)`, one instance per `monitor` run, built in `cmd_monitor` and shared by BOTH trigger sources below:

| Name | What it does |
|---|---|
| `maybe_respond(request_rec)` | Called for every REQUEST record a trigger source writes, from either the Modbus sniffer's thread or `http_watch.py`'s thread. If `active_response.enabled`, the record's `decision` is in `trigger_decisions`, and its destination is trusted (below), acquires `self._lock`, then issues one FC5 write of `lockout_coil` → ON to the PLC (subject to `cooldown_seconds`) and logs an `ACTIVE_RESPONSE` record (`SUCCEEDED`/`FAILED`/`SKIPPED_COOLDOWN`/`INTERRUPTED`) |
| `inactive(config, evlog, extra_triggers=None)` | No-op fallback used when the real constructor's own config validation fails (I-008 item 4), so a bad `active_response` section degrades `monitor` mode instead of crashing it |
| Destination trust (I-008 item 2, generalized D-009) | `dst_ip == config.plc_ip` is trusted **unconditionally, from any sensor** — today's original behaviour, unchanged. Any OTHER destination is trusted only when `(request_rec["sensor"], request_rec["dst_ip"], request_rec["dst_port"])` is one of the tuples in `extra_triggers` (e.g. `("http_watch", hmi_ip, hmi_port)`). This is keyed on **who produced the record**, not just where it was addressed — a D-009 architect-review round-1 BLOCKER found that a flat "trusted destination IPs" set let a *Modbus*-sourced BLOCK record addressed to the HMI's IP also fire the real PLC lockout write, which the feature was never meant to do; `cmd_monitor` only ever adds the HMI as `("http_watch", hmi_ip, hmi_port)`, so only a record `http_watch.py` itself wrote, addressed to that exact host:port, can use it |
| `self._lock` (D-009 round-2 should-fix) | A `threading.Lock` held across the entire cooldown-check → send → log sequence, since `maybe_respond()` is now called concurrently from two threads sharing one `ActiveResponder`; without it, both could pass the cooldown check before either updated `_last_fired`, firing two real FC5 writes |

Guardian's own outbound lockout write is skipped as a trigger by `own_ip`/lockout-value checks (I-008 item 3); these, the cooldown value, and config validation are untouched by D-009. `_log()` also tolerates the evidence log already being closed (a background sniffer thread can still be mid-callback for a brief window after `cmd_monitor`'s shutdown starts): the write attempt is caught and surfaced loudly on the console instead of crashing the calling thread or silently losing the record.

### 4.6c `http_watch.py` (passive sensor — D-009)

`sniff_http_watch(iface, config, evlog, on_event=None, stop_event=None)`, mirrors `analyzer.sniff_live()`'s scapy usage:

| Name | What it does |
|---|---|
| `build_http_request_record(...)` | Builds one REQUEST-shaped record (`sensor="http_watch"`, `decision="BLOCK"`, `action="OBSERVED"`) for a SYN to the HMI's web port from an unauthorized or spoofed source — `event_type`/`rules` are `UNAUTHORIZED_HTTP_ACCESS`/`["SRC_NOT_ALLOWLISTED_HTTP"]` normally, or `SPOOFED_SOURCE`/`["MAC_MISMATCH"]` when the source IP is listed but its MAC doesn't match (mirrors `policy.py`'s `MAC_MISMATCH`) |
| `HttpWatch.handle_syn(src_ip, src_port, ts, src_mac=None)` | Skips a source only when its IP is in `config.sources` **and** its MAC matches (or none is configured) — reuses the SAME `authorized_sources` allowlist, no second one. De-dupes retransmitted SYNs for the same `(src_ip, src_port)` within `_DEDUP_WINDOW_S`; separately rate-limits to at most one REQUEST record per source IP per `_RATE_WINDOW_S`, folding any suppressed attempts into the next record's `details` (SYN-flood/port-scan guard, so quiet-port-80 noise can't out-write the Modbus sniffer's own evidence writes through the shared log lock) |
| `sniff_http_watch(...)` | Loops short, bounded `sniff(timeout=1s, ...)` slices with BPF `tcp port {hmi_port} and host {hmi_ip}` (both from `http_watch.hmi_ip/hmi_port`) instead of one unbounded `sniff()` call — scapy's `stop_filter` is only polled between received *packets*, so on quiet traffic an unbounded call could never notice `stop_event`; the bounded-slice loop guarantees it returns within about one slice of `stop_event.set()` regardless of traffic volume (D-009 round-2 BLOCKER) |

**Passive, not inline** (restated from the module docstring because this is easy to misread given it shares `ActiveResponder` with the Modbus side): this module cannot stop the attacker's TCP SYN/HTTP request from reaching the HMI — only `httpgate.py` (D-008, inline, built — §4.6) can, and only once Guardian actually sits in the path (the same not-yet-built inline topology dependency as `proxy.py`, A-004/A-033). `http_watch.py` detects the connection attempt and, via `cmd_monitor`'s shared `on_event` callback, feeds it to the SAME `ActiveResponder.maybe_respond()` the Modbus sniffer uses, so a D-007 lockout write can follow after the fact — "attack lands, compensating control follows," same framing as the Modbus BLOCK case.

`cmd_monitor` runs this on a background `threading.Thread` (daemon) alongside the existing Modbus `sniff_live()` call, gated entirely behind `http_watch.enabled` (off by default — nothing changes unless set; a null/empty `http_watch.hmi_ip` also keeps it off, with a clear console message, rather than silently matching every destination). If the thread fails to start, or `sniff()` raises for any reason (e.g. Npcap/permissions), the exception is caught and logged to the console; `monitor` mode continues running its Modbus sniffing and still writes `SESSION_END` (same bar as I-008 item 6). On shutdown, `cmd_monitor`'s `finally` (1) disarms SIGTERM/SIGBREAK/SIGINT first via `_ignore_stop_signals()`, same as `cmd_proxy`'s A-016/A-025 fix, so a second Ctrl+C during the join below can't skip `SESSION_END`; (2) sets `responder.active = False` **before** touching the thread, so even a packet that slips in during the join window can't fire a live write; (3) sets the thread's `stop_event` and joins it with a 3s timeout; (4) if the thread is still alive after that, records `http_watch_thread_stuck_at_shutdown: true` in `SESSION_END` rather than silently proceeding as if it had stopped (it is a daemon thread, so it cannot block process exit either way).

**Operational note (I-009 lesson, restated for this module):** arm `http_watch.enabled=true` with `active_response.enabled=false` first, enumerate every real source that legitimately connects to the HMI's web port, and add all of them to `authorized_sources` with the correct MAC before ever enabling `active_response` against it — exactly the discipline that was missing the first time D-007 was armed live on the Modbus side.

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

`build_report()` writes Markdown with: 1 Evidence (file, SHA-256, size, frames, first/last packet UTC, config hash, log chain head); 2 Summary (counts by decision/event, unauthorized sources); 3 Hosts (IP, MACs with mismatch/multi-MAC flags, identity, requests by category); 4 Findings per unauthorized source (active window, frames, rules, attempted changes, **accepted by the PLC or not**) **and an "Authorized-source requests with decision ALERT/BLOCK" subsection** (authorized sources that still tripped a policy rule, e.g. a protected-point write); 5 Timeline (all notable events + first contact per host); 6 Authorized changes; 7 Method and limitations.

§3 Hosts, §4 Findings and §6 Authorized changes all report a request's **effective category** (`_cat()` in `forensics.py`), not the raw decoded frame category: the REQUEST record's `category` field is the frame's as-decoded category (e.g. FC 90 = `config`), but `Policy.evaluate()` can reclassify a specific FC 90 sub-code as a `read` for a source listed in that source's `fc90_read_subcodes` (§4.3); that reclassification only shows up in `event_type`, so counts and tables key off `event_type` via `_EV_CAT`, not the stored `category`, to avoid double-counting a poll as both a config access and a read.

### 4.10 `guardian.py` (CLI)

| Command | Inputs | Outputs |
|---|---|---|
| `proxy [--listen h:p] [--upstream h:p] [--mode monitor\|block]` | config | live console alerts, evidence log |
| `httpgate [--listen h:p] [--upstream h:p] [--mode monitor\|block]` | config | live console alerts, own evidence log (`http_gate.log_path`) |
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
| `authorized_sources.<ip>.name/mac/allow` | Allowlist | `.10` HMI (read, write), MAC `00:00:54:0b:c5:9a`; `.50` Eng laptop (read, write, config), MAC `00:e0:4c:68:00:f4` (corrected S-006/A-029) |
| `authorized_sources.<ip>.fc90_read_subcodes` | FC 90 sub-codes treated as reads for that source | `.10` HMI: `[116]` (0x74 status poll, Port_mirroring_test_3). Every other FC 90 sub-code stays `config` |
| `unknown_sources.allow_reads` | Let unknown hosts read? | `false` |
| `protected_points[]` | `name, table, start, end, min, max, read_only, enabled` | Confirmed `%M` coil map **enabled** (S-005): `%M2/%M3/%M5` 0..1, `%M4` 0..0 (bypass ON alerts/blocks), `%MW0` read-only |
| `enforcement.mode` | `monitor` or `block` | `block` |
| `enforcement.block_response` / `exception_code` | `exception` or `reset` / code | `exception` / 1 |
| `enforcement.block_out_of_range_from_authorized` | | `false` |
| `enforcement.block_unexpected_unit_id` | | `false` |
| `proxy.listen_host/listen_port/upstream_host/upstream_port/connect_timeout_s` | Inline proxy | `0.0.0.0:502` → `192.168.8.11:502`, 3 s |
| `http_gate.listen_host/listen_port/upstream_host/upstream_port/connect_timeout_s` | HTTP gate (D-008) | `0.0.0.0:80` → `192.168.8.10:80`, 3 s |
| `http_gate.log_path/max_connections/idle_timeout_s` | HTTP gate's own evidence log (round 1 BLOCKER 1) and resource bounds (round 1 should-fix 6) | `logs/httpgate_events.jsonl` / 100 / 60 s |
| `http_watch.enabled/hmi_ip/hmi_port` | Passive HTTP-connection trigger for D-007 (D-009) | `false` / `192.168.8.10` / `80` — off by default; see §4.6c |
| `active_response.enabled/lockout_coil/trigger_decisions/cooldown_seconds/unit/timeout_s` | D-007 lockout write, fired from `monitor` mode by either the Modbus sniffer or (if `http_watch.enabled`) `http_watch.py` | see §4.6b; current value `enabled=true, lockout_coil=7, trigger_decisions=["BLOCK"], cooldown_seconds=5, unit=255, timeout_s=2` |
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
| `UPSTREAM_ERROR` | Proxy/gate cannot reach the PLC/HMI | `details` |
| `HTTP_CONNECTION` | `httpgate.py` decision on every connection (D-008) | `src_ip/port`, `dst_ip/port` (gate's own socket), `upstream_host/port` (actual relay target), `source_name`, `authorized`, `decision`, `event_type`, `rules`, `action` (`FORWARDED`/`BLOCKED`/`REJECTED_MAX_CONNECTIONS`/`REVOKED_ON_RELOAD`), `details` |
| `HTTP_REQUEST_LINE` | `httpgate.py`, best-effort, only on an ALLOWed connection whose first line was captured | `src_ip/port`, `request_line` (bounded to 256 bytes, `repr()`-escaped) |
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
6. **Proxy**: exceptions returned for unlogged routine reads are not logged; pipelined requests with a reused transaction ID would overwrite each other in the pending table. `SESSION_END` is now written on Ctrl+C **and** on SIGTERM/SIGBREAK (A-016): the signal handler cancels the running proxy task via `loop.call_soon_threadsafe()` instead of raising, so the cancellation lands at a clean `await` point and can't interrupt `evidence_log.write()` mid-fsync. `_ignore_stop_signals()` (A-023) now disarms SIGTERM, SIGBREAK **and SIGINT** together — a second signal of any of those three received once shutdown has started is ignored (`SIG_IGN`) rather than re-entering the handler or interrupting the write. As of A-025, SIGINT is registered to the *same* handler as SIGTERM/SIGBREAK (`cmd_proxy`'s `_stop`), not left to `asyncio.Runner`'s own default `KeyboardInterrupt` handling, so the *first* Ctrl+C now disarms everything and schedules cancellation immediately too, exactly like SIGTERM/SIGBREAK; the `except KeyboardInterrupt` around `asyncio.run()` is only a fallback for the brief window before that handler is installed. This closes a window left after A-023 where a second Ctrl+C arriving before `cmd_proxy`'s outer `finally` (while `asyncio.Runner` was still unwinding the cancelled task and a client task could be mid `evidence_log.write()`) could still raise `KeyboardInterrupt` at an arbitrary point and corrupt the hash chain. The shared handler also disarms before touching the event loop, and tolerates `loop.call_soon_threadsafe()` raising `RuntimeError("Event loop is closed")` (a narrow race if the signal lands after `asyncio.run()`'s loop starts closing but before `cmd_proxy`'s `finally` runs) — without that ordering, the exception would escape with the handler still armed and skip `SESSION_END` entirely. `GuardianProxy.serve()` no longer does `async with server: await server.serve_forever()`: on Python 3.12.1+, `Server.wait_closed()` (which that `async with` also calls on exit) blocks until every open **client** connection closes, not just the listening socket, so with the HMI still connected, shutdown could otherwise hang indefinitely. `serve()` now awaits a plain `asyncio.Future()` that the cancellation above interrupts directly, then in a `finally` closes the listening socket and every tracked client `StreamWriter` without waiting for `wait_closed()`. On Windows, SIGTERM is not actually deliverable to a Python process by another process (`os.kill`/`TerminateProcess` bypass any registered handler entirely) — only Ctrl+C (SIGINT) and Ctrl+Break (SIGBREAK, sent as `CTRL_BREAK_EVENT` to a process in its own process group) reach a Python signal handler there. A forced kill (`taskkill /F`, Task Manager "End task") still leaves no `SESSION_END` record; that's expected, not a bug.
7. **Timestamps** depend on the Guardian/capture host clock; sync before the demo.
8. **No automated test suite or synthetic test captures** yet; experiments 2–4 rely on real lab captures.
9. Live `frame_no` counts packets matching the capture filter, so it does not equal Wireshark frame numbers.
10. **`httpgate.py` (D-008) is a partial mitigation**: it decides per source IP only (requiring `"write"` permission specifically, round 1 should-fix 8) and cannot distinguish a benign GET from the specific malicious `POST /services/variable/hmi/1` write confirmed in R-004 — any authorized source's HTTP traffic of any kind is forwarded unmodified. It also has the same inline-topology dependency as `proxy.py` (point 1 above), not yet built for the HMI leg (A-033). Architect review: round 1 **FAIL** (2 blockers, 6 should-fix, 4 nits), round 2 **FAIL** (1 blocker, 4 should-fix, 6 nits), round 3 **PASS** (3 should-fix + 4 nits remained; the load-bearing ones fixed directly, the rest tracked as A-036) — full history in D-008, `03_DECISIONS.md`. Not yet run against the real HMI or real attacker traffic — only smoke- and unit-tested against a local fake HMI with temporary configs. An authorized client's legitimately oversized first line (over the ~64KB `StreamReader` buffer limit, with no newline yet) has its buffered bytes cleared by `readline()`'s overrun handling and is not forwarded, though the rest of that connection's stream is still relayed — an accepted limitation of the best-effort request-line peek.
11. **`http_watch.py` (D-009) is detection + reaction, NOT inline**: off by default (`http_watch.enabled=false`). Even when enabled, it only sees a TCP connection attempt to the HMI's web port and logs it + triggers the D-007 lockout write afterward — it cannot stop the original connection or any request on it from reaching the HMI itself; only `httpgate.py` (D-008, inline, and only once the inline topology in point 1 exists for that leg) can actually refuse it. Same "attack lands, compensating control follows" framing as the Modbus-side D-007 BLOCK case. It has not been run against the real HMI/real attacker traffic or architect-reviewed — only unit/smoke-tested (see `guardian/test_runs/`).

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
