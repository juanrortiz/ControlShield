# 03 · Decision Log
_Append-only. Never edit a past decision; supersede it with a new one and mark the old one "Superseded by D-###"._

Status values: Proposed · Accepted · Superseded · Rejected

---

## D-001 · Use a project log kit to track the group project
- **Date / session:** 2026-10-21 · S-001
- **Status:** Accepted
- **Context:** Team project with multiple contributors and deadlines; needs traceable progress, decisions and open items for the final report.
- **Options considered:**
  1. Ad-hoc notes / chat history: no setup, but lossy and hard to report from
  2. Structured log files updated by Claude Code each session: small upfront setup, full paper trail
- **Decision:** Option 2.
- **Rationale:** The session log and decision log feed directly into the final report's methodology section.
- **Consequences:** End each work session with "close session".
- **Approved / informed:** David

---
<!-- Template
## D-### · <short title>
- **Date / session:** YYYY-MM-DD · S-###
- **Status:** Accepted
- **Context:**
- **Options considered:**
  1.
  2.
- **Decision:**
- **Rationale:**
- **Consequences:**
- **Approved / informed:**
-->

## D-002 · Python replaces C as the core Guardian implementation language
- **Date / session:** 2026-10-21 · S-002
- **Status:** Accepted
- **Context:** The brief named C for the analysis tool; the team wants faster development and a demo-ready tool.
- **Options considered:**
  1. Python prototype, port the parser to C later
  2. Python as the official core tool
- **Decision:** Option 2.
- **Rationale:** One codebase covers the parser, policy, evidence log, inline proxy and forensic report; it runs on Windows and Linux.
- **Consequences:** The brief/report must say the tool is in Python; the C requirement is superseded.
- **Approved / informed:** David

## D-003 · Blocking via an inline Modbus/TCP proxy
- **Date / session:** 2026-10-21 · S-002
- **Status:** Accepted
- **Context:** A mirror/SPAN port can only detect. The brief requires real prevention for Iteration 2.
- **Options considered:**
  1. Inline Modbus proxy on Guardian
  2. Switch-assisted port shutdown
  3. Log-only
- **Decision:** Option 1.
- **Rationale:** Real prevention in pure Python, with no dependency on the switch model. `enforcement.mode` toggles monitor (Iteration 1) and block (Iteration 2).
- **Consequences:** The PLC must be reachable only through Guardian (second NIC); this is fail-closed. Physical topology still to be confirmed.
- **Approved / informed:** David

## D-004 · Enable the `%M`/`%MW0` protected points; HMI maintenance bypass alerts, not blocks
- **Date / session:** 2026-10-21 · S-005
- **Status:** Accepted (resolves A-013)
- **Context:** The register map is confirmed on the wire. Without protected points, Guardian catches an unauthorized `%M4` write only as "unknown source," not as the bypass. The HMI legitimately turns `%M4` ON for maintenance.
- **Options considered:**
  1. Enable protected points; authorized out-of-range writes ALERT only (`block_out_of_range_from_authorized=false`)
  2. Enable and block even authorized out-of-range writes
  3. Leave protected points disabled (source-allowlist only)
- **Decision:** Option 1. Protected points enabled in `guardian/config.json`: `%M2/%M3/%M5` 0..1, `%M4` 0..0, `%MW0` read-only.
- **Rationale:** Names the attack (`VALUE_OUT_OF_RANGE: %M4 bypass`) and protects the computed tank level (`%MW0` read-only), while letting the HMI perform real maintenance (its bypass ALERTs, isn't blocked). An unauthorized source is still BLOCKed by the source rule regardless.
- **Consequences:** `%MW1` left unprotected until its meaning is known. If the team wants authorized bypass blocked too, flip `block_out_of_range_from_authorized`.
- **Approved / informed:** David

## D-005 · Add a black-box Experiment 5 alongside the gray-box Experiments 3/4
- **Date / session:** 2026-11-02
- **Status:** Accepted
- **Context:** Experiments 3 and 4 were gray-box — the attacker (`.99`) already knew the register map (`%M4` maintenance bypass, `%MW0` tank level) from `06_REFERENCE.md` before attacking. The team wants a test where the attacker starts from only the PLC's IP, to see whether Guardian still detects/attributes the activity and whether the attacker can rediscover the map on its own.
- **Options considered:**
  1. Reuse the gray-box attack script with no map knowledge fed in. Rejected — doesn't exercise real discovery tooling.
  2. Build a discovery → enumeration → inference pipeline: nmap for port/service discovery (matches how a real external attacker recons), then a read-only pymodbus sweep and classification stage for the Modbus-specific inference.
- **Decision:** Option 2, implemented as `tools/plc_blackbox.py` (adapted from a reference script). Read-only only — no FC5/FC6/FC15/FC16 write probing is in scope; a write-capable black-box test needs its own decision. Runs only against the lab PLC (`192.168.8.11`) on the isolated lab network, by the team, per the evidence/attack-testing rules (CLAUDE.md; D-003, D-004).
- **Rationale:** Matches the brief's forensics focus — contrasting gray-box and black-box attacker knowledge is a stronger report finding than gray-box alone, and nmap-based discovery is realistic attacker tradecraft.
- **Consequences:** New action A-022 (run Experiment 5: capture with `wireshark-capture`, hash + inventory, analyze with Guardian, compare the discovered map against `06_REFERENCE`'s known map).
- **Open question:** whether the black-box run goes through the inline proxy (depends on A-019/A-004, not yet built) or only the port mirror — defaults to port-mirror until the inline topology exists.
- **Approved / informed:** David

## D-006 · Renumber the Exp. 1–4 methodology table
- **Date / session:** 2026-11-02 · S-006
- **Status:** Accepted
- **Context:** The team wants to run three new tests — nmap + HMI web-portal bypass, a direct-Modbus `%M4` flip with Guardian detection, and an inline IPS test — that don't map 1:1 onto the original Exp. 1–4 table in `07_REPORT_NOTES.md` (1 Normal baseline, 2 Authorized change, 3 Unauthorized change, 4 Forensics).
- **Options considered:**
  1. Leave the old table and describe the new tests separately, risking the two schemes being confused in the report.
  2. Rewrite the table with the new definitions, explicitly flagging that it supersedes the version used through S-005.
- **Decision:** Option 2. New table: 1 = Recon + web-portal bypass, 2 = Direct-Modbus bypass flip + overload, 3 = Inline IPS (NIPS), 4 = Forensics (kept, general-purpose).
- **Rationale:** A single, current table beats two competing numbering schemes; a one-line supersession note plus descriptive capture filenames (not bare "Experiment N") avoids the exact collision already documented for `Experiment_4.pcapng`.
- **Consequences:** `Experiment3_capture.pcapng`/`Experiment_4.pcapng` (old numbering) keep their original meaning as recorded in `06_REFERENCE.md` — not reinterpreted against the new table. The old table's baseline category (previously "Exp. 1") has no number under the new scheme; noted in `07_REPORT_NOTES.md`.
- **Approved / informed:** David

## D-007 · Reactive PLC-side interlock as the near-term Iteration-2 approach; true inline prevention (D-003) deferred
- **Date / session:** 2026-11-04 · S-006
- **Status:** Accepted
- **Context:** D-003 chose an inline Modbus proxy for real prevention, needing Guardian physically in the PLC's path (2nd NIC, PLC re-cabled). That rewiring hasn't happened yet. A capture taken without it (`exp3_no_inline_baseline_2026-11-04.pcapng`) confirmed the obvious: a passive mirror can detect and log a BLOCK decision, but the real PLC still accepts the attacker's write — a SPAN/mirror port is architecturally one-way; the switch has already forwarded the original frame before Guardian (on the mirror port) sees a copy. Switch-assisted port shutdown (D-003's Option 2) was investigated as an alternative and ruled out: the lab switch (TP-Link TL-SG105E) has no SNMP and no scriptable interface of any kind — confirmed both from its own web UI (no SNMP menu) and TP-Link's own community forum (the same question, unanswered). The team then proposed a third approach: have Guardian itself write to a new, dedicated PLC coil that ladder logic treats as a lockout, using connectivity Guardian already has.
- **Key fact enabling this:** Guardian's host (`.50`) already has live, two-way Modbus write access to the real PLC *today*, with no rewiring — confirmed from existing evidence (`Experiment 2.pcapng`, `mixed_hmi_attacker_2026-11-02.pcapng`): `.50`'s own FC1/FC3 requests get real PLC responses over the normal switch fabric, not just mirrored copies. Port 5 is mirroring-*and*-normal, not receive-only.
- **Options considered:**
  1. Wait until the physical rewiring is done before any Iteration-2 test. Rejected for now — no timeline on the rewiring, and this gives a usable interim result.
  2. Switch-assisted port shutdown. Rejected — infeasible on this switch (no SNMP/API).
  3. Reactive PLC-side interlock: a new coil (e.g. `%M7`/GUARDIAN_LOCKOUT) added to the PLC program; when Guardian's live monitoring flags a BLOCK-worthy event, it immediately issues its own authorized FC5 write to set that coil, and ladder logic forces a safe state regardless of the attacker's write.
- **Decision:** Option 3, pursued now; Option 1 (D-003's true inline proxy) remains the long-term goal and will be tested separately when the physical topology is ready.
- **Rationale:** Unlike switch shutdown, this doesn't depend on the switch at all, and it's buildable immediately. It is explicitly **not** equivalent to D-003's "real prevention" criterion (A-019: "attacker's write never reaches the PLC") — the malicious write still lands at the PLC; Guardian's counter-write arrives after it, not before. What it can plausibly prevent is the *physical consequence*: Experiment 2's real data showed ~8.6s from the `%M4` flip to the tank crossing the overload threshold, almost certainly far longer than Guardian's detect-and-counter-write round trip. Report this as a reactive compensating control, explicitly distinct from true inline prevention, and keep both results (this one now, the inline one later) as a defense-in-depth comparison rather than picking one.
- **Consequences:** Needs a new PLC program change (team, in the dev software: add the lockout coil + a ladder rung that forces safety when it's set) and new Guardian code (an "active response" capability that doesn't exist yet — `monitor` mode is currently detect-and-log only). `config.json`'s MAC entry for `.50` is stale (flagged `SPOOFED_SOURCE`/`MAC_MISMATCH` in recent forensic reports) and should be corrected so Guardian's own remediation writes aren't misattributed. Safety-relevant change (Guardian now issues live writes to the PLC automatically) — goes through the project's maker-checker/architect review before being trusted.
- **Approved / informed:** David

## D-008 · Add a connection-level inline gate for the HMI's web API (partial mitigation for R-004)
- **Date / session:** 2026-11-09
- **Status:** Accepted
- **Context:** Retesting nmap/black-box recon against the real lab network re-confirmed R-004 (the HMI's web API on `.10:80` accepts the maintenance-bypass write and Guardian, watching only port 502, sees none of it). The team asked whether Guardian blocks port 80 too — it doesn't; `proxy.py` only ever listens on one Modbus port, and nothing in the codebase parses HTTP.
- **Options considered:**
  1. A firewall rule on the HMI host/switch, outside Guardian entirely. Fastest, but not part of the tool and produces no evidence-log record for the report.
  2. A thin TCP-level inline gate: reuse the existing `authorized_sources` IP allowlist, decide once at TCP-connect time, no HTTP parsing. Cheap, logged to the same hash-chained evidence log, but all-or-nothing per source IP.
  3. A full HTTP-aware proxy (its own request-line/path decoder + policy, mirroring `modbus.py`+`policy.py`), able to allow a GET but block the specific `POST /services/variable/hmi/1` write.
- **Decision:** Option 2, implemented as `guardian/plcguard/httpgate.py` + a new `guardian.py httpgate` subcommand.
- **Rationale:** Keeps the fix inside Guardian's own evidence chain (unlike Option 1) for a fraction of Option 3's effort; Option 3 remains the "proper" fix if there's time later.
- **Consequences:** The gate cannot distinguish a benign GET from the exact malicious `POST /services/variable/hmi/1` write R-004 already confirmed — any authorized source's HTTP traffic of any kind is forwarded unmodified. Same A-004-style inline-topology dependency as the Modbus proxy: it only prevents anything if the HMI is reachable solely through it, and that physical/network step is **not done** — nothing currently forces real attacker traffic aimed at `.10:80` through this gate. New `http_gate` section added to `config.json`.
- **Architect review round 1 (A-034): FAIL.**
  - **BLOCKER 1:** `httpgate.py` defaulted to the same evidence log path (`log.path`) as `proxy`/`monitor`; two processes appending to one log split the hash chain silently. Fixed: `http_gate.log_path` is now its own file, and `EvidenceLog.__init__` takes an OS-level exclusive lock, refusing outright to open a file something else already has open.
  - **BLOCKER 2:** the `HTTP_CONNECTION` record was only written after peeking the connection's first line; a client reset mid-peek or an over-limit line with no newline (`readline()` raises `ValueError`, not the `LimitOverrunError` the code's `except` clause actually caught — dead code) could leave an ALLOWed connection with no record at all, while `stats` still counted it. Fixed: the decision record is now written before the upstream connect is even attempted; the first-line peek became a separate, optional `HTTP_REQUEST_LINE` record that can never prevent the main one. `u_writer` is now closed in all paths (previously leaked on several early returns).
  - **Should-fix, applied:** (3) half-close support in the relay (`write_eof()` instead of a full close on one direction's EOF, so a client that stops sending early doesn't lose the HMI's reply); (4) CLI overrides (`--listen`/`--upstream`/`--mode`) are now re-applied after every config hot-reload, and an empty `upstream_host` now fails closed instead of resolving to loopback; (5) a reload that revokes a source's authorization now closes that source's already-open connections, not just future ones; (6) `http_gate.max_connections`/`idle_timeout_s` bound concurrent connections and per-connection staleness, and repeated BLOCKs from one source are rate-limited in the evidence log (once per 2s, with a suppressed-count note) instead of fsync-flooding; (7) the logged/printed request-line preview is now bounded to 256 bytes and `repr()`-escaped (the original was an ANSI-injection vector via the console); (8) the gate now requires `"write"` in a source's `allow` list, not just presence in `authorized_sources` — matching `policy.py`'s semantics instead of diverging from them (no live-config source is read-only today, so this changed no current behavior).
  - **Nits, applied:** doc sync (§4.6a, §4.10, §6, config schema, limitation #10 all updated to match); `HTTP_CONNECTION` now carries explicit `upstream_host`/`upstream_port` fields (distinct from `dst_ip`/`dst_port`, which stay the gate's own socket) since the upstream target can change across a reload; a log-write `OSError` now prints `[ERROR]` to the console instead of failing silently.
  - **Not yet done:** re-running a load/signal-handling check (the `double_sigint_under_load_check.py` style test) against `httpgate.py` specifically — the signal-handling code itself is an exact copy of `proxy.py`'s already-reviewed pattern, confirmed by direct comparison, but not re-exercised under load here.
  - Round-2 fixes verified by 14 targeted checks (separate-log + lock refusal, guaranteed record on client reset, write-permission requirement, max-connections rejection, half-close response delivery, reload-revocation, oversized/control-character request line) — all pass; PM3 regression (`config_mapped.json` against `Port_mirroring_test_3.pcapng`) still 150/150 ALLOW after the shared `evidence_log.py`/`config.py` changes. Submitted for architect review round 2.
- **Architect review round 2: FAIL, 1 blocker** — narrower than round 1 (most of round 1's should-fix items confirmed correct: lock behavior in the normal single-writer case, half-close via `write_eof`, `max_connections` check has no race, CLI-override reapplication, `_is_authorized` as the single source of truth, `readline()`'s `ValueError`-not-`LimitOverrunError` behavior confirmed, `_preview()`'s escaping, `u_writer` closed on every path).
  - **BLOCKER:** `_safe_write(rec)`'s return value was ignored on the ALLOW path — a log-write failure (disk full, fsync error) let an ALLOWed connection relay with no evidence record, exactly round 1's BLOCKER 2 failure mode recurring through a different gap. Also: `_safe_write` only caught `OSError`, not the new `RuntimeError` `evidence_log.write()` can now raise after `close()`.
  - **Should-fix:** (2) a connection forwarded under `monitor` mode (unauthorized but not blocked) was never revoked if the operator later flipped to `block` mode, since revocation keyed off `authorized` instead of "was this ever relayed"; (3) revocation only ran when a *new* connection triggered a reload check — a revoked source's existing connection could relay forever if nobody else connected afterward; (4) revocation closed only the client-side writer, not the upstream one, so a few already-buffered bytes could still reach the HMI after the revocation record was written; (5) per-source suppressed-BLOCK counts could be lost permanently if that source never reconnected or the gate shut down first.
  - **Should-fix (evidence_log.py):** the exclusive lock, held on the real log file's own bytes, made Windows block even a read-only opener (`verify`, a live tail) and could surface a confusing raw `PermissionError` (from `verify()` reading before the lock was taken) instead of the intended clean `RuntimeError`.
  - **Nits:** idle-timeout half-close left the other direction running on its own separate timer instead of tearing the whole connection down; `REJECTED_MAX_CONNECTIONS` records weren't rate-limited the way BLOCK records are; the suppression-tracking dicts had no eviction; a malformed config section (wrong type, not just a syntax error) could crash every single new connection instead of being handled once; `stats["forwarded"]` was incremented before the upstream connect was confirmed to succeed; one more edge case (an authorized client's own oversized first line can lose buffered bytes) needed writing down in the design doc, not fixing.
  - **Round-3 fixes applied** (builder subagent): `_safe_write` now catches `RuntimeError` too and its return value is checked on the ALLOW path (`if ... is None: return`) — the actual blocker fix; revocation now keys off a new `relayed` flag instead of `authorized` (catches the monitor-mode case); `serve()` runs a ~1s background reload-poll task so revocation isn't gated on a new connection arriving; revocation now closes the upstream writer too and sets a `revoked` flag `pipe()` checks every loop iteration; `flush_suppressed_blocks()` writes any still-pending suppressed-BLOCK counts before `SESSION_END`; `evidence_log.py`'s lock moved to a sidecar file (`path + ".lock"`) taken before any read of the real log, fixing the Windows read-blocking and TOCTOU issues; idle-timeout now force-closes both directions, not just a half-close; BLOCK-path rate-limiting factored into `_log_rate_limited()` and reused for `REJECTED_MAX_CONNECTIONS`; rate-limit tracking dicts get a lazy prune past 500 entries; `config.py`'s reload exception handling broadened to `except Exception`; `stats["forwarded"]` now increments only after the upstream connect succeeds.
  - Re-verified independently (not just the builder's own report): 14 round-2 checks + 16 new round-3 checks (sidecar lock + concurrent `verify()` while held, write-failure fail-closed, monitor-mode revocation tracking, revoked connection's writer closed, `stats` increments correct) all pass; PM3 regression still 150/150 ALLOW. Submitted for architect review round 3.
- **Architect review round 3: PASS, 0 blockers** — 3 should-fix + 4 nits remained (code-reading review, no commands run).
  - **Should-fix 1 (correctness gap, fixed):** the round-3 claim that idle-timeout force-closes both directions was wrong — closing both writers only *after* `gather()` returns is a no-op, since by then both `pipe()` tasks have already finished on their own; the sibling direction still waited out its own separate timer (up to 2× `idle_timeout_s`). Fixed for real this time: on detecting its own timeout, a `pipe()` closure now closes both writers immediately, which — since each writer shares a transport with the sibling's reader — wakes that sibling's blocked read right away. Verified with a dedicated test (silent HMI + silent client, nothing to EOF on its own): connection now ends at ~1.0× `idle_timeout_s`, not ~2×.
  - **Should-fix 2 (data loss, fixed):** the nit-9 prune dropped a still-pending suppressed-BLOCK count on the floor instead of folding it into `stats["blocked_suppressed"]` first — the same loss `flush_suppressed_blocks()` exists to prevent, just via a different code path. Fixed: the prune now adds any non-zero count to stats before deleting the entry.
  - **Should-fix 3 (robustness, fixed):** a malformed config value (e.g. a source's `allow` set to `null`) reaching `_is_authorized()` raised uncaught, and in two places that mattered: inside the new background reload-poll task (silently killing should-fix 3's own revocation polling for the rest of the run) and in `handle_client` after the writer was already tracked but before any enclosing `try/finally` existed (a permanent per-connection leak against `max_connections`). Fixed: the poll loop and `serve()`'s shutdown path both catch and log instead of dying silently; the authorization lookup in `handle_client` is now wrapped so that specific leak can't happen. Full load()-time type validation for `authorized_sources[].allow`/`max_connections`/`idle_timeout_s` (so a bad value is rejected once, at config load, instead of handled defensively at every call site) is tracked as **A-036**, not fixed here — lower priority, no live-config value is actually malformed today.
  - **Nit (revoke-while-connecting race, fixed):** a reload could revoke a connection while it was still waiting on `open_connection()` (up to `connect_timeout_s`); `_revoke_now_unauthorized()` had no writer reference yet at that moment, so the now-connected upstream writer never got closed by the revoke, and the client's already-sent first line still reached the HMI. Fixed: `handle_client` checks `info["revoked"]` immediately after the connect succeeds and bails out if set; `_revoke_now_unauthorized()` also now skips an entry already marked `revoked`, so a second reload tick in the same window can't double-log it.
  - **Nits, accepted as documentation-only (not code bugs):** the shared BLOCK/capacity rate-limit bucket (nit 8) means `stats["blocked_suppressed"]` reconciles against `blocked + rejected_capacity`, not `blocked` alone — now stated explicitly in the design doc rather than left implicit; the design doc's own description of the lock (pre-dating the round-2 sidecar rework) was stale and has been corrected to match the sidecar-file approach, including reversing a now-backwards claim that Windows blocks reads of a live log (it doesn't, since round 2 — that was true only of the superseded real-file-locking approach).
  - All four fixes re-verified: full existing suite (14 + 16 checks) still passes, a new dedicated idle-timeout-wake test passes (connection ends at ~1.0×, not ~2×, `idle_timeout_s`), `py_compile` clean, PM3 regression still 150/150 ALLOW.
- **D-008 status: closed as PASS.** A-036 tracks the one deferred hardening item (load()-time config type validation), same posture as D-007/A-031 and D-009/A-035 — not required before citing this control in the report, but before calling it fully finished.
- **Approved / informed:** David

## D-009 · Passive HTTP-connection trigger for the D-007 lockout (second, independent partial mitigation for R-004)
- **Date / session:** 2026-11-09
- **Status:** Accepted
- **Context:** Alongside D-008 (an inline gate, which still needs HMI-side topology work it doesn't have — A-033), the team asked whether a reaction to unauthorized HMI:80 access is possible with NO inline position at all, the same way D-007 reacts to Modbus BLOCKs without being inline on the PLC's path.
- **Options considered:**
  1. Wait for D-008's inline topology (A-033) before doing anything for the HTTP leg. Rejected — no timeline on the rewiring, same reasoning D-007 used to reject waiting on D-003's topology.
  2. A new passive sniffer (`guardian/plcguard/http_watch.py`) watching TCP connections to the HMI's web port for a source IP not in `authorized_sources`, feeding a synthetic trigger into the SAME `ActiveResponder` D-007 already built and proved, sharing its cooldown state with the Modbus-side trigger.
- **Decision:** Option 2.
- **Rationale:** Reuses D-007's already-proven mechanism (two prior architect rounds, demonstrated working live against a real attack) instead of building a second lockout path; the only new risk is the trust boundary this adds to `ActiveResponder`, which got its own architect review.
- **Consequences:** `ActiveResponder.maybe_respond()`'s dst_ip guard (I-008 item 2: only fire on traffic to a trusted destination) generalized from a single fixed IP to `(sensor, dst_ip, dst_port)` triples — `dst_ip == plc_ip` stays trusted unconditionally from any sensor (unchanged), the HMI is trusted ONLY from `http_watch`'s own sensor+port, so a Modbus-sourced record addressed to the HMI's IP still cannot fire the lockout. `http_watch.enabled` defaults `false`; existing behavior is unchanged unless explicitly turned on. Like D-007 itself, this is reactive, not preventive — it cannot stop the HTTP request, only react to it afterward (same "attack lands, compensating control follows" tradeoff). **Needs the switch to also mirror the HMI's port (currently only the PLC's port 2 is mirrored, per I-007's resolution) before it can see anything live** — tracked as X-003.
- **Architect review round 1: FAIL, 2 blockers (BLOCKER 1: the generalized trust check as first written would have let a Modbus BLOCK addressed to the HMI's IP also fire the lockout — not what this was for; BLOCKER 2: the sniffer thread couldn't actually be stopped on quiet traffic, so a real PLC write could land and fail to log after `SESSION_END`/log close), 5 should-fix (no lock around the now-two-thread cooldown/send/log sequence; unbounded dedup + per-packet logging under a SYN flood, which could also starve the Modbus sniffer's own callback by holding the evidence log's lock too long; test suite only covered the happy path and tested a copy of the detection logic rather than the real code path; no MAC check, unlike `policy.py`'s `MAC_MISMATCH` posture; `cmd_monitor`'s shutdown didn't disarm stop signals first, the same class of bug A-016/A-025 already fixed for `cmd_proxy`), 3 nits.
- **Round 2 fixes:** trust check now keys on `(sensor, dst_ip, dst_port)` — `extra_triggers`, not a flat IP set — so only `http_watch`'s own sensor+port can trigger on the HMI; `ActiveResponder` gained a lock held across the full cooldown-check/send/log sequence; `http_watch.py`'s sniffer loops bounded 1s `sniff()` slices instead of one unbounded call, `cmd_monitor` disarms the responder (`active = False`) before joining the thread, and `EvidenceLog` gained a `_closed` flag (checked/set under its existing lock) so a write after `close()` is refused cleanly instead of crashing or corrupting the chain; per-source rate limiting with a suppressed-count added; a MAC check against `authorized_sources[ip].mac` added, classifying a mismatch as `SPOOFED_SOURCE`/`MAC_MISMATCH`; tests rewritten to drive the real `sniff_http_watch()` code path via a monkeypatched `scapy.sendrecv.sniff`, plus new tests for the Modbus-to-HMI rejection, an 8-thread concurrency race, bounded shutdown with no traffic, and a post-close write attempt.
  - **Architect review round 2: PASS.** Both round-1 blockers confirmed fixed in code and tests, not just claimed. Six should-fix / six nits remain, not blocking (tracked as A-035): the join/timeout window isn't fully bounded if `active_response.timeout_s` is set ≥3s (a real write could finish after `SESSION_END`); suppressed-SYN counts can be lost if pruned or the session ends mid-window; no global flood cap (a spoofed-source-IP flood still gets one evidence write per unique IP); the rate-limit window (10s) is longer than the default cooldown (5s), so a second real attack from the same IP inside that window currently gets no lockout; the sniffer reopens its capture handle every 1s slice (a narrow miss window); a few logging/test-rigor nits.
  - Verified independently (not just the builder's report) both rounds: `python -I -m py_compile` clean on every touched file; `test_runs/a033_http_watch/http_watch_check.py` 25/25 then 41/41 PASS; `guardian.py analyze test_runs/port_mirroring_test_3/Port_mirroring_test_3.pcapng -q` unchanged at 150/150 ALLOW both times, confirming no regression from either this change or D-008's concurrent, independent changes to the shared `evidence_log.py`/`config.py`/`guardian.py` files.
- **Approved / informed:** David
