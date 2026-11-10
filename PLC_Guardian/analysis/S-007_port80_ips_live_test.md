# S-007 · Port 80 IPS live test — D-009 (`http_watch` → `active_response`) confirmed end-to-end

_Analysis date: 2026-11-09/10. Analyst: David Jessup with Claude. tshark 4.6.9. Read-only analysis; captures not modified._

Tags: **[CONFIRMED]** = shown in the capture(s) or the live evidence log cited here · **[UNVERIFIED]** = inference still to check.

---

## 1. Evidence

| Item | Value |
|---|---|
| File | `Port 80 IPS.pcapng` (as downloaded; working copy for analysis only — original untouched) |
| SHA-256 | `4619452f229185c052330f5159ae52db976421acc8dbdbb3a67f832f239d541c` |
| Frames / duration | 726 frames, 14.081 s |
| First / last packet (UTC) | 2026-11-10 03:24:03.633738 → 03:24:17.715082 |
| Capture point | Guardian/capture host, port-mirrored traffic (switch TL-SG105E, Port 2 PLC + Port 3 HMI → Port 5 Guardian) |
| Companion evidence | `guardian/logs/live_attacker_test_2026-11-04_v2.jsonl` (Guardian's own hash-chained evidence log, `sensor: live:Ethernet 4` / `http_watch` / `active_response`, same host, same time window) |
| Also referenced (prior event in same test run, different capture) | `Port 80 Test.pcapng`, SHA-256 `c567ebf7d5452cce6f02f4b038ea400b4e80082c92f563aa2cc067325d0d1fe2` (NOT IN INVENTORY either — see §4) |
| Not yet in `06_REFERENCE` capture inventory | Both files above — proposed rows in §5 |

---

## 2. What this capture shows

### 2.1 Traffic composition [CONFIRMED]

`WS tshark -r "Port 80 IPS.pcapng" -q -z conv,tcp`:

| Conversation | Frames | Content |
|---|---|---|
| HMI `.10:13692` ↔ PLC `.11:502` | 411 | Normal HMI poll cycle (unit 255, FC1/FC90/FC3) + two Start/Reset coil writes (FC15, `%M2`/`%M5`) |
| `.99` ↔ HMI `.10:80`, 8 separate TCP streams (ports 56753–56764) | 58+52+48+35+29+11+4×4 ≈ 253 | Attacker web requests to the HMI (see §2.2) |
| `.50:49672` ↔ PLC `.11:502` | 12 | **Guardian's own `active_response` lockout write** (see §2.3) |
| `.10:80` ↔ `.51:40086` | 1 | Single 66-byte frame, no payload exchanged — background noise, not analyzed further |

### 2.2 Attacker SYNs to the HMI's web port [CONFIRMED]

Filter `tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst==192.168.8.10`:

| Frame | Time (UTC) | Source port |
|---|---|---|
| 339 | 03:24:13.047371 | 56759 |
| 389 | 03:24:13.753842 | 56760 |
| 391 | 03:24:13.753855 | 56761 |
| 449 | 03:24:13.888914 | 56762 |
| 451 | 03:24:13.890534 | 56763 |
| 519 | 03:24:14.098670 | 56764 |

Six separate TCP connections from `.99` to `192.168.8.10:80` within about 1.05 s — consistent with a browser or script loading the HMI's web UI (multiple parallel requests for page resources), not a single clean request. An earlier capture from the same test session, `Port 80 Test.pcapng` (see §4), shows the full set of URIs requested in a similar run (`/services/variable/hmi/values`, static JS/CSS/images, `/vars/...` pages) — consistent with this being the same attack pattern repeated.

### 2.3 Guardian's reaction: `http_watch` detects, `active_response` fires [CONFIRMED, correlated to the millisecond]

Filter `tcp.dstport==502 && modbus.func_code in {5,6,15,16,23}` isolates the Modbus writes; frame 349/351 is Guardian's own lockout write:

| Frame | Time (UTC) | Src → Dst | What |
|---|---|---|---|
| 339 | 03:24:13.047371 | `.99` → `.10:80` | First attacker SYN (trigger) |
| 349 | 03:24:13.100993 | `.50` → `.11:502` | FC5 Write Single Coil, address 7 (`%M7`/PLCGUARD), value `0xFF00` (ON) |
| 351 | 03:24:13.104407 | `.11:502` → `.50` | PLC response, accepted (3.4 ms later) |

This matches Guardian's own evidence log (`live_attacker_test_2026-11-04_v2.jsonl`) **to the microsecond**:

```
seq 208 (http_watch):      ts_utc 2026-11-10T03:24:13.047370Z
                            "192.168.8.99 opened a TCP connection to the HMI web port 80; not in authorized_sources"
                            + "5 additional connection attempt(s) from 192.168.8.99 in the preceding 10s
                               were rate-limited, not individually logged"
                            decision: BLOCK, event_type: UNAUTHORIZED_HTTP_ACCESS, rules: [SRC_NOT_ALLOWLISTED_HTTP]

seq 209 (live:Ethernet 4):  ts_utc 2026-11-10T03:24:13.100992Z
                            FC5 Write Single Coil addr=7 values=[1], source_name: "Engineering laptop" (.50)

seq 210 (active_response):  ts_utc 2026-11-10T03:24:13.108069Z
                            outcome: SUCCEEDED, trigger_seq: 208, trigger_decision: BLOCK,
                            trigger_event_type: UNAUTHORIZED_HTTP_ACCESS, trigger_src_ip: 192.168.8.99

seq 211 (live:Ethernet 4):  ts_utc 2026-11-10T03:24:13.104406Z
                            RESPONSE, outcome: ACCEPTED_BY_PLC, latency_ms: 3.414
```

**This confirms the full D-009 chain working live, independently corroborated by both the packet capture and Guardian's own hash-chained evidence log:** an unauthorized TCP connection to the HMI's web port is detected by the passive `http_watch` sniffer (seq 208), attributed to the correct source IP, and triggers Guardian's own `active_response` FC5 write (seq 209/210) within **~54 ms** of the first SYN — the PLC accepts the write 3.4 ms after that. `%M7` (PLCGUARD) latches ON exactly as D-007's interlock is designed to do.

**Also confirms `http_watch`'s rate-limiting is working as designed**: of the 6 SYNs in this capture (§2.2), only the first produced an individually-logged `REQUEST` record; the log entry itself states the other 5 were "rate-limited, not individually logged" — matching the burst of near-simultaneous SYNs seen in the raw packets.

This is the **third** such live, successful detection-and-lockout event in this test session (the first two: `03:21:59Z` and `03:23:33Z`, both `outcome: SUCCEEDED`, visible in the same evidence log but predating this particular capture's time window). A fourth attempt earlier in the session (`03:08:09Z`) recorded `outcome: FAILED` with `TimeoutError` — traced to the Guardian host's own IP being temporarily misconfigured (not `.50`) while the operator was in the switch's admin UI, not a defect in D-009 itself; connectivity and the lockout mechanism were confirmed working normally once the host's IP was corrected.

### 2.4 Normal HMI/PLC traffic, unaffected [CONFIRMED]

Frames 44/52 (03:24:04Z) and 259/262 (03:24:10Z) show the HMI's own FC15 writes to `%M5` (Reset) toggling True→False, and frame 280 (03:24:11Z) a FC15 write to `%M2` (Start) = False — all `ACCEPTED_BY_PLC`, all from the HMI's normal operating cycle, unrelated to the attack. Confirms `http_watch`/`active_response` did not interfere with or false-positive on legitimate HMI traffic during this window.

---

## 3. What this means for the project

- **D-009 is now demonstrated working against live attacker traffic**, not just unit/smoke tests — mirrors D-007's own "demonstrated working against a real attack" milestone (A-032), now extended to the HTTP leg.
- **Detection-to-lockout latency (~54 ms SYN→write, 3.4 ms write→PLC-accept)** is fast enough to be a meaningful compensating control, consistent with D-007's rationale (Experiment 2's ~8.6 s window from attack to physical consequence is far longer than this reaction time).
- **Still reactive, not preventive** (same framing as D-007/D-009's design docs): the attacker's HTTP request to the HMI itself is never blocked — only a compensating PLC-side lockout follows it. The inline alternative (D-008's `httpgate.py`) remains unexercised by real attacker traffic pending A-033 (HMI-side inline topology).
- **The switch-mirror fragility noted in I-007 recurred during this test session** (losing the Port 2/3 → Port 5 mirror after an operator IP change, requiring a disable/re-enable toggle to recover) — not a Guardian defect, but a second occurrence of this switch's known flaky mirror-commit behavior, worth a RAID note (see §5).

---

## 4. Companion capture: `Port 80 Test.pcapng`

A second file from the same test session, captured earlier (`2026-11-09 18:54:48 → 18:55:12` local, 1916 frames, 24.2 s), was analyzed informally during the live session (not written up as a separate report): it showed `.99` making extensive HTTP requests directly to `192.168.8.10:80` (the HMI's real address) — `GET /services/variable/hmi/values?page=1&rp=13` repeatedly, plus a full page-load sequence (`/html/...`, `/vars/...` assets) — confirming the attacker was targeting the HMI directly rather than the inline gate (`192.168.8.50:80`), which was expected at that point since A-033's topology isn't built. SHA-256 `c567ebf7d5452cce6f02f4b038ea400b4e80082c92f563aa2cc067325d0d1fe2`. Proposed inventory row below; a fuller write-up can follow if the team wants one.

---

## 5. Proposed `06_REFERENCE.md` capture inventory additions

| File | Date | Who | Scenario | Frames / Duration | SHA-256 |
|---|---|---|---|---|---|
| `Port 80 Test.pcapng` | 2026-11-09 | David Jessup (attacker on `.99`) | `.99` browses/polls the HMI's web UI directly (`192.168.8.10:80`); confirms the HTTP gate (D-008) is not yet in the traffic path (A-033 open) | 1916 fr. / 24.2 s | `c567ebf7d5452cce6f02f4b038ea400b4e80082c92f563aa2cc067325d0d1fe2` |
| `Port 80 IPS.pcapng` | 2026-11-09/10 | David Jessup (attacker on `.99`) | `.99` connects to the HMI's web port; `http_watch` detects it and `active_response` fires a real FC5 lockout write to `%M7`, accepted by the PLC — first capture-corroborated live demonstration of D-009 | 726 fr. / 14.1 s | `4619452f229185c052330f5159ae52db976421acc8dbdbb3a67f832f239d541c` |

## 6. Proposed RAID log addition

| ID | Issue | Impact | Status |
|---|---|---|---|
| (next I-0##) | Switch mirror (TL-SG105E) lost the Port 2 + Port 3 → Port 5 mirror mid-session when the Guardian host's IP was temporarily changed (to access the switch's own admin UI) and changed back — required a Port Mirror disable/re-enable toggle to recover; a second occurrence of I-007's "silent mirror-config loss" failure mode, different trigger this time | Any live monitoring window during this kind of switch/host reconfiguration is a blind spot indistinguishable from "no traffic" | Resolved for this session (toggle recovered it); recommend a quick mirror sanity-check (e.g. confirm fresh HMI/PLC traffic is arriving) after *any* switch admin-UI visit, not just after intentional mirror edits |

---

## 7. Hash re-verification

`WS verify "Port 80 IPS.pcapng"` re-run after this analysis: SHA-256 unchanged, `4619452f229185c052330f5159ae52db976421acc8dbdbb3a67f832f239d541c`.

---

## Reproduce

```sh
bash .claude/skills/wireshark-analyze/scripts/ws.sh verify "C:\Users\david\Downloads\Port 80 IPS.pcapng"
bash .claude/skills/wireshark-analyze/scripts/ws.sh capinfos -c -u -a -e -t -E "C:\Users\david\Downloads\Port 80 IPS.pcapng"
bash .claude/skills/wireshark-analyze/scripts/ws.sh tshark -r "C:\Users\david\Downloads\Port 80 IPS.pcapng" -q -z conv,tcp
bash .claude/skills/wireshark-analyze/scripts/ws.sh tshark -r "C:\Users\david\Downloads\Port 80 IPS.pcapng" -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst==192.168.8.10" -T fields -e frame.number -e frame.time_utc -e ip.src -e tcp.srcport
bash .claude/skills/wireshark-analyze/scripts/ws.sh tshark -r "C:\Users\david\Downloads\Port 80 IPS.pcapng" -Y "tcp.dstport==502 && modbus.func_code in {5,6,15,16,23}" -T fields -e frame.number -e frame.time_utc -e ip.src -e modbus.func_code -e modbus.reference_num
bash .claude/skills/wireshark-analyze/scripts/ws.sh tshark -r "C:\Users\david\Downloads\Port 80 IPS.pcapng" -Y "frame.number==349 || frame.number==351" -T fields -e frame.number -e frame.time_utc -e ip.src -e ip.dst -e modbus.func_code -e modbus.reference_num
```
