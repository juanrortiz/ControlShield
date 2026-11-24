# PLC Guardian (Python)

Modbus/TCP monitor, forensics tool and reactive responder for the M221 lab. Detection (`policy.py`), logging
(`evidence_log.py`), inline blocking (`proxy.py`, `httpgate.py`) and the PLC-side lockout response
(`active_response.py`, `http_watch.py`) are separate components. On the real lab network Guardian sits on a mirror
port, so it **detects, logs and reacts**; it does not block in real time (see *Active response* and
*Inline topology* below).

## Setup (Windows)
- Python 3.10+. `pip install scapy` (only needed for pcap/live modes; the proxy is standard library only).
- Live sniffing (`monitor`) needs **Npcap**. Proxy on port 502 needs an inbound firewall rule for TCP 502.

## GUI (demo / presentation)
`python gui.py` (or double-click `Launch_GUI.bat`) starts a local server and opens **http://127.0.0.1:8765** in your browser.
The UI is a React app built with AlignUI components (`webui/`); **Node.js is needed on first run** (`gui.py` runs `npm install` + `npm run build` for you), after that only Python is needed.
- **Live Demo:** simulated PLC + the real proxy + HMI / laptop / attacker clients on one machine, with a guided tour (no Guardian -> monitor -> auto-lockout -> block -> evidence). No hardware, no Npcap.
- **Lab Mode:** start/stop the real passive `monitor` on the mirror port, set the two flags it reads (`active_response.enabled` for the D-007 lockout, `http_watch.enabled` for the D-009 HTTP watch), and the one-press **Quick clear** buttons ("Control Shield" `%M7`, "Maintenance bypass" `%M4`) for the real PLC. On real hardware Guardian is passive: it detects, logs and reacts, it does not block in real time.
- **Analyze Captures / Evidence:** wrap the real commands below (run `analyze` / `forensics` / `baseline`; verify a log, export CSV, tamper-with-a-copy demo).
- **Docker** (for another machine): `docker build -t plc-guardian -f guardian/Dockerfile .` from the project root, then `docker run --rm -p 127.0.0.1:8765:8765 -v "<captures dir>:/data:ro" plc-guardian`. Supports Live Demo, Analyze and Evidence; Lab Mode is disabled in the image (needs raw capture + the lab network). Not yet tested (no Docker on the dev laptop).
- **UI development:** `python gui.py --no-browser` in one terminal, `cd webui && npm run dev` in another (Vite proxies `/api`).
See `docs/GUARDIAN_DESIGN.md` §4.12.

## Commands (run from this folder)
| Experiment | Command |
|---|---|
| 1 Normal baseline | `python guardian.py baseline ..\capture.pcapng -o baseline.json` |
| 2/3 Live, inline block | `python guardian.py proxy` (`--mode monitor` = Iteration 1, `--mode block` = Iteration 2) |
| HMI web leg, inline gate (D-008) | `python guardian.py httpgate` (`--mode monitor` / `--mode block`); connection-level IP allowlist only |
| Passive live (mirror port) | `python guardian.py monitor --iface "Ethernet"` (also runs the active response / HTTP watch when enabled in `config.json`) |
| Any capture -> log | `python guardian.py analyze ..\capture.pcapng` |
| 4 Forensics | `python guardian.py forensics ..\mixed.pcapng` -> `reports/<name>/report.md, events.jsonl, events.csv` |
| Log integrity | `python guardian.py verify logs\guardian_events.jsonl` |
| Log -> CSV | `python guardian.py export logs\guardian_events.jsonl events.csv` |

Add `--baseline baseline.json` to any command to raise BASELINE_DEVIATION alerts.
`config.json` is re-read live by the proxy (allowlist, `enforcement.mode`), and each reload is logged.

## Rules
SRC_NOT_ALLOWLISTED, MAC_MISMATCH, ACTION_NOT_PERMITTED_FOR_SOURCE (read/write/config per source),
PROTOCOL_ANOMALY (non-zero protocol ID, bad length, unknown FC), UNEXPECTED_UNIT_ID,
VALUE_OUT_OF_RANGE / WRITE_TO_READ_ONLY_POINT (`protected_points`, disabled until the register map exists),
BASELINE_DEVIATION (alert only). FC 90 (0x5A, Schneider engineering) counts as `config`,
except sub-codes listed in a source's `fc90_read_subcodes` (HMI: 116 = 0x74 status poll), which count as `read`;
its sub-code names follow UMAS and are [UNVERIFIED] for the M221.

## Active response (D-007) and HTTP watch (D-009)
Because true inline prevention needs rewiring that has not been done (A-004/A-019), Guardian uses a reactive compensating control:
- **D-007 (`active_response.py`):** when `monitor` sees a decision listed in `active_response.trigger_decisions` (default `BLOCK`), Guardian
  writes coil `%M7` (PLCGUARD, `lockout_coil` 7, unit 255) with its own authorized FC5 write; PLC ladder logic then forces the safe state. A `cooldown_seconds` window limits re-fires during a burst.
  Controlled by `active_response.enabled` in `config.json`.
- **D-009 (`http_watch.py`):** a passive sniffer for TCP connections to the HMI's web port (`http_watch.hmi_ip`/`hmi_port`) from a source not in `authorized_sources`;
  it feeds the **same** responder and cooldown. Needs the switch to mirror the HMI's port, and `monitor` must be restarted to change `http_watch.enabled` (read once at startup).
- **D-008 (`httpgate.py`):** inline connection-level gate in front of the HMI's port 80 (IP allowlist, no HTTP parsing). Code is architect-PASSed but it is **not yet in the real traffic path** (A-033).
These are compensating controls: the PLC still receives the attacker's first packet, and the lockout lands milliseconds later.

## Inline topology (needed for real blocking) [UNVERIFIED - not yet tested on hardware]
The proxy only prevents an attack if the PLC is reachable **only through Guardian**:
- PLC on its own cable to Guardian's 2nd NIC (USB-Ethernet), on a separate subnet (e.g. PLC re-addressed to 192.168.9.11, Guardian NIC2 192.168.9.1); set `proxy.upstream_host` to it.
- Guardian NIC1 on the lab switch takes the address clients already use (192.168.8.11), so the HMI needs no change. Alternatively, repoint the HMI to Guardian's address.
- Fail-closed: if Guardian stops, the PLC is unreachable. Note this trade-off in the write-up.
- Proxy mode sees source IPs but not MACs (the TCP connection ends at Guardian), so MAC checks apply in `monitor`/`analyze` modes only.

## Evidence handling
- Original `.pcapng` files are only read, never modified (the SHA-256 is recorded in each log and report).
- Logs are append-only JSONL with a SHA-256 hash chain. Tampering is *evident* (detectable), but it isn't *prevented*. Hash the log into the case notes after each run.
- Timestamps are UTC from the capture file (pcap) or the host clock (proxy/live). Sync the Guardian clock before the demo.

## Tested so far
Live results below were measured on the lab hardware; evidence is in the repo's `captures/` and `analysis/`.
- **D-007 live (I-009, S-006):** `.99`'s `%M4` write was BLOCKed and Guardian's lockout write landed ~6 ms later; tank level held. `captures/exp3_active_response_success_2026-11-04.pcapng`, `analysis/exp3_active_response_success_2026-11-04_forensic_report.md`. Compare `exp3_no_inline_baseline_2026-11-04.pcapng` (mirroring alone detects but never prevents).
- **D-009 live (S-007):** unauthorized HTTP connection to the HMI triggered the same FC5 lockout (accepted by the PLC 3.4 ms later, matching Guardian's evidence log). `analysis/S-007_port80_ips_live_test.md`.
- **Black-box scan under load (S-007):** 1682 BLOCKed reads fired the lockout 5 times; the cooldown suppressed 1677. Zero writes from `.99`. `analysis/S-007_blackbox_discovery_live_test.md`.
- **Regression:** PM3 replay 150/150 ALLOW held through the S-006/S-007 changes (per the session log).
- **Earlier, offline:** `modbus_capture_practice.pcapng` (frames 4-5) FC3 read correctly ALLOW/NORMAL_READ, report in `reports/practice/`, capture hash unchanged; an edited log record is reported as FAIL by `verify`; proxy forwards an authorized read to `tools/mock_plc.py`.
- **Not yet done:** inline blocking on real hardware with the PLC behind Guardian's 2nd NIC (A-004/A-019); `httpgate` in the real traffic path (A-033); residual hardening A-031, A-035, A-036. The `Inline topology` section above stays `[UNVERIFIED]` until then.
