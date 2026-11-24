# PLC Guardian (Python)

Modbus/TCP monitor + inline blocker for the M221 lab. Detection (`policy.py`), logging (`evidence_log.py`)
and blocking (`proxy.py`) are separate components, one per experiment step.

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
| Passive live (mirror port) | `python guardian.py monitor --iface "Ethernet"` |
| Any capture -> log | `python guardian.py analyze ..\capture.pcapng` |
| 4 Forensics | `python guardian.py forensics ..\mixed.pcapng` -> `reports/<name>/report.md, events.jsonl, events.csv` |
| Log integrity | `python guardian.py verify logs\guardian_events.jsonl` |

Add `--baseline baseline.json` to any command to raise BASELINE_DEVIATION alerts.
`config.json` is re-read live by the proxy (allowlist, `enforcement.mode`), and each reload is logged.

## Rules
SRC_NOT_ALLOWLISTED, MAC_MISMATCH, ACTION_NOT_PERMITTED_FOR_SOURCE (read/write/config per source),
PROTOCOL_ANOMALY (non-zero protocol ID, bad length, unknown FC), UNEXPECTED_UNIT_ID,
VALUE_OUT_OF_RANGE / WRITE_TO_READ_ONLY_POINT (`protected_points`, disabled until the register map exists),
BASELINE_DEVIATION (alert only). FC 90 (0x5A, Schneider engineering) counts as `config`,
except sub-codes listed in a source's `fc90_read_subcodes` (HMI: 116 = 0x74 status poll), which count as `read`;
its sub-code names follow UMAS and are [UNVERIFIED] for the M221.

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
- `modbus_capture_practice.pcapng` (frames 4-5): FC3 read addr 0 qty 10 from .50, unit 1, correctly ALLOW/NORMAL_READ. Report in `reports/practice/`. Capture hash unchanged before/after.
- Hash chain: an edited record is reported as FAIL.
- Proxy: an authorized read is forwarded to `tools/mock_plc.py` and returns correctly.
- Not yet tested: blocking on real hardware, live sniffing on Windows/Npcap, real write traffic.
