"""PLC Guardian control-panel engine: everything the web UI can do, with no UI code in it.

The engine owns the demo stack (simulated PLC + the real Guardian proxy + three simulated clients),
the Lab Mode passive monitor and quick clear, capture analysis and evidence-log helpers. Every observable change is
published on an event bus; `server.py` streams it to the browser as Server-Sent Events.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))       # .../guardian
ROOT = os.path.dirname(HERE)                                              # project root
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tools"))

from plcguard.active_response import ActiveResponder, _detect_own_ip, send_fc5   # noqa: E402
from plcguard.config import Config                        # noqa: E402
from plcguard.evidence_log import EvidenceLog, export_csv, utc_iso, verify   # noqa: E402
from plcguard.modbus import parse_frame                   # noqa: E402
import modbus_client as mc                                # noqa: E402

REAL_CONFIG = os.path.join(HERE, "config.json")
DEMO_DIR = os.path.join(HERE, "demo")
DEMO_LOGS = os.path.join(DEMO_DIR, "logs")
DEMO_CFG = os.path.join(DEMO_DIR, "config.json")
GUARDIAN_PY = os.path.join(HERE, "guardian.py")
MOCK_PLC_PY = os.path.join(HERE, "tools", "mock_plc.py")
HOST, PLC_PORT, PROXY_PORT = "127.0.0.1", 5020, 5502
WIN = sys.platform == "win32"
LAB_ENABLED = os.environ.get("GUARDIAN_LAB", "1") != "0"
# directories the UI may read captures / logs from (plus anything under them)
DATA_ROOTS = [os.path.realpath(p) for p in (ROOT, HERE, os.environ.get("GUARDIAN_DATA", "")) if p]

# demo actors: key -> (label, source ip)
ACTORS = {"hmi": ("HMI", "127.0.0.10"),
          "laptop": ("Engineering laptop", "127.0.0.2"),
          "attacker": ("Attacker", "127.0.0.99")}
IP_TO_ACTOR = {v[1]: k for k, v in ACTORS.items()}
DEMO_NAMES = {v[1]: v[0] for v in ACTORS.values()}
UNIT = 255
COUNT_TAGS = ("allow", "alert", "detect", "block", "lock")

FALLBACK_POINTS = [
    {"name": "%M4 Maintenance bypass (ON defeats the level-80 stop)", "table": "coil", "start": 4,
     "end": 4, "min": 0, "max": 0, "enabled": True},
    {"name": "%MW0 Tank level", "table": "holding", "start": 0, "end": 0, "read_only": True, "enabled": True},
    {"name": "%M7 PLCGUARD lockout", "table": "coil", "start": 7, "end": 7, "min": 1, "max": 1,
     "enabled": True}]

RULE_TEXT = {
    "SRC_NOT_ALLOWLISTED": "sender is not on the allowlist",
    "ACTION_NOT_PERMITTED_FOR_SOURCE": "this host may not do that kind of action",
    "WRITE_TO_READ_ONLY_POINT": "target is a read-only PLC point",
    "VALUE_OUT_OF_RANGE": "value is outside the safe range",
    "PROTOCOL_ANOMALY": "malformed / unknown Modbus frame",
    "UNEXPECTED_UNIT_ID": "unexpected Modbus unit id",
    "MAC_MISMATCH": "MAC does not match the allowlisted device (spoofing?)",
    "BASELINE_DEVIATION": "never seen in the learned baseline",
}


class ApiError(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


# ───────────────────────────────────────────────────────────── helpers
def now_tag() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_port(host: str, port: int, timeout: float = 6.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if port_open(host, port):
            return True
        time.sleep(0.15)
    return False


def write_json_atomic(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    for _ in range(5):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.1)
    os.replace(tmp, path)


def local_time(ts_utc: str) -> str:
    try:
        return datetime.fromisoformat(ts_utc.replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S.%f")[:-3]
    except Exception:           # noqa: BLE001
        return ts_utc or ""


def safe_path(p: str, must_exist: bool = True) -> str:
    """Resolve a user-supplied path and refuse anything outside the project / data directories."""
    if not p:
        raise ApiError("path is required")
    rp = os.path.realpath(p if os.path.isabs(p) else os.path.join(HERE, p))
    if not any(rp == r or rp.startswith(r + os.sep) for r in DATA_ROOTS):
        raise ApiError("path is outside the project and data directories", 403)
    if must_exist and not os.path.isfile(rp):
        raise ApiError(f"file not found: {p}", 404)
    return rp


def pdu_read_hr(addr, qty): return struct.pack(">BHH", 3, addr, qty)
def pdu_read_coils(addr, qty): return struct.pack(">BHH", 1, addr, qty)
def pdu_write_coil(addr, on): return struct.pack(">BHH", 5, addr, 0xFF00 if on else 0)
def pdu_write_reg(addr, val): return struct.pack(">BHH", 6, addr, val)
PDU_FC90 = bytes([90, 0x00, 0x10, 0x00])      # Schneider engineering frame (sub-code 0x10)


def summarize_pdu(pdu: bytes, unit: int = UNIT) -> str:
    try:
        raw = struct.pack(">HHHB", 1, 0, len(pdu) + 1, unit) + pdu
        return parse_frame(raw, is_request=True).summary()
    except Exception:           # noqa: BLE001
        return pdu.hex()


def describe_event(rec: dict, names: dict | None = None):
    """One evidence-log record -> (time, source, what, verdict, why, tag), or None to skip."""
    names = names or {}
    kind, ts = rec.get("record"), local_time(rec.get("ts_utc", ""))
    if kind == "REQUEST":
        ip = rec.get("src_ip", "?")
        label = names.get(ip) or rec.get("source_name")
        who = f"{label} · {ip}" if label else ip
        action, dec = rec.get("action", ""), rec.get("decision", "ALLOW")
        if action.startswith("BLOCKED"):
            verdict, tag = "BLOCKED", "block"
        elif dec == "BLOCK":
            verdict, tag = "DETECTED, not stopped", "detect"
        elif dec == "ALERT":
            verdict, tag = "ALERT (allowed)", "alert"
        else:
            verdict, tag = "allowed", "allow"
        reasons = [RULE_TEXT.get(r, r) for r in rec.get("rules", [])]
        why = "; ".join(reasons) if reasons else f"authorized: {str(rec.get('event_type', '')).lower().replace('_', ' ')}"
        det = rec.get("details") or []
        if det and reasons:
            why += f"  [{det[0]}]"
        return ts, who, rec.get("summary", ""), verdict, why, tag
    if kind == "RESPONSE":
        out = str(rec.get("outcome", ""))
        short = "accepted by PLC" if out.startswith("ACCEPTED") else "rejected by PLC" if out.startswith("REJECTED") else out
        return ts, "↳ PLC", rec.get("summary", ""), short, out, "resp"
    if kind == "ACTIVE_RESPONSE":
        out = rec.get("outcome", "")
        who = rec.get("trigger_source_name") or rec.get("trigger_src_ip")
        why = f"reaction to {rec.get('trigger_event_type')} from {who}"
        if rec.get("details"):
            why += f"  [{rec['details'][0]}]"
        if out == "SKIPPED_COOLDOWN":
            return ts, "Guardian (self)", "lockout already fired recently", "lockout in cooldown", why, "info"
        return ts, "Guardian (self)", f"FC5 write coil %M{rec.get('lockout_coil')} = 1 (lockout)", \
            f"LOCKOUT {out}", why, "lock" if out == "SUCCEEDED" else "alert"
    if kind == "CONFIG_RELOADED":
        return ts, "Guardian", f"config reloaded, mode = {rec.get('enforcement_mode')}", "config", \
            "allowlist: " + ", ".join(rec.get("authorized_sources", [])), "info"
    if kind in ("SESSION_START", "SESSION_END"):
        return ts, "Guardian", kind.replace("_", " ").lower(), kind.split("_")[1].lower(), \
            str(rec.get("sensor", "")), "info"
    if kind in ("MALFORMED", "UPSTREAM_ERROR"):
        return ts, rec.get("src_ip", "Guardian"), kind.lower(), kind.lower(), "; ".join(rec.get("details", [])), "alert"
    return None


def row_dict(rid: int, ch: str, d) -> dict:
    return {"id": rid, "ch": ch, "time": d[0], "src": d[1], "what": d[2], "verdict": d[3], "why": d[4], "tag": d[5]}


class Tailer:
    """Incrementally reads new JSONL records appended to a (possibly not yet existing) file."""

    def __init__(self, path: str, cb):
        self.path, self.cb, self.pos, self.buf = path, cb, 0, b""

    def poll(self) -> None:
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        if size < self.pos:
            self.pos, self.buf = 0, b""
        if size == self.pos:
            return
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self.pos)
                data = fh.read()
        except OSError:
            return
        self.pos += len(data)
        parts = (self.buf + data).split(b"\n")
        self.buf = parts.pop()
        for ln in parts:
            if ln.strip():
                try:
                    self.cb(json.loads(ln))
                except ValueError:
                    pass


class Proc:
    """Child process with streamed output and a graceful stop (Ctrl+Break so Guardian writes SESSION_END)."""

    def __init__(self, name, args, out_cb, cwd=HERE):
        self.name, self.args, self.out_cb, self.cwd = name, args, out_cb, cwd
        self.p = None

    def start(self):
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if WIN else 0
        self.p = subprocess.Popen([sys.executable, "-u", *self.args], cwd=self.cwd, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                  encoding="utf-8", errors="replace", bufsize=1, creationflags=flags)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            self.out_cb(self.name, line.rstrip())
        self.out_cb(self.name, f"[process exited with code {self.p.wait()}]")

    def alive(self) -> bool:
        return self.p is not None and self.p.poll() is None

    def stop(self, grace: float = 5.0):
        if not self.alive():
            return
        try:
            self.p.send_signal(signal.CTRL_BREAK_EVENT if WIN else signal.SIGINT)
        except Exception:       # noqa: BLE001
            pass
        try:
            self.p.wait(grace)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait(2)


# ───────────────────────────────────────────────────────────── scenarios / tour
def _scenarios():
    S = lambda label, tip, pdus: {"label": label, "tip": tip, "pdus": pdus}
    return {
        "hmi": [
            S("Read tank level", "Normal HMI poll of %MW0. Allowlisted + read = allowed.", [pdu_read_hr(0, 1)]),
            S("Read status coils", "Normal HMI poll of %M2-%M7.", [pdu_read_coils(2, 6)]),
            S("Press START", "Authorized write: HMI may write. Starts the tank filling.", [pdu_write_coil(2, 1)]),
            S("Press RESET", "Authorized write to %M5: empties the tank (simulation).", [pdu_write_coil(5, 1)]),
            S("Bypass ON (HMI)", "Authorized host, but %M4 is protected (safe value is 0): allowed with an ALERT, never blocked.", [pdu_write_coil(4, 1)]),
            S("Bypass OFF (HMI)", "HMI writes %M4 = 0 (the safe value).", [pdu_write_coil(4, 0)]),
            S("Engineering cmd (FC 90)", "The HMI may read and write but not configure: Guardian blocks it even though the HMI is authorized.", [PDU_FC90]),
        ],
        "laptop": [
            S("Write %MW1 = 5", "Engineering laptop is allowed to write. Unprotected register: allowed.", [pdu_write_reg(1, 5)]),
            S("Engineering cmd (FC 90)", "Config-class traffic is allowed for this host. (The demo PLC doesn't implement FC 90, so the PLC itself rejects it.)", [PDU_FC90]),
            S("Clear lockout %M7", "An authorized host clearing Guardian's lockout is allowed but raises an ALERT.", [pdu_write_coil(7, 0)]),
            S("Read tank level", "Allowlisted read.", [pdu_read_hr(0, 1)]),
        ],
        "attacker": [
            S("Probe: read level", "Reconnaissance from an unknown IP. Even reads are refused (unknown_sources.allow_reads = false).", [pdu_read_hr(0, 1)]),
            S("Bypass %M4 = 1", "THE attack: forces the maintenance bypass so the level-80 stop no longer works and the tank overflows.", [pdu_write_coil(4, 1)]),
            S("Fake level %MW0 = 0", "Tries to lie about the level by writing the read-only counter register.", [pdu_write_reg(0, 0)]),
            S("Force START %M2", "Unauthorized process command.", [pdu_write_coil(2, 1)]),
            S("Scan x25 reads", "Burst of reads from the unauthorized host.", [pdu_read_hr(0, 1)] * 25),
        ],
    }


SCENARIOS = _scenarios()

TOUR = [
    ("Start the demo system",
     "Launches a simulated PLC (a tank process) and the real PLC Guardian proxy on this machine. The HMI, an engineering "
     "laptop and an attacker are three simulated clients with different IP addresses. Nothing here touches the lab network.",
     "tour_start"),
    ("1 · Normal operation",
     "The HMI (allowlisted) reads the tank and presses START. Guardian checks every request, lets these through "
     "(green rows) and the tank fills. This is what 'normal' looks like.", "tour_normal"),
    ("2 · Without Guardian the attacker wins",
     "Guardian is bypassed. The attacker writes the maintenance-bypass coil %M4, which defeats the level-80 stop: "
     "the tank climbs past 80 into overload. Nothing is checked and nothing is logged (pink row).", "tour_noguard"),
    ("3 · Guardian in MONITOR mode: detected, not stopped",
     "Same attack, Guardian on but only monitoring. It flags the write as BLOCK-grade (orange) and logs who, what and "
     "why, but still forwards it, so the tank still overflows. Evidence without prevention.", "tour_monitor"),
    ("4 · Add the reactive lockout (D-007)",
     "Still monitor-only, but now Guardian reacts: after seeing the attack it writes the lockout coil %M7 on the PLC "
     "itself (purple row). The PLC halts the fill. This is the compensating control used when Guardian can only watch "
     "a mirror port.", "tour_lockout"),
    ("5 · BLOCK mode: the attack never reaches the PLC",
     "Guardian's proxy is in block mode. The attacker's write is refused with a Modbus exception, %M4 never changes and "
     "the tank stops at 80. The HMI keeps working normally.", "tour_block"),
    ("6 · More things Guardian catches",
     "The attacker probes with a read, tries to fake the tank level on a read-only register, and the HMI tries an "
     "engineering command it is not allowed to send. Read the 'Why' column for each.", "tour_more"),
    ("7 · The evidence is tamper-evident",
     "Every row above is a record in a SHA-256 hash chain. The Evidence screen verifies it, then alters a COPY of the "
     "log and shows verification fail at the exact record that was changed.", "tour_evidence"),
]


class Engine:
    def __init__(self):
        self._lock = threading.RLock()
        self._subs: set[queue.Queue] = set()
        self._rid = 0
        self.rows = {"demo": deque(maxlen=500), "lab": deque(maxlen=500)}
        self.console = {k: deque(maxlen=400) for k in ("demo", "lab", "analyze")}
        self.last_result = "Press “Start system” (or step 1 of the tour) to begin."
        self.counts = {k: 0 for k in COUNT_TAGS}
        self.st = {"system": "stopped", "route": "on", "mode": "block", "lockout": True, "allow_attacker": False}
        self.plc = None
        self.tid = 100
        self.plc_proc = self.proxy_proc = None
        self.responder = self.resp_log = None
        self.tailers: list[Tailer] = []
        self.guardian_log = None
        self.stop_poll = threading.Event()
        self.lab_procs: dict[str, Proc] = {}
        self.lab_tailers: list[Tailer] = []
        self.lab_logs: dict[str, str] = {}
        self.an_busy = False
        self.an_result = None
        self._down = threading.Event()
        threading.Thread(target=self._tail_loop, daemon=True).start()

    # ------------------------------------------------------------ event bus
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=2000)
        with self._lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q) -> None:
        with self._lock:
            self._subs.discard(q)

    def emit(self, typ: str, data) -> None:
        msg = (typ, data)
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass

    def state(self) -> dict:
        with self._lock:
            procs = {k: p.alive() for k, p in self.lab_procs.items()}
            return {**self.st, "counts": dict(self.counts), "plc": self.plc, "result": self.last_result,
                    "demo_log": self.guardian_log, "lab_enabled": LAB_ENABLED,
                    "lab_running": {"monitor": procs.get("monitor", False)},
                    "lab_logs": dict(self.lab_logs), "analyze_busy": self.an_busy}

    def snapshot(self) -> dict:
        with self._lock:
            return {"state": self.state(), "rows": {k: list(v) for k, v in self.rows.items()},
                    "console": {k: list(v) for k, v in self.console.items()}}

    def push_state(self) -> None:
        self.emit("state", self.state())

    def set_result(self, text: str) -> None:
        self.last_result = text
        self.emit("result", text)

    def add_row(self, ch: str, d) -> dict:
        with self._lock:
            self._rid += 1
            row = row_dict(self._rid, ch, d)
            self.rows[ch].append(row)
            if ch == "demo" and row["tag"] in self.counts:
                self.counts[row["tag"]] += 1
        self.emit("row", row)
        if ch == "demo" and row["tag"] in COUNT_TAGS:
            self.emit("counts", dict(self.counts))
        return row

    def out_cb(self, name: str, line: str) -> None:
        ch = "analyze" if name.startswith("an:") else "lab" if name == "monitor" else "demo"
        text = line if ch == "analyze" else f"[{name}] {line}"
        with self._lock:
            self.console[ch].append(text)
        self.emit("console", {"ch": ch, "line": text})

    def clear(self, ch: str = "demo") -> None:
        with self._lock:
            if ch in self.rows:
                self.rows[ch].clear()
            if ch == "demo":
                self.counts = {k: 0 for k in COUNT_TAGS}
        self.emit("cleared", {"ch": ch})
        if ch == "demo":
            self.emit("counts", dict(self.counts))

    # ------------------------------------------------------------- tail loop
    def _tail_loop(self):
        while not self._down.is_set():
            for t in list(self.tailers) + list(self.lab_tailers):
                try:
                    t.poll()
                except Exception as e:      # noqa: BLE001
                    self.out_cb("gui", f"tail error: {e}")
            time.sleep(0.15)

    # ============================================================== DEMO
    def meta(self) -> dict:
        return {
            "actors": [{"key": k, "label": v[0], "ip": v[1]} for k, v in ACTORS.items()],
            "scenarios": {k: [{"id": f"{k}:{i}", "label": s["label"], "tip": s["tip"]} for i, s in enumerate(v)]
                          for k, v in SCENARIOS.items()},
            "tour": [{"title": t[0], "text": t[1]} for t in TOUR],
            "lab_enabled": LAB_ENABLED,
        }

    def build_demo_config(self) -> dict:
        try:
            with open(REAL_CONFIG, encoding="utf-8") as fh:
                points = json.load(fh).get("protected_points") or FALLBACK_POINTS
        except (OSError, ValueError):
            points = FALLBACK_POINTS
        auth = {ACTORS["hmi"][1]: {"name": "HMI", "allow": ["read", "write"]},
                ACTORS["laptop"][1]: {"name": "Engineering laptop", "allow": ["read", "write", "config"]}}
        if self.st["allow_attacker"]:
            auth[ACTORS["attacker"][1]] = {"name": "Attacker (allowlisted, read-only)", "allow": ["read"]}
        return {
            "_comment": "Generated by the PLC Guardian control panel for the Live Demo. Not the lab config.",
            "plc": {"ip": HOST, "port": PLC_PORT, "unit_ids": [1, 255]},
            "authorized_sources": auth,
            "unknown_sources": {"allow_reads": False},
            "protected_points": points,
            "enforcement": {"mode": self.st["mode"], "block_response": "exception", "exception_code": 1,
                            "block_out_of_range_from_authorized": False, "block_unexpected_unit_id": False},
            "proxy": {"listen_host": HOST, "listen_port": PROXY_PORT, "upstream_host": HOST,
                      "upstream_port": PLC_PORT, "connect_timeout_s": 3},
            "log": {"path": self.guardian_log or os.path.join(DEMO_LOGS, "demo.jsonl"), "log_allowed_reads": True},
            "active_response": {"enabled": True, "lockout_coil": 7, "trigger_decisions": ["BLOCK"],
                                "cooldown_seconds": 5, "unit": UNIT, "timeout_s": 2},
            "http_watch": {"enabled": False},
        }

    def write_demo_config(self) -> None:
        if self.st["system"] == "stopped" and not os.path.isdir(DEMO_DIR):
            return
        os.makedirs(DEMO_DIR, exist_ok=True)
        write_json_atomic(DEMO_CFG, self.build_demo_config())

    def set_control(self, route=None, mode=None, lockout=None, allow_attacker=None) -> None:
        if route is not None:
            self.st["route"] = "on" if route in (True, "on") else "off"
        if mode is not None:
            if mode not in ("monitor", "block"):
                raise ApiError("mode must be monitor or block")
            self.st["mode"] = mode
        if lockout is not None:
            self.st["lockout"] = bool(lockout)
        if allow_attacker is not None:
            self.st["allow_attacker"] = bool(allow_attacker)
        if mode is not None or allow_attacker is not None:
            self.write_demo_config()
        self.push_state()

    def start_system(self) -> None:
        with self._lock:
            if self.st["system"] != "stopped":
                return
            for port in (PLC_PORT, PROXY_PORT):
                if port_open(HOST, port):
                    raise ApiError(f"port {port} on {HOST} is already in use (a leftover demo process?)", 409)
            self.st["system"] = "starting"
        self.clear("demo")
        self.push_state()
        threading.Thread(target=self._start_worker, daemon=True).start()

    def _start_worker(self) -> None:
        try:
            os.makedirs(DEMO_LOGS, exist_ok=True)
            tag = now_tag()
            self.guardian_log = os.path.join(DEMO_LOGS, f"demo_{tag}_guardian.jsonl")
            resp_path = os.path.join(DEMO_LOGS, f"demo_{tag}_lockout.jsonl")
            write_json_atomic(DEMO_CFG, self.build_demo_config())
            self.plc_proc = Proc("PLC", [MOCK_PLC_PY, "--port", str(PLC_PORT), "--sim"], self.out_cb)
            self.plc_proc.start()
            if not wait_port(HOST, PLC_PORT):
                raise RuntimeError("simulated PLC did not start")
            self.proxy_proc = Proc("Guardian", [GUARDIAN_PY, "--config", DEMO_CFG, "--log", self.guardian_log,
                                                "proxy"], self.out_cb)
            self.proxy_proc.start()
            if not wait_port(HOST, PROXY_PORT):
                raise RuntimeError("Guardian proxy did not start (see the process console)")
            cfg = Config(DEMO_CFG)
            self.resp_log = EvidenceLog(resp_path)
            self.resp_log.write_session_start("gui-demo-active-response", cfg.sha256)
            self.responder = ActiveResponder(cfg, self.resp_log)
            self.stop_poll.clear()
            threading.Thread(target=self._poll_plc, daemon=True).start()
            self.tailers = [Tailer(self.guardian_log, self.on_rec), Tailer(resp_path, self.on_rec)]
            self.st["system"] = "running"
            self.set_result("System running. Pick a client's button, or run the guided tour.")
            self.push_state()
        except Exception as e:      # noqa: BLE001
            self.out_cb("gui", f"start failed: {e}")
            self.set_result(f"Could not start: {e}")
            self.st["system"] = "running"           # let stop_system tear down whatever did start
            self.stop_system()

    def stop_system(self) -> None:
        with self._lock:
            if self.st["system"] in ("stopped", "stopping"):
                return
            self.st["system"] = "stopping"
        self.push_state()
        threading.Thread(target=self._stop_worker, daemon=True).start()

    def _stop_worker(self) -> None:
        self.stop_poll.set()
        for p in (self.proxy_proc, self.plc_proc):
            if p:
                p.stop()
        if self.resp_log:
            try:
                self.resp_log.write({"record": "SESSION_END", "ts_utc": utc_iso(time.time()),
                                     "ts_source": "host_clock", "sensor": "gui-demo-active-response"})
                self.resp_log.close()
            except Exception:       # noqa: BLE001
                pass
        self.responder = self.resp_log = None
        time.sleep(0.4)
        for t in self.tailers:
            t.poll()
        self.tailers = []
        self.plc = None
        self.st["system"] = "stopped"
        self.set_result("System stopped. Logs are kept in guardian/demo/logs/ (see the Evidence screen).")
        self.emit("plc", None)
        self.push_state()

    def _poll_plc(self) -> None:
        while not self.stop_poll.is_set():
            try:
                c = mc.request(HOST, PLC_PORT, 1, pdu_read_coils(0, 8), timeout=1.0)
                h = mc.request(HOST, PLC_PORT, 1, pdu_read_hr(0, 1), timeout=1.0)
                plc = {"coils": [(c[2] >> i) & 1 for i in range(8)], "level": struct.unpack(">H", h[2:4])[0]}
            except Exception:       # noqa: BLE001
                plc = None
            if plc != self.plc:
                self.plc = plc
                self.emit("plc", plc)
            self.stop_poll.wait(0.35)

    def reset_plc(self) -> None:
        """Presenter reset: written straight to the simulated PLC, bypassing Guardian (not an attack)."""
        try:
            mc.request(HOST, PLC_PORT, 1, struct.pack(">BHHB", 15, 0, 8, 1) + b"\x00", timeout=2)
            mc.request(HOST, PLC_PORT, 1, pdu_write_reg(0, 0), timeout=2)
        except OSError as e:
            self.set_result(f"Reset failed: {e}")

    # --------------------------------------------------- records / reactions
    def on_rec(self, rec: dict) -> None:
        d = describe_event(rec, DEMO_NAMES)
        if d:
            row = self.add_row("demo", d)
            if rec.get("record") == "REQUEST" and rec.get("sensor") == "proxy":
                actor = IP_TO_ACTOR.get(rec.get("src_ip"))
                if actor:
                    self.emit("anim", {"actor": actor, "tag": row["tag"], "blocked": row["tag"] == "block",
                                       "direct": False})
        if (rec.get("record") == "REQUEST" and rec.get("sensor") == "proxy" and self.st["lockout"]
                and rec.get("decision") == "BLOCK" and self.responder is not None):
            threading.Thread(target=self.responder.maybe_respond, args=(rec,), daemon=True).start()

    # ------------------------------------------------------------ scenarios
    def send(self, actor: str, pdu: bytes, label: str = ""):
        """Blocking: one request as `actor`, through Guardian (route on) or straight to the PLC (route off)."""
        name, ip = ACTORS[actor]
        route = self.st["route"] == "on"
        port = PROXY_PORT if route else PLC_PORT
        self.tid += 1
        try:
            resp = mc.request(HOST, port, UNIT, pdu, tid=self.tid, bind=ip, timeout=4.0)
            text = mc.describe(resp)
            ok = resp is not None and not resp[0] & 0x80
        except OSError as e:
            text, ok = f"network error: {e}", False
        if not route:
            self.add_row("demo", (time.strftime("%H:%M:%S.000"), f"{name} · {ip}", summarize_pdu(pdu),
                                  "no Guardian", "Guardian was not in the path: nothing was checked or logged", "bypass"))
            self.emit("anim", {"actor": actor, "tag": "bypass", "blocked": False, "direct": True})
        self.set_result(f"{name}: {label or summarize_pdu(pdu)}  →  PLC/Guardian reply: {text}")
        return ok, text

    def run_scenario(self, sid: str) -> None:
        if self.st["system"] != "running":
            raise ApiError("start the system first", 409)
        try:
            actor, idx = sid.split(":")
            sc = SCENARIOS[actor][int(idx)]
        except (ValueError, KeyError, IndexError):
            raise ApiError("unknown scenario") from None

        def work():
            pdus, n_ok = sc["pdus"], 0
            for i, pdu in enumerate(pdus):
                o, _ = self.send(actor, pdu, sc["label"] if len(pdus) == 1 else f"{sc['label']} ({i + 1}/{len(pdus)})")
                n_ok += o
                if len(pdus) > 1:
                    time.sleep(0.12)
            if len(pdus) > 1:
                self.set_result(f"{ACTORS[actor][0]}: {sc['label']}: {n_ok}/{len(pdus)} requests answered normally")
        threading.Thread(target=work, daemon=True).start()

    # ----------------------------------------------------------------- tour
    def tour_run(self, i: int) -> dict:
        if not 0 <= i < len(TOUR):
            raise ApiError("unknown tour step")
        if i != 0 and self.st["system"] != "running":
            raise ApiError("start the system first (step 1 of the tour)", 409)
        fn = getattr(self, TOUR[i][2])
        threading.Thread(target=fn, daemon=True).start()
        return {"goto": "evidence"} if TOUR[i][2] == "tour_evidence" else {}

    def _setup(self, route, mode, lockout):
        self.set_control(route=route, mode=mode, lockout=lockout)
        time.sleep(0.4)
        self.reset_plc()
        time.sleep(0.4)

    def _attack_sequence(self):
        self.send("hmi", pdu_write_coil(2, 1), "HMI presses START")
        time.sleep(3.5)
        self.send("attacker", pdu_write_coil(4, 1), "Attacker forces bypass %M4 = 1")

    def tour_start(self):
        try:
            self.start_system()
        except ApiError as e:
            self.set_result(str(e))

    def tour_normal(self):
        self._setup(True, "block", False)
        self.send("hmi", pdu_read_hr(0, 1), "HMI reads tank level")
        time.sleep(0.5)
        self.send("hmi", pdu_read_coils(2, 6), "HMI reads status coils")
        time.sleep(0.5)
        self.send("hmi", pdu_write_coil(2, 1), "HMI presses START")

    def tour_noguard(self):
        self._setup(False, "block", False)
        self._attack_sequence()

    def tour_monitor(self):
        self._setup(True, "monitor", False)
        self._attack_sequence()

    def tour_lockout(self):
        self._setup(True, "monitor", True)
        self._attack_sequence()

    def tour_block(self):
        self._setup(True, "block", True)
        self._attack_sequence()
        time.sleep(1.0)
        self.send("hmi", pdu_read_hr(0, 1), "HMI still reads the tank")

    def tour_more(self):
        self.set_control(route=True, mode="block", lockout=False)
        time.sleep(0.4)
        self.send("attacker", pdu_read_hr(0, 1), "Attacker probes (read)")
        time.sleep(0.6)
        self.send("attacker", pdu_write_reg(0, 0), "Attacker fakes tank level")
        time.sleep(0.6)
        self.send("hmi", PDU_FC90, "HMI sends engineering command")

    def tour_evidence(self):
        pass

    # ================================================================ LAB
    def _need_lab(self):
        if not LAB_ENABLED:
            raise ApiError("Lab Mode is disabled in this environment (GUARDIAN_LAB=0, e.g. inside Docker)", 403)

    def lab_config(self) -> dict:
        self._need_lab()
        try:
            with open(REAL_CONFIG, encoding="utf-8") as fh:
                d = json.load(fh)
        except (OSError, ValueError) as e:
            raise ApiError(f"config.json: {e}", 500) from e
        plc, hw, ar = d.get("plc", {}), d.get("http_watch", {}), d.get("active_response", {})
        return {"active_response": bool(ar.get("enabled")), "http_watch": bool(hw.get("enabled")),
                "info": {"plc": f"{plc.get('ip')}:{plc.get('port')}", "lockout_coil": ar.get("lockout_coil"),
                         "hmi_watch": f"{hw.get('hmi_ip')}:{hw.get('hmi_port')}",
                         "allowlist": [f"{v.get('name', k)} ({k})" for k, v in d.get("authorized_sources", {}).items()]}}

    def lab_apply(self, active_response: bool, http_watch: bool) -> dict:
        """Set the two flags the passive monitor reads at start-up; every other setting is left as it is."""
        self._need_lab()
        with open(REAL_CONFIG, encoding="utf-8") as fh:
            d = json.load(fh)
        d["active_response"]["enabled"], d["http_watch"]["enabled"] = bool(active_response), bool(http_watch)
        write_json_atomic(REAL_CONFIG, d)
        self.out_cb("gui", f"config.json updated: active_response={bool(active_response)} http_watch={bool(http_watch)}")
        return self.lab_config()

    def lab_ifaces(self) -> list:
        self._need_lab()
        try:
            from scapy.all import conf
            return sorted({i.name for i in conf.ifaces.values() if getattr(i, "name", None)})
        except Exception as e:      # noqa: BLE001
            raise ApiError(f"interface detection failed (is scapy/Npcap installed?): {e}", 500) from e

    def lab_coils(self) -> dict:
        """Read-only status of the real PLC's %M2-%M7 plus whether THIS host may write to it."""
        self._need_lab()
        cfg = Config(REAL_CONFIG)
        own = _detect_own_ip(cfg.plc_ip, cfg.plc_port)
        src = cfg.sources.get(own or "")
        out = {"plc": f"{cfg.plc_ip}:{cfg.plc_port}", "own_ip": own, "reachable": False, "coils": {},
               "writer_ok": bool(src and "write" in src.get("allow", []))}
        try:
            unit = int(cfg.get("active_response", {}).get("unit", UNIT))
            c = mc.request(cfg.plc_ip, cfg.plc_port, unit, pdu_read_coils(2, 6), timeout=1.5)
            out["coils"] = {f"M{2 + i}": (c[2] >> i) & 1 for i in range(6)}
            out["reachable"] = True
        except Exception:       # noqa: BLE001
            pass
        return out

    def lab_clear(self, coil: int) -> dict:
        """One-click clear of %M7 (Guardian lockout) or %M4 (maintenance bypass) on the REAL PLC.

        Sent with Guardian's own validated FC5 helper (the reply must echo the request). Refused
        unless this host is an allowlisted writer, otherwise a running Guardian would flag the write
        as an attack and re-fire the lockout."""
        self._need_lab()
        if coil not in (4, 7):
            raise ApiError("only %M4 (maintenance bypass) and %M7 (Control Shield lockout) can be cleared here")
        cfg = Config(REAL_CONFIG)
        own = _detect_own_ip(cfg.plc_ip, cfg.plc_port)
        src = cfg.sources.get(own or "")
        if not src or "write" not in src.get("allow", []):
            raise ApiError(f"this host ({own}) is not an allowlisted writer in config.json, so the write would be "
                           "treated as an attack. Run this from the allowlisted engineering laptop.", 403)
        unit = int(cfg.get("active_response", {}).get("unit", UNIT))
        try:
            send_fc5(cfg.plc_ip, cfg.plc_port, unit, coil, False, 2.0)
        except Exception as e:      # noqa: BLE001
            raise ApiError(f"write to {cfg.plc_ip}:{cfg.plc_port} failed: {e}", 502) from e
        self.out_cb("gui", f"cleared %M{coil} on {cfg.plc_ip}:{cfg.plc_port} from {own}")
        return self.lab_coils()

    def lab_start(self, key: str, iface: str = "") -> None:
        """Start the passive monitor (the only Lab sensor) on a mirror-port interface."""
        self._need_lab()
        if key != "monitor":
            raise ApiError("unknown sensor: Lab Mode only runs the passive monitor")
        p = self.lab_procs.get(key)
        if p and p.alive():
            raise ApiError(f"{key} is already running", 409)
        if not iface.strip():
            raise ApiError("a capture interface is required for the passive monitor")
        log = os.path.join(HERE, "logs", f"gui_{key}_{now_tag()}.jsonl")
        args = ["--config", REAL_CONFIG, "--log", log, key, "--iface", iface.strip()]
        p = Proc(key, [GUARDIAN_PY, *args], self.out_cb)
        p.start()
        self.lab_procs[key] = p
        self.lab_logs[key] = log
        self.lab_tailers.append(Tailer(log, lambda rec: self._lab_rec(rec)))
        self.out_cb("gui", f"started {key}, evidence log: {log}")
        threading.Thread(target=self._lab_watch, args=(key, p), daemon=True).start()
        self.push_state()

    def _lab_rec(self, rec):
        d = describe_event(rec, {})
        if d:
            self.add_row("lab", d)

    def _lab_watch(self, key, p):
        while p.alive():
            time.sleep(0.7)
        self.push_state()

    def lab_stop(self, key: str) -> None:
        self._need_lab()
        p = self.lab_procs.get(key)
        if not p or not p.alive():
            return

        def stopper():
            p.stop()
            self.push_state()
        threading.Thread(target=stopper, daemon=True).start()

    # ============================================================ ANALYZE
    def captures(self) -> list:
        out = []
        for base in sorted({ROOT, HERE, os.environ.get("GUARDIAN_DATA", "")} - {""}):
            try:
                for f in sorted(os.listdir(base)):
                    if f.lower().endswith((".pcap", ".pcapng")):
                        p = os.path.join(base, f)
                        out.append({"path": p, "name": f, "size": os.path.getsize(p)})
            except OSError:
                pass
        return out

    def capture_hash(self, path: str) -> dict:
        return {"sha256": sha256_file(safe_path(path))}

    def analyze_run(self, mode: str, pcap: str, baseline: str = "") -> None:
        if mode not in ("analyze", "forensics", "baseline"):
            raise ApiError("unknown analysis")
        pcap = safe_path(pcap)
        if self.an_busy:
            raise ApiError("an analysis is already running", 409)
        base = ["--config", REAL_CONFIG]
        if baseline.strip() and mode != "baseline":
            base += ["--baseline", safe_path(baseline)]
        stem = os.path.splitext(os.path.basename(pcap))[0].replace(" ", "_")
        tag = f"gui_{stem}_{now_tag()}"
        out_dir = os.path.join("reports", tag)
        if mode == "analyze":
            log = os.path.join("logs", tag + ".jsonl")
            args, result = base + ["--log", log, "analyze", pcap, "-q"], ("log", os.path.join(HERE, log))
        elif mode == "forensics":
            args, result = base + ["forensics", pcap, "-o", out_dir], ("report", os.path.join(HERE, out_dir))
        else:
            os.makedirs(os.path.join(HERE, out_dir), exist_ok=True)
            bp = os.path.join(out_dir, "baseline.json")
            args, result = base + ["baseline", pcap, "-o", bp], ("baseline", os.path.join(HERE, bp))
        self.an_busy, self.an_result = True, None
        with self._lock:
            self.console["analyze"].clear()
        self.emit("cleared", {"ch": "analyze"})
        self.push_state()
        before = sha256_file(pcap)

        def work():
            p = Proc("an:" + mode, [GUARDIAN_PY, *args], self.out_cb)
            p.start()
            p.p.wait()
            time.sleep(0.3)
            after = sha256_file(pcap)
            res = {"mode": mode, "rc": p.p.returncode, "kind": result[0], "path": result[1], "pcap": pcap,
                   "sha_before": before, "sha_after": after, "unchanged": before == after, "rows": [], "report": ""}
            if p.p.returncode == 0:
                log_path = result[1] if result[0] == "log" else \
                    os.path.join(result[1], "events.jsonl") if result[0] == "report" else None
                if log_path and os.path.isfile(log_path):
                    res["log"] = log_path
                    res["rows"] = self._rows_from_log(log_path)
                if result[0] == "report":
                    try:
                        with open(os.path.join(result[1], "report.md"), encoding="utf-8") as fh:
                            res["report"] = fh.read()
                    except OSError:
                        pass
            self.an_result, self.an_busy = res, False
            self.emit("analyze_done", res)
            self.push_state()
        threading.Thread(target=work, daemon=True).start()

    # ============================================================ EVIDENCE
    def _rows_from_log(self, path: str, limit: int = 1500, names=None) -> list:
        rows, n = [], 0
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    d = describe_event(json.loads(line), names)
                except ValueError:
                    continue
                if d:
                    n += 1
                    rows.append(row_dict(n, "ev", d))
                    if n >= limit:
                        break
        return rows

    def evidence_logs(self) -> list:
        found = []
        for base in (DEMO_LOGS, os.path.join(HERE, "logs")):
            try:
                for f in os.listdir(base):
                    if f.endswith(".jsonl"):
                        p = os.path.join(base, f)
                        found.append((os.path.getmtime(p), p))
            except OSError:
                pass
        rep = os.path.join(HERE, "reports")
        try:
            for d in os.listdir(rep):
                p = os.path.join(rep, d, "events.jsonl")
                if os.path.isfile(p):
                    found.append((os.path.getmtime(p), p))
        except OSError:
            pass
        found.sort(reverse=True)
        return [{"path": p, "name": os.path.relpath(p, HERE), "mtime": m, "size": os.path.getsize(p)}
                for m, p in found[:60]]

    def evidence_records(self, path: str) -> list:
        return self._rows_from_log(safe_path(path), names=DEMO_NAMES if os.path.abspath(path).startswith(DEMO_DIR) else None)

    def evidence_verify(self, path: str) -> dict:
        ok, n, bad, msg = verify(safe_path(path))
        return {"ok": ok, "records": n, "bad_seq": bad, "message": msg}

    def evidence_tamper(self, path: str) -> dict:
        p = safe_path(path)
        with open(p, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        if len(lines) < 3:
            raise ApiError("need a log with at least 3 records (run a few scenarios first)")
        idx = next((i for i, ln in enumerate(lines) if '"decision":"BLOCK"' in ln), len(lines) // 2)
        orig_ok, _, _, orig_msg = verify(p)
        edited = lines[idx].replace('"decision":"BLOCK"', '"decision":"ALLOW"') if '"decision":"BLOCK"' in lines[idx] \
            else '{"tampered":true,' + lines[idx][1:]
        lines[idx] = edited
        os.makedirs(DEMO_DIR, exist_ok=True)
        cp = os.path.join(DEMO_DIR, "tampered_copy.jsonl")
        with open(cp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        ok, _, bad, msg = verify(cp)
        return {"original_ok": orig_ok, "original_message": orig_msg, "record_no": idx + 1,
                "was_block": '"decision":"ALLOW"' in edited, "copy_ok": ok, "copy_message": msg, "copy_path": cp}

    def evidence_csv(self, path: str) -> bytes:
        p = safe_path(path)
        out = os.path.join(DEMO_DIR, "export.csv")
        os.makedirs(DEMO_DIR, exist_ok=True)
        export_csv(p, out)
        with open(out, "rb") as fh:
            return fh.read()

    # ------------------------------------------------------------ shutdown
    def shutdown(self) -> None:
        self._down.set()
        self.stop_poll.set()
        procs = [p for p in (self.proxy_proc, self.plc_proc, *self.lab_procs.values()) if p and p.alive()]
        for p in procs:
            p.stop(3)
        if self.resp_log:
            try:
                self.resp_log.close()
            except Exception:       # noqa: BLE001
                pass
