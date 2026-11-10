"""Active response (D-007): Guardian's own authorized FC5 lockout-coil write, issued when a
BLOCK-worthy verdict fires in live `monitor` mode.

This is a reactive, PLC-side compensating control, NOT the inline proxy (D-003). A passive
mirror port cannot stop the attacker's frame from reaching the PLC first -- Guardian's
lockout write lands after it, over its own brand new outbound connection to the PLC, the same
way `tools/modbus_client.py` talks to the PLC (see `build()`/`request()` there). It only
applies to `monitor` mode; `analyze` (offline pcap) and `proxy` (which already blocks
synchronously) are untouched.

Off by default, and stays off unless ALL of the following hold -- never guessed or defaulted:
  - `active_response.enabled` is true,
  - `active_response.lockout_coil` is a real non-negative integer,
  - `active_response.trigger_decisions` is a non-empty list of real decisions (see policy.py)
    that contains nothing weaker than BLOCK (ALLOW/ALERT) unless explicitly opted into, and
  - `plc.ip` is non-empty.
A config that violates one of these while `enabled` is true raises ValueError at construction
time (I-008 item 4) rather than running with a silently-wrong setting; `guardian.py`'s
cmd_monitor catches that and falls back to `ActiveResponder.inactive()` so a bad config.json
degrades monitor mode to active-response-off instead of crashing it (I-008 item 6).

Every attempted write -- succeeded, failed, or skipped for cooldown -- is written to the same
hash-chained evidence log as everything else, as a new record type `ACTIVE_RESPONSE`, so the
audit trail covers Guardian's own actions too. A PLC that is slow or unreachable must never be
able to hang or crash monitor mode: the write runs over one overall deadline and any ordinary
exception is caught and logged, never raised back into the sniffer's callback (KeyboardInterrupt
is the one exception that IS re-raised, after being logged -- see `maybe_respond()`).

D-009 added a second, independent trigger source (`http_watch.py`'s passive HTTP-connection
watcher) that calls `maybe_respond()` from its own background thread, alongside the Modbus
sniffer's thread -- both share this one `ActiveResponder` instance so cooldown state is shared
across trigger types. `maybe_respond()` is internally locked (`self._lock`) across its entire
cooldown-check/send/log sequence so the two threads can't race each other into a double real
write or a torn log entry. Which destinations a BLOCK verdict may legitimately target is also
no longer a single fixed IP: `dst_ip == plc_ip` is trusted unconditionally from ANY sensor
(unchanged original behaviour), while any other destination is only trusted from the specific
`(sensor, dst_ip, dst_port)` triples passed in as `extra_triggers` -- see `__init__`'s comment.
"""
from __future__ import annotations

import socket
import struct
import threading
import time
from typing import Optional

from .evidence_log import EvidenceLog, utc_iso

# Decision vocabulary from policy.py (ALLOW/ALERT/BLOCK). Kept here as a literal set, not an
# import of policy's _RANK, so a future rename there is a visible merge conflict instead of a
# silent behaviour change in what this module will accept.
_VALID_DECISIONS = {"ALLOW", "ALERT", "BLOCK"}


def build_fc5(addr: int, on: bool) -> bytes:
    """FC5 Write Single Coil PDU: 0xFF00 = ON, 0x0000 = OFF (Modbus spec), same layout as
    tools/modbus_client.py's build("write-coil", ...)."""
    return struct.pack(">BHH", 5, addr, 0xFF00 if on else 0x0000)


def send_fc5(host: str, port: int, unit: int, addr: int, on: bool, timeout_s: float) -> bytes:
    """One-shot FC5 write over a new TCP connection to the PLC. Raises OSError/RuntimeError on
    any failure (connect timeout, reset, PLC exception reply, or a reply that does not actually
    prove the write happened -- see validation below); the caller is responsible for catching
    it -- this function never retries.

    A real FC5 success reply echoes the request PDU exactly (function code 0x05, same coil
    address, same 0xFF00/0x0000 value) with a transaction ID and unit ID matching what was
    sent. Nothing short of that full, matching echo counts as success (I-008 item 1): a short/
    truncated body, a wrong TID, a wrong unit, or any mismatching body all raise here, so the
    caller's `except` always logs FAILED rather than SUCCEEDED for them.

    `timeout_s` bounds the ENTIRE call (connect + send + every recv) via one overall deadline
    (I-008 item 7), not a fresh per-call timeout each time -- a slow peer trickling bytes one at
    a time can block for at most ~timeout_s total, not (7+length)*timeout_s.
    """
    pdu = build_fc5(addr, on)
    tid = 1  # fixed; the only thing that matters is that the reply below echoes this same value
    deadline = time.monotonic() + timeout_s

    def _remaining() -> float:
        r = deadline - time.monotonic()
        if r <= 0:
            raise TimeoutError(f"overall deadline of {timeout_s}s exceeded")
        return r

    s = socket.create_connection((host, port), timeout=_remaining())
    try:
        s.settimeout(_remaining())
        s.sendall(struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu)

        hdr = b""
        while len(hdr) < 7:
            s.settimeout(_remaining())
            chunk = s.recv(7 - len(hdr))
            if not chunk:
                raise ConnectionError("connection closed before a response header arrived")
            hdr += chunk
        recv_tid = struct.unpack(">H", hdr[0:2])[0]
        length = struct.unpack(">H", hdr[4:6])[0]
        recv_unit = hdr[6]
        if length < 1:
            raise RuntimeError(f"PLC response declared length={length}; no PDU to validate")

        body = b""
        while len(body) < length - 1:
            s.settimeout(_remaining())
            chunk = s.recv(length - 1 - len(body))
            if not chunk:
                # Was: `break`, which let a short body through to the success return below.
                # A truncated reply is never proof of a successful write -- fail loudly.
                raise ConnectionError(
                    f"connection closed with a short reply ({len(body)} of {length - 1} "
                    f"expected PDU bytes)")
            body += chunk

        if recv_tid != tid:
            raise RuntimeError(f"transaction ID mismatch: sent {tid}, PLC replied {recv_tid}")
        if recv_unit != unit:
            raise RuntimeError(f"unit ID mismatch: sent {unit}, PLC replied {recv_unit}")
        if body and body[0] & 0x80:
            code = body[1] if len(body) > 1 else None
            raise RuntimeError(f"PLC returned exception {code}")
        if body != pdu:
            raise RuntimeError(
                f"PLC reply PDU did not echo the request (sent {pdu.hex()}, got {body.hex()}) "
                f"-- not a valid FC5 success response")
        return body
    finally:
        s.close()


def _detect_own_ip(plc_ip: str, plc_port: int) -> Optional[str]:
    """Best-effort guess at which local IP this host would use to reach the PLC, so
    `maybe_respond()` can recognize (and never fire on) Guardian's own outbound write -- the
    same "ask a socket" approach proxy.py uses to learn its own listen address off
    `server.sockets[0].getsockname()`, rather than hardcoding an IP anywhere (I-008 item 3).
    A UDP connect() never sends a packet; it only asks the OS to pick the outbound route/source
    address for that destination. Returns None (guard simply does nothing) if that fails, e.g.
    no route to the PLC yet -- never raises into the caller."""
    if not plc_ip:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((plc_ip, plc_port or 1))
            return s.getsockname()[0]
    except OSError:
        return None


class ActiveResponder:
    """One instance per `monitor` run. Holds the cooldown state; `maybe_respond()` is called
    from the analyzer's on_event hook for every REQUEST record it writes."""

    def __init__(self, config, evlog: EvidenceLog, extra_triggers=None):
        self.config = config
        self.evlog = evlog
        self._last_fired: Optional[float] = None   # time.monotonic() of the last fired write
        # Cooldown-check-through-send-through-log is now reachable from two threads at once
        # (the Modbus sniffer's callback and, when http_watch.py is enabled, its own sniffer
        # thread -- both call maybe_respond() through cmd_monitor's shared on_event). Without
        # a lock, two threads could both pass the cooldown check before either sets
        # _last_fired, firing two real FC5 writes back to back, or a SKIPPED_COOLDOWN could log
        # while a send from the other thread is still in flight (D-009 architect review round
        # 2, should-fix 2). Held across the ENTIRE cooldown-check/send/log sequence below, not
        # just the _last_fired read/write, so the two threads are fully serialized through it.
        self._lock = threading.Lock()
        # I-008 item 2, generalized for the http_watch.py trigger (D-009 architect review round
        # 2, BLOCKER 1): a BLOCK verdict must only ever fire this write when its trigger is
        # something Guardian actually trusts to react on the PLC's behalf. That trust is now
        # WHO produced the record, not just where it was addressed to -- `dst_ip == plc_ip` is
        # trusted unconditionally (any sensor: this is exactly today's original, unchanged
        # behaviour), while any OTHER destination is only trusted from the specific
        # (sensor, dst_ip, dst_port) triples listed in `extra_triggers` (e.g.
        # `("http_watch", hmi_ip, hmi_port)`), checked below in `maybe_respond()`. A flat
        # "trusted IP" set would have let a MODBUS record addressed to the HMI's IP also fire
        # the lockout write just because that IP happened to be in the set -- this module never
        # even looks at Modbus traffic to the HMI, since the Modbus sniffer only watches
        # `plc.port`, but a generic allowlist of destination IPs couldn't tell the difference by
        # itself; keying on `sensor` too closes that off explicitly rather than by accident.
        # Defaults to empty so a run that never passes this argument (e.g. an older caller, or
        # http_watch disabled) behaves identically to before this parameter existed.
        self.extra_triggers = set(extra_triggers) if extra_triggers else set()

        cfg = config.get("active_response", {}) or {}
        enabled = bool(cfg.get("enabled", False))
        lockout_coil = cfg.get("lockout_coil")
        trigger_decisions = cfg.get("trigger_decisions", ["BLOCK"])
        cooldown_raw = cfg.get("cooldown_seconds", 5)
        unit_raw = cfg.get("unit", 1)
        timeout_raw = cfg.get("timeout_s", 2)
        # Explicit, separate opt-in (I-008 item 4): without this, trigger_decisions may only
        # ever contain "BLOCK" -- ALERT is also used for authorized-but-out-of-range writes
        # (e.g. the HMI's own maintenance-bypass toggle), and firing the lockout write on those
        # would lock out legitimate HMI use.
        allow_weak_trigger = bool(cfg.get("allow_weaker_than_block_trigger", False))

        errors = []

        # cooldown_seconds: a real, positive (>= 1) number. Rejects 0, negative, NaN, and
        # anything non-numeric rather than silently hammering the PLC every event in a burst.
        try:
            cooldown_seconds = float(cooldown_raw)
            if not (cooldown_seconds >= 1):   # also true for NaN, which fails every comparison
                errors.append(f"cooldown_seconds must be a number >= 1, got {cooldown_raw!r}")
        except (TypeError, ValueError):
            errors.append(f"cooldown_seconds must be numeric, got {cooldown_raw!r}")
            cooldown_seconds = 5.0

        # trigger_decisions: non-empty list of real decision values, nothing weaker than BLOCK
        # unless allow_weak_trigger opts in explicitly.
        if not isinstance(trigger_decisions, list) or not trigger_decisions:
            errors.append(f"trigger_decisions must be a non-empty list, got {trigger_decisions!r}")
            trigger_decisions = []
        else:
            unknown = [d for d in trigger_decisions if d not in _VALID_DECISIONS]
            if unknown:
                errors.append(f"trigger_decisions has unknown decision value(s) {unknown!r} "
                              f"(valid: {sorted(_VALID_DECISIONS)})")
            weak = [d for d in trigger_decisions if d in _VALID_DECISIONS and d != "BLOCK"]
            if weak and not allow_weak_trigger:
                errors.append(
                    f"trigger_decisions includes {weak!r}, weaker than BLOCK -- this would fire "
                    f"Guardian's own lockout write on an authorized-but-flagged event (e.g. the "
                    f"HMI's maintenance bypass) and lock out legitimate use; set "
                    f"active_response.allow_weaker_than_block_trigger=true to opt in explicitly")

        # lockout_coil: a real, non-negative int (bool excluded -- it is technically an int in
        # Python). None (the config.py default when omitted) is allowed through here -- that's
        # the normal "off" state -- but any other non-conforming value is a config error.
        valid_coil = (isinstance(lockout_coil, int) and not isinstance(lockout_coil, bool)
                      and lockout_coil >= 0)
        if lockout_coil is not None and not valid_coil:
            errors.append(f"lockout_coil must be a non-negative integer, got {lockout_coil!r}")

        if enabled and not config.plc_ip:
            errors.append("active_response.enabled is true but plc.ip is empty")

        self.errors = errors
        if enabled and errors:
            raise ValueError("active_response config is invalid: " + "; ".join(errors))

        self.enabled = enabled
        self.lockout_coil = lockout_coil
        self.trigger_decisions = set(trigger_decisions)
        self.cooldown_seconds = cooldown_seconds
        self.unit = int(unit_raw)
        self.timeout_s = float(timeout_raw)

        # off unless enabled AND lockout_coil is a real non-negative int AND plc.ip is set.
        self.active = bool(self.enabled and valid_coil and config.plc_ip)
        self.own_ip = _detect_own_ip(config.plc_ip, config.plc_port) if self.active else None

    @classmethod
    def inactive(cls, config, evlog: EvidenceLog, extra_triggers=None) -> "ActiveResponder":
        """A no-op responder that never raises, used when constructing the real one failed
        because active_response's own config is invalid (I-008 item 6) -- lets `monitor` mode
        degrade to active-response-off instead of crashing before SESSION_END is written."""
        self = cls.__new__(cls)
        self.config = config
        self.evlog = evlog
        self._last_fired = None
        self._lock = threading.Lock()
        self.extra_triggers = set(extra_triggers) if extra_triggers else set()
        self.enabled = False
        self.lockout_coil = None
        self.trigger_decisions = set()
        self.cooldown_seconds = 5.0
        self.unit = 1
        self.timeout_s = 2.0
        self.active = False
        self.own_ip = None
        self.errors = ["constructed via ActiveResponder.inactive() fallback"]
        return self

    def maybe_respond(self, request_rec: dict) -> Optional[dict]:
        """`request_rec` is the REQUEST record as already written to the evidence log (has
        `seq`). Returns the ACTIVE_RESPONSE record if one was written, else None (feature is
        inert, this verdict doesn't trigger it, or a safety guard below says not to even
        evaluate this request as a trigger)."""
        if not self.active:
            return None
        if request_rec.get("decision") not in self.trigger_decisions:
            return None

        # I-008 item 2 (generalized by D-009, see __init__'s comment on extra_triggers):
        # dst_ip == plc_ip is trusted unconditionally, exactly as always; any other
        # destination is only trusted from the specific (sensor, dst_ip, dst_port) this
        # responder was explicitly told to trust. A BLOCK verdict addressed anywhere else
        # must not trigger a write to the real PLC's lockout coil.
        dst_ip = request_rec.get("dst_ip")
        if dst_ip != self.config.plc_ip:
            trigger_key = (request_rec.get("sensor"), dst_ip, request_rec.get("dst_port"))
            if trigger_key not in self.extra_triggers:
                return None

        # I-008 item 3: Guardian's own outbound lockout write is itself live Modbus traffic
        # that the sniffer sees and could otherwise re-evaluate as a trigger. Skip (don't even
        # evaluate) anything that looks like Guardian's own hand: traffic FROM this host, or a
        # write that targets the lockout coil with the value that would clear/undo it.
        if self.own_ip and request_rec.get("src_ip") == self.own_ip:
            return None
        if (request_rec.get("category") == "write" and request_rec.get("table") == "coil"
                and request_rec.get("address") == self.lockout_coil
                and request_rec.get("values") in ([0], [False])):
            return None

        # Everything from here on touches shared state (_last_fired) and/or makes the real
        # network write, so it is fully serialized across both possible caller threads (see
        # __init__'s comment on self._lock).
        with self._lock:
            now = time.monotonic()
            if self._last_fired is not None and (now - self._last_fired) < self.cooldown_seconds:
                return self._log(request_rec, outcome="SKIPPED_COOLDOWN",
                                  detail=f"last fired {now - self._last_fired:.2f}s ago "
                                         f"(cooldown {self.cooldown_seconds}s)")

            self._last_fired = now  # mark the attempt, not just success: a hung/failed PLC
                                     # must not be hammered every event in a burst either
            try:
                send_fc5(self.config.plc_ip, self.config.plc_port, self.unit, self.lockout_coil,
                         True, self.timeout_s)
                return self._log(request_rec, outcome="SUCCEEDED")
            except Exception as e:       # noqa: BLE001 -- must never escape into the sniffer loop
                return self._log(request_rec, outcome="FAILED", detail=f"{type(e).__name__}: {e}")
            except BaseException as e:
                # Ctrl+C (or SystemExit/GeneratorExit) mid-write: log the interrupted attempt
                # before letting it propagate, so shutdown isn't silently missing from the
                # evidence trail (I-008 item 8).
                self._log(request_rec, outcome="INTERRUPTED", detail=f"{type(e).__name__}: {e}")
                raise

    def _log(self, request_rec: dict, outcome: str, detail: Optional[str] = None) -> Optional[dict]:
        rec = {
            "record": "ACTIVE_RESPONSE",
            "ts_utc": utc_iso(time.time()),
            "ts_source": "host_clock",
            "sensor": "active_response",
            "trigger_seq": request_rec.get("seq"),
            "trigger_decision": request_rec.get("decision"),
            "trigger_event_type": request_rec.get("event_type"),
            "trigger_src_ip": request_rec.get("src_ip"),
            "trigger_source_name": request_rec.get("source_name"),
            "trigger_summary": request_rec.get("summary"),
            "plc_ip": self.config.plc_ip,
            "plc_port": self.config.plc_port,
            "unit": self.unit,
            "lockout_coil": self.lockout_coil,
            "outcome": outcome,
        }
        if detail:
            rec["details"] = [detail]
        try:
            return self.evlog.write(rec)
        except RuntimeError as e:
            # D-009 architect review round 2, BLOCKER 2: the evidence log can be closed out
            # from under a background sniffer thread during cmd_monitor's shutdown (bounded
            # join timeout expired, or the race window before it). A real FC5 write that
            # succeeded (outcome SUCCEEDED/FAILED above) but can no longer be logged is exactly
            # the case D-007's "every attempted write is logged" guarantee cannot cover once the
            # log is gone -- there is nowhere left to put the record. Surface it loudly on the
            # console (never silently swallowed) instead of raising into the sniffer callback,
            # which would otherwise crash that thread.
            print(f"[ARESP] WARNING: could not log ACTIVE_RESPONSE outcome={outcome} for "
                  f"trigger seq={request_rec.get('seq')}: evidence log already closed ({e})")
            return None
