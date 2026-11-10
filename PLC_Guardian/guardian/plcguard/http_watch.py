"""Passive HTTP-connection watcher: a second, independent trigger source for the D-007
active-response lockout (plcguard/active_response.py), for deployments where Guardian can
see the HMI's web traffic on a mirror port but is NOT inline on that segment (no `httpgate.py`,
D-008, in the path there).

IMPORTANT -- this module is PASSIVE, exactly like `analyzer.py`'s `sniff_live()`: it can
detect and log a TCP connection attempt to the HMI's web port, and it can ask
`ActiveResponder.maybe_respond()` to react afterward with Guardian's own FC5 lockout write to
the PLC, but it cannot stop the attacker's original TCP SYN/HTTP request from reaching the
HMI. The "attack lands, compensating control follows" framing D-007 already uses for Modbus
BLOCKs applies here too: by the time the lockout coil write lands, the HTTP connection this
module saw has already been accepted by the HMI. `httpgate.py` (D-008, inline) CAN refuse the
connection itself -- it exists today -- but only once Guardian is actually in the path between
clients and the HMI, which is the same not-yet-built inline topology dependency `proxy.py` has
for the Modbus leg (A-004/A-033). Until then, point `httpgate.py`'s listen address at test
clients directly to exercise it; it is not yet in the path of real traffic aimed at the HMI's
real address, and this module (`http_watch.py`) is the only thing that sees that real traffic
passively.

OPERATIONAL LESSON (learned the hard way on the Modbus side, I-009): D-007's first live test
false-fired because an authorized source's own legitimate-but-unlisted traffic pattern wasn't
in the allowlist yet. Do not arm `http_watch.py` with `active_response.enabled=true` live
without going through the same discipline that fixed that: run with `http_watch.enabled=true`
and `active_response.enabled=false` first, let it log every real source that legitimately
opens a connection to `.10:80` (the HMI's own health checks, browser tabs left open, monitoring
tools, etc.), get every one of them into `authorized_sources` with the right MAC, and only then
enable `active_response` -- otherwise the very first unlisted-but-legitimate connection fires a
real lockout write against live hardware.

Mirrors `analyzer.sniff_live()`'s scapy usage and BPF-filter style: filter is
`tcp port {hmi_port} and host {hmi_ip}`, both configurable (`http_watch.hmi_ip`,
`http_watch.hmi_port` in config.json). A NEW TCP connection attempt is recognized as a SYN
without ACK (`tcp.flags` includes 'S', not 'A') -- the same bit scapy's `sniff_live` tests for
stream start, re-purposed here to mean "connection attempt" rather than "stream start" since
this module does not reassemble the HTTP stream at all.

Authorization reuses `config.sources` (the SAME `authorized_sources` allowlist policy.py and
the Modbus side already use) directly -- there is deliberately no second, parallel allowlist to
keep in sync. Like `policy.py`'s `MAC_MISMATCH` rule, a source IP that IS listed but arrives
with a different MAC than configured is NOT treated as authorized here either (a source
spoofing an allowlisted IP must not pass silently); see `HttpWatch.handle_syn`.

De-duplication and rate-limiting (so one attacker can't drown the evidence log, or slow the
Modbus sniffer's own callback enough for Npcap to drop Modbus packets, by generating lots of
SYNs):
  - Retransmitted SYNs for the exact same (src_ip, src_port) within `_DEDUP_WINDOW_S` are
    treated as the one connection attempt already logged -- `ActiveResponder`'s own cooldown
    already suppresses repeated lockout fires, so this part is purely about not spamming the
    log with duplicates of ONE handshake.
  - A SYN flood or port scan from one source IP across MANY different source ports is a
    different problem dedup alone doesn't cover: `_RATE_WINDOW_S` caps logging to at most one
    REQUEST record per source IP per window, with every additional attempt in that window
    folded into a `suppressed_count` on the next record instead of writing one record each.
  - `_seen`/`_rate` are pruned on every call so a long-running `monitor` session doesn't grow
    them unboundedly from many distinct attacking source ports/IPs.

Shutdown: scapy's `sniff(stop_filter=...)` only evaluates the stop filter between PACKETS it
receives, so on quiet traffic a single unbounded `sniff()` call may never check it and never
return. `sniff_http_watch()` instead loops a short, bounded `sniff(timeout=_SNIFF_SLICE_S, ...)`
call and re-checks `stop_event` between slices, so it returns within one slice length of
`stop_event.set()` regardless of how little port-80 traffic there is -- not "promptly" in the
sub-second sense, but bounded and predictable. The caller (`cmd_monitor`) runs this on a
background `threading.Thread`, is responsible for `stop_event.set()` plus a bounded
`thread.join(timeout=...)` comfortably larger than `_SNIFF_SLICE_S` in its shutdown path, and
must disarm the shared `ActiveResponder` (`responder.active = False`) BEFORE that join so that
even a packet slipping in during the shutdown race can't fire a live PLC write after the
evidence log has started closing -- see `cmd_monitor`'s `finally` block.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from .config import Config, _norm_mac
from .evidence_log import EvidenceLog, utc_iso

_DEDUP_WINDOW_S = 5.0   # suppress a duplicate REQUEST record for the same (src_ip, src_port)
                        # SYN retransmit within this window; well under active_response's own
                        # default cooldown_seconds (5s), so it never masks a genuinely new
                        # connection attempt from a fast-reconnecting attacker.
_RATE_WINDOW_S = 10.0   # at most one REQUEST record per source IP per this many seconds,
                        # regardless of how many distinct source ports it tries -- a SYN flood
                        # / port scan guard, separate from the per-(ip,port) dedup above.
_PRUNE_MAX_AGE_S = max(_DEDUP_WINDOW_S, _RATE_WINDOW_S) * 4   # bound _seen/_rate growth
_MAX_LOGGED_IP_LEN = 64   # defensive cap on an attacker-influenced string before it goes into
                          # a log line / console print (scapy has already parsed src_ip as a
                          # valid IP literal, so this is cheap insurance, not a real boundary)


def _safe_str(value: str, max_len: int = _MAX_LOGGED_IP_LEN) -> str:
    """Bound and make printable any attacker-influenced value before it lands in an evidence
    record's `details`/`summary` or a console print -- never trust that an upstream parser's
    output is already safe to print/log verbatim."""
    s = str(value)
    if len(s) > max_len:
        s = s[:max_len] + "...(truncated)"
    return s.encode("unicode_escape").decode("ascii")


def build_http_request_record(src_ip: str, src_port: int, hmi_ip: str, hmi_port: int,
                               ts: float, spoofed_mac: Optional[str] = None,
                               suppressed_count: int = 0) -> dict:
    """Build the REQUEST-shaped record for one unauthorized SYN to the HMI's web port. Exposed
    as a standalone function (not inlined in the sniff callback) so it can be unit-tested
    without scapy's sniff()/live capture at all -- see
    test_runs/a033_http_watch/http_watch_check.py.

    `spoofed_mac`, if given, means the source IP IS listed in authorized_sources but arrived
    with a different MAC than configured (mirrors policy.py's MAC_MISMATCH rule) -- the event
    is reclassified from a plain unauthorized-source access to a spoofed-source one.
    `suppressed_count` folds in how many additional connection attempts from this same source
    IP were rate-limited (not individually logged) since the last record for it.
    """
    src_ip_s = _safe_str(src_ip)
    if spoofed_mac is not None:
        event_type, rules = "SPOOFED_SOURCE", ["MAC_MISMATCH"]
        detail = (f"{src_ip_s} opened a TCP connection to the HMI web port {hmi_port} using "
                   f"MAC {_safe_str(spoofed_mac)}, which does not match the MAC configured for "
                   f"that IP in authorized_sources -- treated as spoofed, not authorized")
    else:
        event_type, rules = "UNAUTHORIZED_HTTP_ACCESS", ["SRC_NOT_ALLOWLISTED_HTTP"]
        detail = (f"{src_ip_s} opened a TCP connection to the HMI web port {hmi_port}; not in "
                   f"authorized_sources")
    details = [detail]
    if suppressed_count:
        details.append(f"{suppressed_count} additional connection attempt(s) from {src_ip_s} "
                        f"in the preceding {_RATE_WINDOW_S:.0f}s were rate-limited, not "
                        f"individually logged")
    return {
        "record": "REQUEST",
        "ts_utc": utc_iso(ts),
        "ts_source": "host_clock",
        "sensor": "http_watch",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": hmi_ip,
        "dst_port": hmi_port,
        "source_name": None,
        "authorized": False,
        "category": "access",
        "event_type": event_type,
        "decision": "BLOCK",
        "rules": rules,
        "details": details,
        "summary": f"TCP SYN to HMI:{hmi_port} from {'spoofed' if spoofed_mac else 'unauthorized'} "
                    f"source {src_ip_s}",
        "action": "OBSERVED",   # passive: Guardian cannot block this connection itself (see
                                 # module docstring); only active_response.py's reactive
                                 # lockout write can follow it.
    }


class HttpWatch:
    """One instance per `monitor` run with `http_watch.enabled = true`. Holds the de-dup/
    rate-limit state; actual reaction to a logged event is the caller's job (feeding the
    written record into the shared `ActiveResponder.maybe_respond()`, same as the Modbus
    side)."""

    def __init__(self, config: Config, evlog: EvidenceLog,
                 on_event: Optional[Callable[[dict], None]] = None):
        self.config = config
        self.evlog = evlog
        self.on_event = on_event
        cfg = config.get("http_watch", {}) or {}
        self.hmi_ip = cfg.get("hmi_ip", "192.168.8.10")
        self.hmi_port = int(cfg.get("hmi_port", 80))
        self._seen: dict = {}   # (src_ip, src_port) -> time.monotonic() of last logged SYN
        self._rate: dict = {}   # src_ip -> {"window_start": monotonic, "suppressed": int}
        self.count = 0

    def _prune(self, now: float) -> None:
        """Bound _seen/_rate growth: a long-running session hit by many distinct attacking
        source ports/IPs must not accumulate unbounded dict entries."""
        stale = [k for k, t in self._seen.items() if (now - t) > _PRUNE_MAX_AGE_S]
        for k in stale:
            del self._seen[k]
        stale_ips = [ip for ip, st in self._rate.items()
                     if (now - st["window_start"]) > _PRUNE_MAX_AGE_S]
        for ip in stale_ips:
            del self._rate[ip]

    def _dedup_ok(self, key, now: float) -> bool:
        last = self._seen.get(key)
        self._seen[key] = now
        return last is None or (now - last) >= _DEDUP_WINDOW_S

    def _rate_check(self, src_ip: str, now: float) -> Optional[int]:
        """Returns the suppressed_count to attach to a new record if this source IP is due to
        be logged again (new window), or None if this attempt should be silently counted and
        suppressed instead (still inside an existing window)."""
        state = self._rate.get(src_ip)
        if state is not None and (now - state["window_start"]) < _RATE_WINDOW_S:
            state["suppressed"] += 1
            return None
        suppressed = state["suppressed"] if state is not None else 0
        self._rate[src_ip] = {"window_start": now, "suppressed": 0}
        return suppressed

    def handle_syn(self, src_ip: str, src_port: int, ts: float,
                   src_mac: Optional[str] = None) -> Optional[dict]:
        """Called for every new (SYN, non-ACK) connection attempt to the HMI's web port.
        Returns the written REQUEST record, or None if the source is authorized (IP AND MAC
        match), a deduped retransmit, or rate-limited this window."""
        now_m = time.monotonic()
        self._prune(now_m)

        src = self.config.sources.get(src_ip)
        spoofed_mac = None
        if src is not None:
            configured_mac = src.get("mac")
            if configured_mac and src_mac and _norm_mac(src_mac) != configured_mac:
                spoofed_mac = src_mac   # listed IP, wrong MAC -> treat as spoofed, not authorized
            else:
                return None             # listed IP, MAC matches (or unknown) -> authorized

        if not self._dedup_ok((src_ip, src_port), now_m):
            return None
        suppressed = self._rate_check(src_ip, now_m)
        if suppressed is None:
            return None

        self.count += 1
        rec = self.evlog.write(build_http_request_record(
            src_ip, src_port, self.hmi_ip, self.hmi_port, ts,
            spoofed_mac=spoofed_mac, suppressed_count=suppressed))
        if self.on_event:
            self.on_event(rec)
        return rec


_SNIFF_SLICE_S = 1.0   # see module docstring's Shutdown section: bounded slice length so the
                        # loop below notices stop_event promptly even on quiet traffic.


def sniff_http_watch(iface: Optional[str], config: Config, evlog: EvidenceLog,
                      on_event: Optional[Callable[[dict], None]] = None,
                      stop_event: Optional[threading.Event] = None) -> HttpWatch:
    """Loops short, bounded scapy `sniff()` slices (see module docstring's Shutdown section for
    why one unbounded call is not stoppable) filtered to the HMI's web port, until `stop_event`
    is set. Callers (cmd_monitor) run this on a background thread and signal `stop_event` plus
    a bounded `join()` from their shutdown path.
    """
    import scapy.layers.l2, scapy.layers.inet   # noqa: F401  register link types before sniff()
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import sniff

    watch = HttpWatch(config, evlog, on_event=on_event)
    stop_event = stop_event or threading.Event()

    def cb(pkt):
        if IP not in pkt or TCP not in pkt:
            return
        tcp = pkt[TCP]
        # New connection attempt only: SYN set, ACK not set. A SYN-ACK (HMI's reply) or any
        # established-connection segment has ACK set and is ignored -- this module only ever
        # reports the attacker's/client's opening SYN.
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            return
        ip = pkt[IP]
        if ip.dst != watch.hmi_ip or tcp.dport != watch.hmi_port:
            return
        smac = pkt[Ether].src if Ether in pkt else None
        watch.handle_syn(ip.src, tcp.sport, float(pkt.time), src_mac=smac)

    bpf = f"tcp port {watch.hmi_port} and host {watch.hmi_ip}"
    while not stop_event.is_set():
        sniff(iface=iface, filter=bpf, prn=cb, store=False, timeout=_SNIFF_SLICE_S)
    return watch
