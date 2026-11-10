"""Connection-level inline gate for the HMI's web API (partial mitigation for RAID R-004).

    attacker / unlisted host --TCP 80--> Guardian (this gate) --TCP 80--> HMI

Unlike plcguard/proxy.py (which decodes Modbus and has a per-action policy via
policy.py), this gate does NOT parse HTTP at all. The decision is made exactly
once, at TCP-connect time, from the source IP against the same
`authorized_sources` allowlist policy.py uses for Modbus -- specifically, a
source must be present AND have "write" in its `allow` list (D-008 architect
review round 1, should-fix 8: this gate has no per-action categories the way
policy.py does, so forwarding its HTTP traffic at all is treated as equivalent
to Modbus write access, not just read):

    source IP authorized for write      -> ALLOW (relay the whole connection, unmodified)
    source IP not authorized for write  -> BLOCK (close immediately; nothing is relayed)

It cannot tell a benign GET of the HMI's status page from a malicious
`POST /services/variable/hmi/1` from the SAME authorized source -- that needs
an HTTP-aware policy (a method/path/body decoder + rules, the way modbus.py +
policy.py work for Modbus). Not built; see D-008's "Consequences".

Like plcguard/proxy.py, this only prevents anything if the HMI is reachable
*only* through Guardian -- the same A-004-style inline-topology dependency,
not yet built for the HMI leg either. Until that topology exists, pointing a
test client's HTTP requests directly at this gate's listen address is how to
exercise it; it is not yet actually in the live path of real attacker traffic
aimed at the HMI's real address.

Run it as its own `guardian.py httpgate` process, alongside (not instead of)
the Modbus proxy/monitor -- but note `http_gate.log_path` defaults to its OWN
evidence log file, separate from `log.path`. Two processes appending to one
log file split the hash chain (D-008 architect review round 1, BLOCKER 1);
`EvidenceLog` also now refuses outright to open a log file something else
already has open, so that mistake fails loudly at startup instead of silently
corrupting the chain.
"""
from __future__ import annotations

import asyncio
import logging
import time

from .config import Config
from .evidence_log import EvidenceLog, utc_iso

log = logging.getLogger("guardian.httpgate")

_FIRST_LINE_TIMEOUT_S = 2.0      # how long to wait for a request line before relaying blind
_REQUEST_LINE_LIMIT = 256        # D-008 round 1 should-fix 7: bound + escape, never trust raw attacker bytes
_BLOCK_LOG_INTERVAL_S = 2.0      # rate-limit BLOCK evidence writes per source IP (should-fix 6)


def _preview(data: bytes, limit: int = _REQUEST_LINE_LIMIT) -> str | None:
    """A bounded, safe-to-print representation of attacker-controlled bytes.

    Truncates before decoding (so a multi-megabyte line never gets fully decoded just to
    be thrown away) and returns a `repr()` of the result, which escapes control characters
    (including ANSI escapes -- round 1 should-fix 7 flagged printing raw bytes to the
    console as an injection vector) and non-printable/non-ASCII bytes alike.
    """
    if not data:
        return None
    truncated = len(data) > limit
    text = data[:limit].decode("latin-1")
    return repr(text) + ("...(truncated)" if truncated else "")


class HttpGate:
    def __init__(self, config: Config, evlog: EvidenceLog, console=print, on_reload=None):
        self.config = config
        self.evlog = evlog
        self.console = console
        self.on_reload = on_reload   # called with (self.config) right after a reload, so the
                                      # caller can re-apply CLI overrides config.load() just wiped
                                      # (D-008 round 1 should-fix 4)
        self.stats = {"connections": 0, "forwarded": 0, "blocked": 0, "alerts": 0,
                      "upstream_errors": 0, "rejected_capacity": 0, "revoked_on_reload": 0,
                      "blocked_suppressed": 0}
        self._client_writers: set[asyncio.StreamWriter] = set()   # tracked so shutdown can close them without waiting
        self._active: dict[asyncio.StreamWriter, dict] = {}        # writer -> {src_ip, src_port, authorized}
        self._last_block_log: dict[str, float] = {}                # src_ip -> ts of last logged BLOCK
        self._block_suppressed: dict[str, int] = {}                 # src_ip -> count suppressed since then

    @property
    def gcfg(self) -> dict:
        return self.config.get("http_gate", {})

    def _is_authorized(self, src_ip: str):
        src = self.config.sources.get(src_ip)
        authorized = src is not None and "write" in src.get("allow", [])
        return authorized, src

    def _safe_write(self, rec: dict):
        """evlog.write() under a bare try/except: a log-write failure (e.g. disk full, fsync
        error) must fail this connection closed, never crash the gate -- but round 1 nit 11
        flagged that it was being swallowed with no console trace at all. Returns None (and
        prints [ERROR]) on failure instead of letting the exception propagate. Every caller
        that writes the ALLOW/FORWARDED decision record MUST check this return value and
        fail the connection closed on None (D-008 round 2 BLOCKER): a write failure here is
        not just a logging gap, it means the connection is about to be relayed with NO
        evidence record at all. Catches RuntimeError too, not just OSError -- evlog.write()
        raises RuntimeError if called after the log has been close()'d (D-009's `_closed`
        flag), which is exactly the kind of failure this must also fail closed on."""
        try:
            return self.evlog.write(rec)
        except (OSError, RuntimeError) as e:
            self.console(f"[ERROR] evidence log write failed: {e!r}")
            return None

    def _maybe_reload(self) -> None:
        if self.config.reload_if_changed():
            if self.on_reload:
                self.on_reload(self.config)
            self._safe_write({"record": "CONFIG_RELOADED", "ts_utc": utc_iso(time.time()),
                              "ts_source": "host_clock", "sensor": "httpgate",
                              "config_sha256": self.config.sha256,
                              "enforcement_mode": self.config["enforcement"]["mode"],
                              "authorized_sources": sorted(self.config.sources)})
            self.console(f"[config] reloaded; mode={self.config['enforcement']['mode']} "
                         f"allowlist={sorted(self.config.sources)}")
            self._revoke_now_unauthorized()

    def _revoke_now_unauthorized(self) -> None:
        """D-008 round 1 should-fix 5: proxy.py re-evaluates every Modbus frame against the
        current config, but this gate's decision is made once, at connect time -- a reload
        that removes a source from the allowlist (or flips monitor->block) previously had no
        effect on that source's already-open keep-alive connection, which kept relaying
        indefinitely. Close any open connection that the NEW config would now refuse."""
        if self.config["enforcement"]["mode"] != "block":
            return
        for w, info in list(self._active.items()):
            # D-008 round 2 should-fix 2: skip on "relayed", not "authorized". In monitor
            # mode an unauthorized connection is still relayed (authorized=False the whole
            # time, by design) and stays in _active -- if enforcement.mode then flips to
            # block while it's still open, "not authorized" would wrongly skip it here and
            # it would never be revoked. "relayed" only means "already blocked and gone, so
            # there's nothing left to revoke" -- true in both modes.
            if not info.get("relayed") or info.get("revoked"):
                # D-008 round 3 architect review, nit 4: skip one already marked revoked too
                # -- a second reload tick during the same still-connecting window would
                # otherwise write a duplicate REVOKED_ON_RELOAD record and double-count
                # stats["revoked_on_reload"] for the same connection.
                continue
            authorized, _src = self._is_authorized(info["src_ip"])
            if authorized:
                continue
            info["authorized"] = False
            info["revoked"] = True   # D-008 round 2 should-fix 4: pipe() closures check this
                                      # each loop iteration so in-flight bytes already read
                                      # client-side don't keep reaching the HMI after this.
            self._safe_write({
                "record": "HTTP_CONNECTION", "ts_utc": utc_iso(time.time()), "ts_source": "host_clock",
                "sensor": "httpgate", "src_ip": info["src_ip"], "src_port": info["src_port"],
                "decision": "BLOCK", "event_type": "UNAUTHORIZED_CONNECTION", "authorized": False,
                "rules": ["SRC_NOT_ALLOWLISTED"], "action": "REVOKED_ON_RELOAD",
                "details": [f"{info['src_ip']} lost its write authorization on a config reload; "
                            f"its already-open connection is being closed now"]})
            self.console(f"[REVOKED] {info['src_ip']}:{info['src_port']} -- connection closed "
                         f"after config reload (no longer allowlisted)")
            for ww in (w, info.get("u_writer")):
                if ww is None:
                    continue
                try:
                    ww.close()
                except Exception:
                    pass
            self.stats["revoked_on_reload"] += 1

    def _log_rate_limited(self, rec: dict, src_ip: str) -> bool:
        """Shared rate-limiting for high-volume rejection records (D-008 round 2 nit 8:
        factored out of the BLOCK path so REJECTED_MAX_CONNECTIONS -- a connect flood at
        the cap -- gets the same "fsync once per interval per source, not once per
        rejected connection" treatment, instead of fsync'ing once per rejection). Writes
        `rec` (with any already-suppressed count folded into its details) if the interval
        since the last write for this src_ip has elapsed, else just increments the
        suppressed counter. Returns True iff it actually wrote."""
        now = time.time()
        last = self._last_block_log.get(src_ip, 0.0)
        if now - last >= _BLOCK_LOG_INTERVAL_S:
            suppressed = self._block_suppressed.pop(src_ip, 0)
            if suppressed:
                rec["details"].append(
                    f"{suppressed} more BLOCKed/rejected connection(s) from {src_ip} in the "
                    f"last {_BLOCK_LOG_INTERVAL_S:.0f}s were rate-limited out of the log")
                self.stats["blocked_suppressed"] += suppressed
            self._safe_write(rec)
            self._last_block_log[src_ip] = now
            return True
        self._block_suppressed[src_ip] = self._block_suppressed.get(src_ip, 0) + 1
        return False

    def flush_suppressed_blocks(self) -> None:
        """D-008 round 2 should-fix 5: _last_block_log/_block_suppressed only flush a
        source's suppressed count the next time THAT source connects again after the
        interval -- a burst followed by silence (or by shutdown) loses that source's
        suppressed count forever, undercounting stats["blocked_suppressed"] relative to
        stats["blocked"]. Call this once, at shutdown, before the SESSION_END record, to
        write a final summary record for every source still holding a suppressed count."""
        for src_ip, count in list(self._block_suppressed.items()):
            if count:
                self._safe_write({
                    "record": "HTTP_CONNECTION", "ts_utc": utc_iso(time.time()), "ts_source": "host_clock",
                    "sensor": "httpgate", "src_ip": src_ip,
                    "decision": "BLOCK", "event_type": "UNAUTHORIZED_CONNECTION",
                    "action": "SUPPRESSED_BLOCK_SUMMARY",
                    "details": [f"{count} BLOCKed/rejected connection(s) from {src_ip} were "
                                f"rate-limited out of the log and never individually recorded"]})
                self.stats["blocked_suppressed"] += count
        self._block_suppressed.clear()

    def _prune_block_log_entries(self) -> None:
        """D-008 round 2 nit 9: _last_block_log/_block_suppressed grow unboundedly for many
        distinct unauthorized source IPs (e.g. a wide scan). Lazy prune, gated by a size
        check so it's O(1) in the common case: once either dict passes a small threshold,
        drop entries whose last-logged timestamp is old enough that the source has clearly
        moved on, not mid-burst."""
        threshold = 500
        if len(self._last_block_log) <= threshold and len(self._block_suppressed) <= threshold:
            return
        cutoff = time.time() - _BLOCK_LOG_INTERVAL_S * 10
        stale = [ip for ip, ts in self._last_block_log.items() if ts < cutoff]
        for ip in stale:
            self._last_block_log.pop(ip, None)
            # D-008 round 3 architect review, should-fix 2: don't just drop a still-pending
            # suppressed count on the floor -- that's the exact loss flush_suppressed_blocks()
            # exists to prevent, just triggered by a prune instead of shutdown. Folding it into
            # stats (without a full evidence record, to keep this prune cheap under a wide
            # scan) at least keeps the numbers honest; flush_suppressed_blocks() still handles
            # anything left over for the common single-burst case.
            count = self._block_suppressed.pop(ip, 0)
            if count:
                self.stats["blocked_suppressed"] += count

    # --------------------------------------------------------------- per client
    async def handle_client(self, c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter):
        peer = c_writer.get_extra_info("peername") or ("?", 0)
        local = c_writer.get_extra_info("sockname") or ("?", 0)
        src_ip, src_port = peer[0], peer[1]
        if src_ip.startswith("::ffff:"):
            src_ip = src_ip[7:]
        ts = time.time()
        self._maybe_reload()
        self._prune_block_log_entries()

        # D-008 round 1 should-fix 6: bound concurrent connections. A connect flood from an
        # unlisted host (each one fsync'ing a BLOCKED record) could otherwise stall legitimate
        # allowed traffic and fill the log; reject cheaply, before any further work, once at cap.
        max_conn = int(self.gcfg.get("max_connections", 100))
        if len(self._client_writers) >= max_conn:
            self.stats["connections"] += 1
            self.stats["rejected_capacity"] += 1
            self._log_rate_limited({
                "record": "HTTP_CONNECTION", "ts_utc": utc_iso(ts), "ts_source": "host_clock",
                "sensor": "httpgate", "src_ip": src_ip, "src_port": src_port,
                "decision": "BLOCK", "event_type": "CAPACITY_LIMIT", "authorized": None,
                "rules": [], "action": "REJECTED_MAX_CONNECTIONS", "details": [
                    f"http_gate.max_connections ({max_conn}) reached"]}, src_ip)
            self.console(f"[REJECT] {src_ip}:{src_port} -- at max_connections ({max_conn})")
            try:
                c_writer.close()
            except Exception:
                pass
            return

        self.stats["connections"] += 1
        self._client_writers.add(c_writer)
        try:
            # D-008 round 3 architect review, should-fix 1: _is_authorized() (and anything
            # else here before the main try/finally below starts) can raise on a malformed
            # config value that load() currently accepts without checking (e.g. a source's
            # "allow" set to null instead of a list, making "write" in None a TypeError).
            # That used to happen with c_writer already added to _client_writers above but
            # with no enclosing try/finally yet to clean it up -- a permanent leak counting
            # against max_connections forever, one connection at a time. This small wrapper
            # guarantees that specific cleanup regardless; a load()-time type check for
            # "allow" etc. is tracked separately (A-036) rather than fixed here.
            authorized, src = self._is_authorized(src_ip)
        except Exception:
            self._client_writers.discard(c_writer)
            try:
                c_writer.close()
            except Exception:
                pass
            raise

        enforce = self.config["enforcement"]["mode"] == "block"
        blocked = (not authorized) and enforce
        up_host = self.gcfg.get("upstream_host")
        up_port = int(self.gcfg.get("upstream_port", 80))

        rec = {
            "record": "HTTP_CONNECTION", "ts_utc": utc_iso(ts), "ts_source": "host_clock",
            "sensor": "httpgate", "src_ip": src_ip, "src_port": src_port,
            "dst_ip": local[0], "dst_port": local[1],              # the gate's own listening socket
            "upstream_host": up_host, "upstream_port": up_port,    # D-008 round 1 nit 10: the actual
            "source_name": src.get("name") if src else None,       # relay target, which can change
            "authorized": authorized,                              # across a reload -- distinct from
            "decision": "ALLOW" if authorized else "BLOCK",        # dst_ip/dst_port above
            "event_type": "AUTHORIZED_CONNECTION" if authorized else "UNAUTHORIZED_CONNECTION",
            "rules": [] if authorized else ["SRC_NOT_ALLOWLISTED"],
            "details": [] if authorized else [
                f"{src_ip} is not authorized for 'write' in authorized_sources; http_gate "
                f"decides per source IP only, with no per-request categories"],
        }

        u_writer = None
        # relayed: True once the code is actually going to connect upstream/relay (set just
        # before the ALLOW/FORWARDED write below) -- used by _revoke_now_unauthorized() to
        # tell "still open and relaying" apart from "already blocked and gone" (should-fix 2).
        # revoked: set True by _revoke_now_unauthorized(); pipe() checks it each loop
        # iteration so in-flight bytes stop reaching the HMI immediately (should-fix 4).
        # u_writer: filled in once the upstream connect succeeds, so revocation can close it
        # too, not just the client side (should-fix 4).
        info = {"src_ip": src_ip, "src_port": src_port, "authorized": authorized,
                "relayed": False, "revoked": False, "u_writer": None}
        self._active[c_writer] = info
        try:
            if blocked:
                rec["action"] = "BLOCKED"
                self.stats["blocked"] += 1
                self.stats["alerts"] += 1
                wrote = self._log_rate_limited(rec, src_ip)
                if wrote:
                    self.console(f"[BLOCKED] {utc_iso(ts)} {src_ip}:{src_port} -> "
                                 f"HMI {local[0]}:{local[1]} (not allowlisted)")
                return

            rec["action"] = "FORWARDED" if authorized else "FORWARDED (enforcement off: would block)"
            if not authorized:
                self.stats["alerts"] += 1

            if not up_host:
                # D-008 round 1 should-fix 4: a reload that lands between a start-up CLI
                # override and its first write-back could otherwise leave this empty, which
                # used to mean open_connection(None, port) -- resolves to loopback and, with
                # the default 0.0.0.0 listen host, the gate would connect to itself in a loop.
                rec["decision"], rec["action"] = "BLOCK", "BLOCKED"
                rec["details"].append("http_gate.upstream_host is empty -- failing closed")
                self._safe_write(rec)
                self.console(f"[ERROR] no upstream_host configured; refusing {src_ip}:{src_port}")
                self.stats["blocked"] += 1
                return

            # Write the connection's decision record NOW, before attempting the upstream
            # connect or peeking any client bytes -- D-008 round 1 BLOCKER 2: the original
            # code only logged after a successful peek, so a client that reset the connection
            # (nmap -sT without -sV sends no payload and often RSTs quickly) or sent an
            # over-limit line with no newline could leave an ALLOWed connection with NO
            # evidence record at all, while stats["alerts"]/["forwarded"] below still counted
            # it -- a silent mismatch between the log and the session's own stats.
            #
            # info["relayed"] is set True here, before the write, not after it succeeds: a
            # write failure below fails the connection closed via the `return`, so nothing
            # is actually relayed either way, but should-fix 2's revoke logic only needs
            # "did we decide to relay" (vs. "already blocked"), and the connection is torn
            # down (not left in _active) by the finally block's cleanup regardless.
            info["relayed"] = True
            if self._safe_write(rec) is None:
                # D-008 round 2 BLOCKER: a log-write failure here must fail this connection
                # closed, not silently proceed to relay unlogged traffic. Cleanup happens in
                # the existing `finally` below (closes c_writer; u_writer is still None here).
                return

            try:
                u_reader, u_writer = await asyncio.wait_for(
                    asyncio.open_connection(up_host, up_port),
                    timeout=float(self.gcfg.get("connect_timeout_s", 3)))
            except (OSError, asyncio.TimeoutError) as e:
                self.stats["upstream_errors"] += 1
                self._safe_write({
                    "record": "UPSTREAM_ERROR", "ts_utc": utc_iso(time.time()), "ts_source": "host_clock",
                    "sensor": "httpgate", "src_ip": src_ip, "src_port": src_port,
                    "details": [f"cannot reach HMI {up_host}:{up_port}: {e!r}"]})
                self.console(f"[ERROR] cannot reach HMI {up_host}:{up_port}: {e!r}")
                return

            if info.get("revoked"):
                # D-008 round 3 architect review, nit 4: a reload can revoke this connection
                # while it was still waiting on open_connection() (up to connect_timeout_s).
                # _revoke_now_unauthorized() only closes a writer it already has a reference
                # to, and info["u_writer"] was still None at that moment -- so without this
                # check, the now-connected u_writer would never get closed by the revoke, and
                # the client's already-buffered first line would still reach the HMI below.
                try:
                    u_writer.close()
                except Exception:
                    pass
                return

            # D-008 round 2 nit 11: only count as "forwarded" once the upstream connect has
            # actually succeeded -- counting it right after the decision record write above
            # (before the connect was even attempted) double-counted a connection that then
            # hit UPSTREAM_ERROR in both stats["forwarded"] and stats["upstream_errors"].
            self.stats["forwarded"] += 1
            info["u_writer"] = u_writer
            tag = "ALLOW" if authorized else "ALLOW*"
            self.console(f"[{tag}] {utc_iso(ts)} {rec['source_name'] or src_ip} -> HMI "
                         f"{up_host}:{up_port}")

            # Best-effort peek at the request line, for a SEPARATE, OPTIONAL evidence record
            # -- it never gates the decision (already made and logged above, on source IP
            # alone) and its absence or failure never prevents the HTTP_CONNECTION record
            # above from existing. readline() does NOT raise LimitOverrunError on an
            # over-limit line with no separator (round 1 BLOCKER 2 finding): it catches that
            # internally and re-raises ValueError, after clearing the relevant part of its own
            # buffer -- so data loss on an oversized first line is expected here, not a bug,
            # and the `except` below must catch ValueError, not LimitOverrunError. A client
            # RST during the peek raises ConnectionError, also caught; either way nothing
            # beyond this best-effort peek is lost, since the main record is already written.
            first_line = b""
            try:
                first_line = await asyncio.wait_for(c_reader.readline(), timeout=_FIRST_LINE_TIMEOUT_S)
            except (asyncio.TimeoutError, ValueError, ConnectionError, OSError):
                pass
            preview = _preview(first_line)
            if preview is not None:
                self._safe_write({
                    "record": "HTTP_REQUEST_LINE", "ts_utc": utc_iso(time.time()), "ts_source": "host_clock",
                    "sensor": "httpgate", "src_ip": src_ip, "src_port": src_port,
                    "request_line": preview})

            if first_line:
                try:
                    u_writer.write(first_line)
                    await u_writer.drain()
                except (ConnectionError, OSError):
                    return

            idle_timeout = float(self.gcfg.get("idle_timeout_s", 60))

            async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
                # D-008 round 1 should-fix 3: half-close, not a full close, on EOF from one
                # direction -- a client that shuts down its write side after sending the
                # request (HTTP/1.0-style, or `nc -N`) used to have writer.close() tear down
                # the WHOLE upstream socket here, losing the HMI's still-pending reply. Both
                # directions are only fully closed afterwards, in the outer `finally` below.
                # Also bounds each direction with an idle timeout (should-fix 6): nothing
                # here has Modbus's one-MBAP-frame-at-a-time structure to bound a stall by.
                #
                # D-008 round 2 should-fix 4: check info["revoked"] each loop iteration (not
                # just "if not data") so a config reload that revokes this source stops
                # forwarding immediately, instead of letting bytes already buffered
                # client-side before the close propagates still reach the HMI. `info` is the
                # same dict object referenced from self._active[c_writer] and this closure --
                # no extra locking needed, asyncio's event loop is single-threaded.
                #
                # D-008 round 2 nit 7: return whether this direction exited via an idle
                # timeout (as opposed to clean EOF/error) -- the caller uses that to decide
                # whether to tear down the WHOLE connection (timeout = peer went silent) or
                # just half-close as before (clean EOF = peer deliberately done sending).
                timed_out = False
                try:
                    while True:
                        if info.get("revoked"):
                            break
                        try:
                            data = await asyncio.wait_for(reader.read(65536), timeout=idle_timeout)
                        except asyncio.TimeoutError:
                            # D-008 round 3 architect review, nit 5: closing both writers only
                            # AFTER gather() returns is a no-op -- by then BOTH pipe()s have
                            # already finished on their own (gather waits for both), so the
                            # sibling direction already sat out its own full idle_timeout
                            # instead of being woken early. The actual fix has to happen HERE,
                            # the moment a timeout is detected, not after the fact: closing
                            # u_writer/c_writer immediately tears down the shared transport on
                            # each end, which unblocks the SIBLING pipe()'s own blocked
                            # reader.read() right away (it shares a transport with whichever
                            # writer this direction just closed) instead of leaving it to wait
                            # out its own separate timer.
                            timed_out = True
                            for w in (u_writer, c_writer):
                                try:
                                    w.close()
                                except Exception:
                                    pass
                            break
                        if not data or info.get("revoked"):
                            break
                        writer.write(data)
                        await writer.drain()
                except (ConnectionError, OSError):
                    pass
                finally:
                    if not timed_out:
                        try:
                            if writer.can_write_eof():
                                writer.write_eof()
                        except Exception:
                            pass
                return timed_out

            await asyncio.gather(pipe(c_reader, u_writer), pipe(u_reader, c_writer),
                                  return_exceptions=True)
        except (ConnectionError, OSError) as e:
            self.console(f"[ERROR] {src_ip}:{src_port}: {type(e).__name__}: {e}")
        finally:
            self._client_writers.discard(c_writer)
            self._active.pop(c_writer, None)
            for w in (u_writer, c_writer):   # D-008 round 1 BLOCKER 2 last bullet: every early
                if w is not None:            # return above left u_writer unclosed; now guaranteed
                    try:
                        w.close()
                    except Exception:
                        pass

    async def serve(self, ready: asyncio.Event | None = None):
        host = self.gcfg.get("listen_host", "0.0.0.0")
        port = int(self.gcfg.get("listen_port", 80))
        server = await asyncio.start_server(self.handle_client, host, port)
        self.bound = server.sockets[0].getsockname()
        self.console(f"PLC Guardian HTTP gate listening on {host}:{self.bound[1]} -> "
                     f"HMI {self.gcfg.get('upstream_host')}:{self.gcfg.get('upstream_port', 80)} | "
                     f"mode={self.config['enforcement']['mode']} | log={self.evlog.path}")
        if ready:
            ready.set()

        async def _reload_poll():
            # D-008 round 2 should-fix 3: _maybe_reload() (and thus _revoke_now_unauthorized())
            # was previously only ever invoked from handle_client, at the top of each NEW
            # connection -- a config change that should revoke someone has no effect at all
            # if nobody else connects afterwards; that someone's keep-alive connection would
            # otherwise relay forever. Poll roughly once a second for the life of the server.
            while True:
                await asyncio.sleep(1.0)
                try:
                    self._maybe_reload()
                except Exception as e:
                    # D-008 round 3 architect review, should-fix 1: an uncaught exception here
                    # (e.g. from the same kind of malformed-config value that handle_client now
                    # guards against above) would otherwise kill this loop silently -- the
                    # should-fix-3 fix it's running for would then quietly stop working for the
                    # rest of the run, with nothing in the console to say so.
                    self.console(f"[ERROR] reload poll failed: {type(e).__name__}: {e}")

        poll_task = asyncio.ensure_future(_reload_poll())
        try:
            # Same shutdown pattern as GuardianProxy.serve() (see its comment): deliberately
            # not `async with server: await server.serve_forever()` -- on Python 3.12.1+,
            # Server.wait_closed() blocks until every client connection closes too, which can
            # hang shutdown indefinitely with the HMI (or a test client) still connected.
            await asyncio.Future()
        finally:
            poll_task.cancel()
            try:
                await poll_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                # Belt-and-suspenders alongside the try/except inside _reload_poll() itself:
                # make sure a stray exception here still lets server.close() and the
                # client-writer cleanup below run (round 3 architect review, should-fix 1).
                self.console(f"[ERROR] reload poll task raised on shutdown: {type(e).__name__}: {e}")
            server.close()
            for w in list(self._client_writers):
                try:
                    w.close()
                except Exception:
                    pass
