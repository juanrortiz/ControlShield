"""Inline enforcement: an asyncio Modbus/TCP proxy that sits between clients and the PLC.

    HMI / engineering / attacker  --TCP 502-->  Guardian (this proxy)  --TCP 502-->  PLC

Every request is parsed and judged by the Policy *before* it is forwarded. Blocked
requests never reach the PLC; the client gets a Modbus exception (or the TCP
connection is reset, per config). Responses from the PLC are correlated by
transaction ID so the log records whether the PLC accepted each change.

The proxy only *prevents* an attack if the PLC cannot be reached any other way,
i.e. the PLC sits behind Guardian (second NIC / separate segment). See README.

Set enforcement.mode = "monitor" to forward everything but still detect + log
(demo Iteration 1), and "block" for Iteration 2. config.json is re-read on change,
so the mode and allowlist can be flipped live during the demo.
"""
from __future__ import annotations

import asyncio
import logging
import time

from .config import Config
from .events import request_record, response_record
from .evidence_log import EvidenceLog, utc_iso
from .modbus import MBAP_LEN, MAX_LENGTH_FIELD, build_exception, parse_frame
from .policy import BLOCK, Policy

log = logging.getLogger("guardian.proxy")


class GuardianProxy:
    def __init__(self, config: Config, evlog: EvidenceLog, baseline: dict | None = None,
                 console=print):
        self.config = config
        self.evlog = evlog
        self.policy = Policy(config, baseline)
        self.console = console
        self.stats = {"connections": 0, "requests": 0, "forwarded": 0, "blocked": 0, "alerts": 0}

    # ------------------------------------------------------------------ helpers
    @property
    def pcfg(self) -> dict:
        return self.config.get("proxy", {})

    def _maybe_reload(self) -> None:
        if self.config.reload_if_changed():
            self.evlog.write({"record": "CONFIG_RELOADED", "ts_utc": utc_iso(time.time()),
                              "ts_source": "host_clock", "sensor": "proxy",
                              "config_sha256": self.config.sha256,
                              "enforcement_mode": self.config["enforcement"]["mode"],
                              "authorized_sources": sorted(self.config.sources)})
            self.console(f"[config] reloaded; mode={self.config['enforcement']['mode']} "
                         f"allowlist={sorted(self.config.sources)}")

    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader):
        hdr = await reader.readexactly(MBAP_LEN)
        length = int.from_bytes(hdr[4:6], "big")
        if length < 2 or length > MAX_LENGTH_FIELD:
            return hdr, f"BAD_MBAP_LENGTH_{length}"
        body = await reader.readexactly(length - 1)
        return hdr + body, None

    # --------------------------------------------------------------- per client
    async def handle_client(self, c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter):
        peer = c_writer.get_extra_info("peername") or ("?", 0)
        local = c_writer.get_extra_info("sockname") or ("?", 0)
        src_ip, src_port = peer[0], peer[1]
        if src_ip.startswith("::ffff:"):
            src_ip = src_ip[7:]
        self.stats["connections"] += 1
        up_host = self.pcfg.get("upstream_host", self.config.plc_ip)
        up_port = int(self.pcfg.get("upstream_port", self.config.plc_port))
        u_reader = u_writer = None
        relay_task = None
        pending: dict[int, dict] = {}   # tid -> request record (for response correlation)

        async def relay_upstream():
            try:
                while True:
                    raw, err = await self._read_frame(u_reader)
                    if err:
                        break
                    resp = parse_frame(raw, is_request=False)
                    req_rec = pending.pop(resp.tid, None)
                    if req_rec is not None and (req_rec.get("category") != "read" or resp.category == "exception"):
                        self.evlog.write(response_record(resp, req_rec, ts=time.time(),
                                                         ts_source="host_clock", sensor="proxy"))
                    c_writer.write(raw)
                    await c_writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                pass
            finally:
                try:
                    c_writer.close()
                except Exception:
                    pass

        try:
            while True:
                try:
                    raw, err = await self._read_frame(c_reader)
                except asyncio.IncompleteReadError:
                    break
                ts = time.time()
                self._maybe_reload()
                if err:
                    self.evlog.write({"record": "MALFORMED", "ts_utc": utc_iso(ts), "ts_source": "host_clock",
                                      "sensor": "proxy", "src_ip": src_ip, "src_port": src_port,
                                      "event_type": "PROTOCOL_ANOMALY", "details": [err],
                                      "raw_hex": raw.hex(), "action": "CONNECTION_CLOSED"})
                    self.console(f"[ANOMALY] {src_ip}:{src_port} {err} -> connection closed")
                    break

                frame = parse_frame(raw, is_request=True)
                v = self.policy.evaluate(frame, src_ip)
                self.stats["requests"] += 1
                enforce = self.config["enforcement"]["mode"] == "block"
                blocked = v.decision == BLOCK and enforce
                if blocked:
                    action = "BLOCKED"
                elif v.decision == BLOCK:
                    action = "FORWARDED (enforcement off: would block)"
                else:
                    action = "FORWARDED"

                rec = None
                if v.is_notable or self.config["log"]["log_allowed_reads"]:
                    rec = self.evlog.write(request_record(
                        frame, v, ts=ts, ts_source="host_clock", sensor="proxy",
                        src_ip=src_ip, src_port=src_port, dst_ip=local[0], dst_port=local[1],
                        action=action))
                if v.decision != "ALLOW":
                    self.stats["alerts"] += 1
                    tag = "BLOCKED" if blocked else v.decision
                    self.console(f"[{tag}] {utc_iso(ts)} {src_ip} {frame.summary()} "
                                 f"-> {v.event_type} {v.rules}")
                elif frame.category in ("write", "config"):
                    self.console(f"[ALLOW] {utc_iso(ts)} {v.source_name or src_ip} {frame.summary()}")

                if blocked:
                    self.stats["blocked"] += 1
                    if self.config["enforcement"]["block_response"] == "reset":
                        break
                    c_writer.write(build_exception(frame, int(self.config["enforcement"]["exception_code"])))
                    await c_writer.drain()
                    continue

                # Forward to the PLC (connect lazily on first allowed request).
                if u_writer is None:
                    try:
                        u_reader, u_writer = await asyncio.wait_for(
                            asyncio.open_connection(up_host, up_port),
                            timeout=float(self.pcfg.get("connect_timeout_s", 3)))
                    except (OSError, asyncio.TimeoutError) as e:
                        self.evlog.write({"record": "UPSTREAM_ERROR", "ts_utc": utc_iso(time.time()),
                                          "ts_source": "host_clock", "sensor": "proxy",
                                          "details": [f"cannot reach PLC {up_host}:{up_port}: {e!r}"]})
                        self.console(f"[ERROR] cannot reach PLC {up_host}:{up_port}: {e!r}")
                        c_writer.write(build_exception(frame, 0x0B))  # gateway target failed
                        await c_writer.drain()
                        break
                    relay_task = asyncio.create_task(relay_upstream())
                if rec is not None:
                    pending[frame.tid] = rec
                elif frame.category != "read":
                    pending[frame.tid] = {"category": frame.category}
                u_writer.write(raw)
                await u_writer.drain()
                self.stats["forwarded"] += 1
        except (ConnectionError, OSError):
            pass
        finally:
            for w in (u_writer, c_writer):
                if w is not None:
                    try:
                        w.close()
                    except Exception:
                        pass
            if relay_task:
                relay_task.cancel()

    async def serve(self, ready: asyncio.Event | None = None):
        host = self.pcfg.get("listen_host", "0.0.0.0")
        port = int(self.pcfg.get("listen_port", 502))
        server = await asyncio.start_server(self.handle_client, host, port)
        self.bound = server.sockets[0].getsockname()
        self.console(f"PLC Guardian proxy listening on {host}:{self.bound[1]} -> "
                     f"PLC {self.pcfg.get('upstream_host', self.config.plc_ip)}:"
                     f"{self.pcfg.get('upstream_port', self.config.plc_port)} | "
                     f"mode={self.config['enforcement']['mode']} | log={self.evlog.path}")
        if ready:
            ready.set()
        async with server:
            await server.serve_forever()
