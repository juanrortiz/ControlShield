"""Load and hot-reload Guardian's JSON config (allowlist, PLC, protected registers, enforcement)."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Optional


def _norm_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return mac.strip().lower().replace("-", ":")


class Config:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self._mtime = None
        self.data: dict = {}
        self.sha256 = ""
        self.load()

    def load(self) -> None:
        with open(self.path, "rb") as fh:
            raw = fh.read()
        data = json.loads(raw.decode("utf-8"))
        for ip, src in data.get("authorized_sources", {}).items():
            src["mac"] = _norm_mac(src.get("mac"))
            src.setdefault("name", ip)
            src.setdefault("allow", ["read"])
        data.setdefault("plc", {}).setdefault("port", 502)
        data.setdefault("unknown_sources", {}).setdefault("allow_reads", False)
        data.setdefault("protected_points", [])
        enf = data.setdefault("enforcement", {})
        enf.setdefault("mode", "block")
        enf.setdefault("block_response", "exception")
        enf.setdefault("exception_code", 1)
        enf.setdefault("block_out_of_range_from_authorized", False)
        enf.setdefault("block_unexpected_unit_id", False)
        log = data.setdefault("log", {})
        log.setdefault("path", "logs/guardian_events.jsonl")
        log.setdefault("log_allowed_reads", False)
        # D-007 active response: off unless enabled=true AND lockout_coil is a real int --
        # plcguard/active_response.py enforces that guardrail again itself, this is just
        # giving every run a complete section to read even if config.json omits it.
        ar = data.setdefault("active_response", {})
        ar.setdefault("enabled", False)
        ar.setdefault("lockout_coil", None)
        ar.setdefault("trigger_decisions", ["BLOCK"])
        ar.setdefault("cooldown_seconds", 5)
        ar.setdefault("unit", 1)
        ar.setdefault("timeout_s", 2)
        # D-008 http_gate: connection-level inline gate for the HMI's web API
        # (partial mitigation for RAID R-004). upstream_host has no default --
        # cmd_httpgate refuses to start without one (config.json or --upstream).
        # log_path defaults to its OWN file, separate from log.path -- architect
        # review round 1 BLOCKER 1: two processes (e.g. this gate run alongside
        # `proxy`/`monitor`, as httpgate.py's docstring says to) appending to the
        # same evidence log split the hash chain, since each keeps its own seq/prev.
        hg = data.setdefault("http_gate", {})
        hg.setdefault("listen_host", "0.0.0.0")
        hg.setdefault("listen_port", 80)
        hg.setdefault("upstream_port", 80)
        hg.setdefault("connect_timeout_s", 3)
        hg.setdefault("log_path", "logs/httpgate_events.jsonl")
        hg.setdefault("max_connections", 100)
        hg.setdefault("idle_timeout_s", 60)
        # http_watch: passive HTTP-connection trigger for the D-007 lockout (see
        # plcguard/http_watch.py). Off by default -- enabling it does not change any existing
        # Modbus-side behaviour; it only adds a second, independent trigger source that
        # cmd_monitor wires into the SAME ActiveResponder instance (shared cooldown).
        hw = data.setdefault("http_watch", {})
        hw.setdefault("enabled", False)
        hw.setdefault("hmi_ip", "192.168.8.10")
        hw.setdefault("hmi_port", 80)
        self.data = data
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self._mtime = os.stat(self.path).st_mtime

    def reload_if_changed(self) -> bool:
        """Reload when the file on disk changed. Returns True if a reload happened."""
        try:
            m = os.stat(self.path).st_mtime
        except OSError:
            return False
        if m != self._mtime:
            try:
                self.load()
                return True
            except Exception:
                # Keep the last good config if the edited file is mid-save or invalid.
                # Broadened from (ValueError, OSError) (D-008 round 2 nit 10): a malformed
                # section of the wrong type (e.g. "http_gate": null, a non-numeric
                # max_connections) raises AttributeError/TypeError, not ValueError/OSError --
                # left uncaught, self._mtime never updates and the same crash is retried on
                # every single new connection until the file is fixed, instead of being
                # handled once (like this branch already does for ValueError/OSError).
                self._mtime = m
                return False
        return False

    # convenience accessors
    @property
    def plc_ip(self) -> str:
        return self.data["plc"].get("ip", "")

    @property
    def plc_port(self) -> int:
        return int(self.data["plc"]["port"])

    @property
    def sources(self) -> dict:
        return self.data.get("authorized_sources", {})

    def __getitem__(self, k):
        return self.data[k]

    def get(self, k, default=None):
        return self.data.get(k, default)
