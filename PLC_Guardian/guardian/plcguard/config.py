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
            except (ValueError, OSError):
                # Keep the last good config if the edited file is mid-save or invalid.
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
