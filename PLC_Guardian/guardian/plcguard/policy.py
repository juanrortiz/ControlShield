"""Authorization decision for one Modbus request.

This module ONLY decides. It never logs and never blocks; the caller (proxy or
passive monitor) takes the Verdict and hands it to the evidence log and, if
enforcement is on, to the blocker. That separation maps one-to-one onto the
experiments: detect (policy) -> log (evidence_log) -> block (proxy).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .config import Config
from .modbus import ModbusFrame

ALLOW, ALERT, BLOCK = "ALLOW", "ALERT", "BLOCK"
_RANK = {ALLOW: 0, ALERT: 1, BLOCK: 2}


@dataclass
class Verdict:
    decision: str                 # ALLOW / ALERT (allowed but flagged) / BLOCK
    authorized: bool              # is the *source* authorized for this action
    event_type: str
    rules: list = field(default_factory=list)
    source_name: Optional[str] = None
    details: list = field(default_factory=list)

    def escalate(self, decision: str, rule: str, detail: Optional[str] = None) -> None:
        if _RANK[decision] > _RANK[self.decision]:
            self.decision = decision
        self.rules.append(rule)
        if detail:
            self.details.append(detail)

    @property
    def is_notable(self) -> bool:
        """Anything other than a plain authorized read is worth an evidence record."""
        return self.decision != ALLOW or self.event_type != "NORMAL_READ"


def _event_type(category: str, authorized: bool) -> str:
    if authorized:
        return {"read": "NORMAL_READ", "write": "AUTHORIZED_CHANGE",
                "config": "AUTHORIZED_CONFIG_CHANGE"}.get(category, "PROTOCOL_ANOMALY")
    return {"read": "UNAUTHORIZED_READ", "write": "UNAUTHORIZED_CHANGE",
            "config": "UNAUTHORIZED_CONFIG_CHANGE"}.get(category, "UNAUTHORIZED_ACCESS")


class Policy:
    def __init__(self, config: Config, baseline: Optional[dict] = None):
        self.config = config
        self.baseline = baseline

    def evaluate(self, frame: ModbusFrame, src_ip: str, src_mac: Optional[str] = None) -> Verdict:
        cfg = self.config
        src = cfg.sources.get(src_ip)
        cat = frame.category
        enf = cfg["enforcement"]
        # FC 90 sub-codes observed as routine HMI polling can be declared read-only per source
        if frame.fc == 90 and src is not None and frame.subcode in src.get("fc90_read_subcodes", []):
            cat = "read"

        # 1. Who is talking? -------------------------------------------------
        if src is None:
            v = Verdict(ALLOW, False, _event_type(cat, False))
            if cat == "read" and cfg["unknown_sources"]["allow_reads"]:
                v.escalate(ALERT, "SRC_NOT_ALLOWLISTED", f"{src_ip} is not in authorized_sources")
            else:
                v.escalate(BLOCK, "SRC_NOT_ALLOWLISTED", f"{src_ip} is not in authorized_sources")
        else:
            v = Verdict(ALLOW, True, _event_type(cat, True), source_name=src.get("name"))
            mac = (src_mac or "").lower() or None
            if src.get("mac") and mac and mac != src["mac"]:
                v.authorized = False
                v.event_type = "SPOOFED_SOURCE"
                v.escalate(BLOCK, "MAC_MISMATCH",
                           f"{src_ip} seen with MAC {mac}, expected {src['mac']} (possible IP spoofing)")
            if cat in ("read", "write", "config") and cat not in src.get("allow", []):
                v.authorized = False
                v.event_type = _event_type(cat, False)
                v.escalate(BLOCK, "ACTION_NOT_PERMITTED_FOR_SOURCE",
                           f"{src.get('name')} is allowed {src.get('allow')}, attempted '{cat}'")

        # 2. Is the frame itself sane? --------------------------------------
        for a in frame.anomalies:
            v.escalate(BLOCK, "PROTOCOL_ANOMALY", a)
        if cat == "unknown":
            v.event_type = "PROTOCOL_ANOMALY" if v.authorized else "UNAUTHORIZED_ACCESS"

        units = cfg["plc"].get("unit_ids")
        if units and frame.unit not in units:
            v.escalate(BLOCK if enf["block_unexpected_unit_id"] else ALERT,
                       "UNEXPECTED_UNIT_ID", f"unit {frame.unit} not in {units}")

        # 3. Is the value safe for the process? -----------------------------
        if cat == "write":
            for table, addr, value in frame.write_targets():
                for p in cfg["protected_points"]:
                    if not p.get("enabled", True) or p.get("table", "holding") != table:
                        continue
                    if not (p["start"] <= addr <= p.get("end", p["start"])):
                        continue
                    if p.get("read_only"):
                        v.escalate(BLOCK, "WRITE_TO_READ_ONLY_POINT",
                                   f"{p.get('name')} ({table} {addr}) is read-only")
                    elif value is not None and not (p.get("min", value) <= value <= p.get("max", value)):
                        v.escalate(BLOCK if (not v.authorized or enf["block_out_of_range_from_authorized"]) else ALERT,
                                   "VALUE_OUT_OF_RANGE",
                                   f"{p.get('name')} ({table} {addr}) = {value}, "
                                   f"allowed {p.get('min')}..{p.get('max')}")

        # 4. Does it match the learned baseline? (alert only, never blocks) --
        if self.baseline and v.authorized:
            seen = self.baseline.get("sources", {}).get(src_ip, {}).get("signatures", [])
            sig = (f"90:sub{frame.subcode}" if frame.fc == 90
                   else f"{frame.fc}:{frame.address}:{frame.quantity}")
            if sig not in seen:
                v.escalate(ALERT, "BASELINE_DEVIATION", f"{sig} (fc:addr:qty) never seen from {src_ip} in baseline")
        return v
