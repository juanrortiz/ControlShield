"""Build the evidence records that every sensor (proxy, live sniffer, pcap) writes."""
from __future__ import annotations

from typing import Optional

from .evidence_log import utc_iso
from .modbus import ModbusFrame
from .policy import Verdict


def request_record(frame: ModbusFrame, v: Verdict, *, ts: float, ts_source: str, sensor: str,
                   src_ip: str, src_port: int, dst_ip: str, dst_port: int, action: str,
                   src_mac: Optional[str] = None, dst_mac: Optional[str] = None,
                   frame_no: Optional[int] = None) -> dict:
    rec = {
        "record": "REQUEST",
        "ts_utc": utc_iso(ts),
        "ts_epoch": round(ts, 6),
        "ts_source": ts_source,
        "sensor": sensor,
        "frame_no": frame_no,
        "src_ip": src_ip, "src_mac": src_mac, "src_port": src_port,
        "dst_ip": dst_ip, "dst_mac": dst_mac, "dst_port": dst_port,
        "source_name": v.source_name,
        "tid": frame.tid, "unit": frame.unit, "fc": frame.fc, "fc_name": frame.fc_name,
        "category": frame.category, "table": frame.table,
        "address": frame.address, "quantity": frame.quantity,
        "values": frame.values if frame.category == "write" else None,
        "subcode": frame.subcode,
        "summary": frame.summary(),
        "event_type": v.event_type,
        "decision": v.decision,
        "authorized": v.authorized,
        "rules": v.rules,
        "details": v.details,
        "action": action,
        "pdu_hex": (bytes([frame.fc]) + frame.data).hex(),
    }
    return {k: val for k, val in rec.items() if val is not None}


def response_record(resp: ModbusFrame, req_rec: dict, *, ts: float, ts_source: str, sensor: str,
                    frame_no: Optional[int] = None) -> dict:
    if resp.category == "exception":
        outcome = f"REJECTED_BY_PLC (exception {resp.exception_code}: {resp.exception_name})"
    elif req_rec.get("category") in ("write", "config"):
        outcome = "ACCEPTED_BY_PLC"
    else:
        outcome = "OK"
    rec = {
        "record": "RESPONSE",
        "ts_utc": utc_iso(ts),
        "ts_epoch": round(ts, 6),
        "ts_source": ts_source,
        "sensor": sensor,
        "frame_no": frame_no,
        "request_seq": req_rec.get("seq"),
        "src_ip": req_rec.get("dst_ip"), "dst_ip": req_rec.get("src_ip"),
        "src_port": req_rec.get("dst_port"), "dst_port": req_rec.get("src_port"),
        "tid": resp.tid, "fc": resp.fc, "summary": resp.summary(),
        "event_type": req_rec.get("event_type"),
        "outcome": outcome,
        "latency_ms": round((ts - req_rec.get("ts_epoch", ts)) * 1000, 3),
    }
    return {k: val for k, val in rec.items() if val is not None}
