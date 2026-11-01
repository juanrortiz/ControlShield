"""Passive analysis of Modbus/TCP packets (offline PCAP/PCAPNG or live sniffing).

Passive mode can detect and log but cannot block: the verdict is still computed
("would block") and recorded with action = OBSERVED.

Packet handling notes (traps found on the real capture):
  * Ethernet frames shorter than 60 bytes are padded; scapy exposes that padding as
    TCP payload. The payload length is therefore computed from the IP total length,
    not from len(tcp.payload). (modbus_capture_practice.pcapng frame 2 shows this.)
  * Modbus requests can be split across or packed into TCP segments, so each TCP flow
    is reassembled by sequence number; retransmitted segments are skipped.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Callable, Optional

from .config import Config
from .events import request_record, response_record
from .evidence_log import EvidenceLog
from .modbus import parse_frame, split_frames
from .policy import Policy


def tcp_payload(pkt) -> bytes:
    from scapy.layers.inet import IP, TCP
    ip, tcp = pkt[IP], pkt[TCP]
    n = ip.len - ip.ihl * 4 - tcp.dataofs * 4
    if n <= 0:
        return b""
    return bytes(tcp.payload)[:n]


class _Flow:
    __slots__ = ("next_seq", "buf", "dead")

    def __init__(self):
        self.next_seq = None
        self.buf = b""
        self.dead = False


class Analyzer:
    def __init__(self, config: Config, evlog: Optional[EvidenceLog], sensor: str,
                 baseline: Optional[dict] = None, ts_source: str = "pcap",
                 on_event: Optional[Callable[[dict], None]] = None):
        self.config = config
        self.policy = Policy(config, baseline)
        self.evlog = evlog
        self.sensor = sensor
        self.ts_source = ts_source
        self.on_event = on_event
        self.flows: dict = defaultdict(_Flow)
        self.pending: dict = {}           # (client_ip, client_port, tid) -> request record
        self.records: list = []           # every record written (for reports)
        self.stats = Counter()
        self.hosts: dict = {}             # ip -> {"macs": set, ...}
        self.first_ts = self.last_ts = None
        self.frames = 0

    def _emit(self, rec: dict) -> dict:
        if self.evlog is not None:
            rec = self.evlog.write(rec)
        self.records.append(rec)
        if self.on_event:
            self.on_event(rec)
        return rec

    def process(self, pkt, frame_no: Optional[int] = None) -> None:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        self.frames += 1
        ts = float(pkt.time)
        self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        if IP not in pkt:
            return
        ip = pkt[IP]
        smac = pkt[Ether].src.lower() if Ether in pkt else None
        dmac = pkt[Ether].dst.lower() if Ether in pkt else None
        h = self.hosts.setdefault(ip.src, {"macs": set(), "packets": 0, "first_ts": ts})
        h["packets"] += 1
        if smac:
            h["macs"].add(smac)
        if TCP not in pkt:
            return
        tcp = pkt[TCP]
        port = self.config.plc_port
        if tcp.dport != port and tcp.sport != port:
            return
        is_request = tcp.dport == port
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        flow = self.flows[key]
        if tcp.flags & 0x02:  # SYN: new stream
            flow.next_seq, flow.buf, flow.dead = (tcp.seq + 1) & 0xFFFFFFFF, b"", False
            if is_request:
                self.stats["tcp_connections"] += 1
            return
        data = tcp_payload(pkt)
        if not data or flow.dead:
            return
        if flow.next_seq is None:          # capture started mid-stream
            flow.next_seq = tcp.seq
        if tcp.seq != flow.next_seq:
            if ((tcp.seq - flow.next_seq) & 0xFFFFFFFF) > 0x7FFFFFFF:
                self.stats["retransmissions_skipped"] += 1
                return
            # gap (lost packet in capture): resync on this segment
            self.stats["stream_gaps"] += 1
            flow.buf = b""
        flow.next_seq = (tcp.seq + len(data)) & 0xFFFFFFFF
        frames, flow.buf, err = split_frames(flow.buf + data)
        for raw in frames:
            self._handle_frame(raw, is_request, ts, frame_no, ip.src, tcp.sport, ip.dst, tcp.dport, smac, dmac)
        if err:
            flow.dead = True
            self.stats["malformed_streams"] += 1
            self._emit({"record": "MALFORMED", "ts_utc": _iso(ts), "ts_source": self.ts_source,
                        "sensor": self.sensor, "frame_no": frame_no, "src_ip": ip.src, "src_port": tcp.sport,
                        "dst_ip": ip.dst, "dst_port": tcp.dport, "event_type": "PROTOCOL_ANOMALY",
                        "details": [err], "action": "OBSERVED"})

    def _handle_frame(self, raw, is_request, ts, frame_no, sip, sport, dip, dport, smac, dmac):
        frame = parse_frame(raw, is_request)
        if is_request:
            self.stats["requests"] += 1
            self.stats[f"req_{frame.category}"] += 1
            v = self.policy.evaluate(frame, sip, smac)
            self.stats[f"decision_{v.decision}"] += 1
            action = "OBSERVED (passive: would block)" if v.decision == "BLOCK" else "OBSERVED"
            rec = request_record(frame, v, ts=ts, ts_source=self.ts_source, sensor=self.sensor,
                                 src_ip=sip, src_port=sport, dst_ip=dip, dst_port=dport,
                                 src_mac=smac, dst_mac=dmac, frame_no=frame_no, action=action)
            if v.is_notable or self.config["log"]["log_allowed_reads"]:
                rec = self._emit(rec)
            else:
                self.records.append(rec)   # kept in memory for baseline/report, not logged
            self.pending[(sip, sport, frame.tid)] = rec
        else:
            self.stats["responses"] += 1
            if frame.category == "exception":
                self.stats["exceptions"] += 1
            req = self.pending.pop((dip, dport, frame.tid), None)
            if req is None:
                return
            resp = response_record(frame, req, ts=ts, ts_source=self.ts_source,
                                   sensor=self.sensor, frame_no=frame_no)
            # annotate the in-memory copy only (the logged line is already hashed)
            req["_outcome"] = resp["outcome"]
            req["_response_frame"] = frame_no
            req["_response_values"] = frame.values
            if "seq" in req or frame.category == "exception":
                self._emit(resp)


def _iso(ts):
    from .evidence_log import utc_iso
    return utc_iso(ts)


def analyze_pcap(path: str, config: Config, evlog: Optional[EvidenceLog], baseline=None,
                 on_event=None) -> Analyzer:
    import scapy.layers.l2, scapy.layers.inet  # noqa: F401  register link types BEFORE opening the file
    from scapy.utils import PcapReader
    a = Analyzer(config, evlog, sensor=f"pcap:{path.replace(chr(92), '/').split('/')[-1]}",
                 baseline=baseline, ts_source="pcap", on_event=on_event)
    with PcapReader(path) as rd:
        for i, pkt in enumerate(rd, 1):
            a.process(pkt, frame_no=i)
    return a


def sniff_live(iface: Optional[str], config: Config, evlog: EvidenceLog, baseline=None, on_event=None):
    from scapy.sendrecv import sniff
    a = Analyzer(config, evlog, sensor=f"live:{iface or 'default'}", baseline=baseline,
                 ts_source="host_clock (capture driver)", on_event=on_event)
    counter = {"n": 0}

    def cb(pkt):
        counter["n"] += 1
        a.process(pkt, frame_no=counter["n"])

    sniff(iface=iface, filter=f"tcp port {config.plc_port}", prn=cb, store=False)
    return a
