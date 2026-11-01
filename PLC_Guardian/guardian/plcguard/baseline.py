"""Experiment 1: learn what normal Modbus traffic looks like from a known-clean capture."""
from __future__ import annotations

import hashlib
import statistics
from collections import Counter, defaultdict

from .evidence_log import utc_iso


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_baseline(analyzer, pcap_path: str) -> dict:
    per = defaultdict(lambda: {"requests": 0, "categories": Counter(), "fcs": Counter(),
                               "signatures": set(), "write_points": {}, "ts": [], "macs": set(),
                               "units": set()})
    for r in analyzer.records:
        if r.get("record") != "REQUEST":
            continue
        s = per[r["src_ip"]]
        s["requests"] += 1
        s["categories"][r["category"]] += 1
        s["fcs"][str(r["fc"])] += 1
        s["signatures"].add(f"90:sub{r.get('subcode')}" if r["fc"] == 90
                            else f"{r['fc']}:{r.get('address')}:{r.get('quantity')}")
        s["ts"].append(r["ts_epoch"])
        s["units"].add(r["unit"])
        if r.get("src_mac"):
            s["macs"].add(r["src_mac"])
        if r["category"] == "write" and r.get("values") is not None and r.get("address") is not None:
            for i, v in enumerate(r["values"]):
                key = f"{r.get('table')}:{r['address'] + i}"
                lo, hi = s["write_points"].get(key, (v, v))
                s["write_points"][key] = (min(lo, v), max(hi, v))

    out = {"source_pcap": pcap_path.replace("\\", "/").split("/")[-1], "source_sha256": sha256_file(pcap_path),
           "capture_start_utc": utc_iso(analyzer.first_ts) if analyzer.first_ts else None,
           "capture_end_utc": utc_iso(analyzer.last_ts) if analyzer.last_ts else None,
           "sources": {}}
    for ip, s in sorted(per.items()):
        ts = sorted(s["ts"])
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        out["sources"][ip] = {
            "macs": sorted(s["macs"]),
            "requests": s["requests"],
            "categories": dict(s["categories"]),
            "function_codes": dict(s["fcs"]),
            "unit_ids": sorted(s["units"]),
            "signatures": sorted(s["signatures"]),
            "write_points_min_max": {k: list(v) for k, v in sorted(s["write_points"].items())},
            "median_interval_s": round(statistics.median(gaps), 4) if gaps else None,
            "requests_per_s": round(len(ts) / (ts[-1] - ts[0]), 3) if len(ts) > 1 and ts[-1] > ts[0] else None,
        }
    return out


def format_baseline(b: dict) -> str:
    lines = [f"Baseline from {b['source_pcap']} (sha256 {b['source_sha256'][:16]}...)",
             f"Capture window: {b['capture_start_utc']} -> {b['capture_end_utc']}", ""]
    if not b["sources"]:
        lines.append("No Modbus requests found in this capture.")
    for ip, s in b["sources"].items():
        lines.append(f"Source {ip}  MAC {', '.join(s['macs']) or '?'}  units {s['unit_ids']}")
        lines.append(f"  requests: {s['requests']}  by category: {s['categories']}  by FC: {s['function_codes']}")
        lines.append(f"  polling: median interval {s['median_interval_s']} s, {s['requests_per_s']} req/s")
        lines.append(f"  distinct request signatures (fc:addr:qty): {', '.join(s['signatures'])}")
        if s["write_points_min_max"]:
            lines.append(f"  written points (min..max): {s['write_points_min_max']}")
        lines.append("")
    return "\n".join(lines)
