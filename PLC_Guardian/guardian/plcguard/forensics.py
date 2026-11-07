"""Experiment 4: reconstruct what happened in a (mixed) PCAP and write a Markdown report."""
from __future__ import annotations

import os
import platform
import socket
import time
from collections import Counter, defaultdict

from .baseline import sha256_file
from .evidence_log import utc_iso


def _who(ip, cfg):
    s = cfg.sources.get(ip)
    return f"{ip} ({s['name']})" if s else f"{ip} (NOT AUTHORIZED)"


_EV_CAT = {"NORMAL_READ": "read", "UNAUTHORIZED_READ": "read",
           "AUTHORIZED_CHANGE": "write", "UNAUTHORIZED_CHANGE": "write",
           "AUTHORIZED_CONFIG_CHANGE": "config", "UNAUTHORIZED_CONFIG_CHANGE": "config"}


def _cat(r):
    """Effective category. The record keeps the raw frame category (FC 90 = config); policy may
    reclassify a per-source fc90_read_subcodes poll as a read, which only shows in event_type."""
    return _EV_CAT.get(r["event_type"], r["category"])


def _row(*cells):
    return "| " + " | ".join(str(c).replace("|", "/") for c in cells) + " |"


def build_report(analyzer, cfg, pcap_path: str, log_path: str | None, log_head: str | None) -> str:
    reqs = [r for r in analyzer.records if r.get("record") == "REQUEST"]
    notable = [r for r in reqs if r["decision"] != "ALLOW" or r["event_type"] != "NORMAL_READ"]
    malformed = [r for r in analyzer.records if r.get("record") == "MALFORMED"]
    L = []
    L.append("# PLC Guardian forensic report\n")
    L.append("## 1. Evidence\n")
    L.append(_row("Item", "Value"))
    L.append(_row("---", "---"))
    L.append(_row("Capture file", os.path.basename(pcap_path)))
    L.append(_row("SHA-256", sha256_file(pcap_path)))
    L.append(_row("Size (bytes)", os.path.getsize(pcap_path)))
    L.append(_row("Frames", analyzer.frames))
    if analyzer.first_ts is not None:
        L.append(_row("First packet (UTC)", utc_iso(analyzer.first_ts)))
        L.append(_row("Last packet (UTC)", utc_iso(analyzer.last_ts)))
        L.append(_row("Duration (s)", round(analyzer.last_ts - analyzer.first_ts, 3)))
    L.append(_row("Timestamps", "from capture file (clock of the capturing host)"))
    L.append(_row("Guardian config SHA-256", cfg.sha256))
    L.append(_row("Authorized sources", ", ".join(f"{ip} ({s['name']}: {'/'.join(s['allow'])})"
                                                   for ip, s in cfg.sources.items())))
    if log_path:
        L.append(_row("Evidence log", f"{os.path.basename(log_path)} (chain head {log_head})"))
    L.append(_row("Report generated", f"{utc_iso(time.time())} on {socket.gethostname()} ({platform.system()})"))
    L.append("")

    # ---- summary
    dec = Counter(r["decision"] for r in reqs)
    ev = Counter(r["event_type"] for r in reqs)
    L.append("## 2. Summary\n")
    L.append(f"- Modbus requests: **{len(reqs)}** (ALLOW {dec.get('ALLOW', 0)}, ALERT {dec.get('ALERT', 0)}, "
             f"BLOCK-worthy {dec.get('BLOCK', 0)}); responses: {analyzer.stats.get('responses', 0)}; "
             f"exception responses: {analyzer.stats.get('exceptions', 0)}")
    L.append("- Event types: " + (", ".join(f"{k} x{v}" for k, v in ev.most_common()) or "none"))
    unauth_src = sorted({r["src_ip"] for r in reqs if not r["authorized"]})
    if unauth_src:
        L.append(f"- **Unauthorized activity detected from: {', '.join(unauth_src)}**")
    else:
        L.append("- No unauthorized Modbus activity detected.")
    if malformed:
        L.append(f"- Malformed / non-Modbus streams on port {cfg.plc_port}: {len(malformed)}")
    for k in ("retransmissions_skipped", "stream_gaps"):
        if analyzer.stats.get(k):
            L.append(f"- {k.replace('_', ' ')}: {analyzer.stats[k]}")
    L.append("")

    # ---- hosts
    L.append("## 3. Hosts observed\n")
    L.append(_row("IP", "MAC(s)", "Identity", "Modbus requests (by category)", "First packet (UTC)"))
    L.append(_row("---", "---", "---", "---", "---"))
    cats = defaultdict(Counter)
    for r in reqs:
        cats[r["src_ip"]][_cat(r)] += 1
    for ip, h in sorted(analyzer.hosts.items()):
        s = cfg.sources.get(ip)
        ident = s["name"] if s else ("PLC" if ip == cfg.plc_ip else ("UNKNOWN" if ip in cats else "-"))
        mac_note = ", ".join(sorted(h["macs"]))
        if s and s.get("mac") and h["macs"] and s["mac"] not in h["macs"]:
            mac_note += " **(expected " + s["mac"] + ")**"
        if len(h["macs"]) > 1:
            mac_note += " **(multiple MACs: possible spoofing / ARP poisoning)**"
        L.append(_row(ip, mac_note, ident, dict(cats.get(ip, {})) or "-", utc_iso(h["first_ts"])))
    L.append("")

    # ---- findings per unauthorized source
    L.append("## 4. Findings\n")
    if not unauth_src:
        L.append("No unauthorized sources.\n")
    for ip in unauth_src:
        rs = [r for r in reqs if r["src_ip"] == ip and not r["authorized"]]
        changes = [r for r in rs if _cat(r) in ("write", "config")]
        accepted = [r for r in changes if str(r.get("_outcome", "")).startswith("ACCEPTED")]
        L.append(f"### {_who(ip, cfg)}\n")
        L.append(f"- MAC: {', '.join(sorted(analyzer.hosts.get(ip, {}).get('macs', []))) or 'unknown'}")
        L.append(f"- Active: {rs[0]['ts_utc']} -> {rs[-1]['ts_utc']} (frames {rs[0].get('frame_no')}-{rs[-1].get('frame_no')})")
        L.append(f"- Requests: {len(rs)} ({dict(Counter(_cat(r) for r in rs))}); rules fired: "
                 f"{dict(Counter(x for r in rs for x in r['rules']))}")
        L.append(f"- Attempted changes: {len(changes)}; **accepted by the PLC: {len(accepted)}**"
                 + (" (no PLC response seen for some)" if any('_outcome' not in r for r in changes) else ""))
        for r in changes:
            L.append(f"  - frame {r.get('frame_no')} {r['ts_utc']}: {r['summary']} -> {r.get('_outcome', 'no response captured')}")
        L.append("")

    # ---- authorized sources whose request was still ALERT/BLOCK (e.g. protected point)
    auth_flagged = [r for r in reqs if r["authorized"] and r["decision"] in ("ALERT", "BLOCK")]
    if auth_flagged:
        L.append("### Authorized-source requests with decision ALERT/BLOCK\n")
        L.append("These came from an authorized source but the policy returned ALERT or BLOCK "
                 "(rules and details below). BLOCK is the policy verdict; in a pcap analysis nothing was actually dropped.\n")
        L.append(_row("Time (UTC)", "Frame", "Source", "Action", "Decision", "Rules", "Details", "PLC outcome"))
        L.append(_row("---", "---", "---", "---", "---", "---", "---", "---"))
        for r in auth_flagged:
            L.append(_row(r["ts_utc"], r.get("frame_no"), _who(r["src_ip"], cfg), r["summary"], r["decision"],
                          ", ".join(r["rules"]), "; ".join(r.get("details") or []) or "-",
                          r.get("_outcome", "-")))
        L.append("")

    # ---- timeline
    L.append("## 5. Timeline of notable events\n")
    L.append("Authorized reads (normal polling) are omitted; first contact by each host on the Modbus port is included.\n")
    L.append(_row("Time (UTC)", "Frame", "Source", "Action", "Event", "Verdict", "PLC outcome"))
    L.append(_row("---", "---", "---", "---", "---", "---", "---"))
    first_seen, rows, first_ids = set(), [], set()
    notable_ids = {id(r) for r in notable}
    for r in reqs:
        if r["src_ip"] not in first_seen:
            first_seen.add(r["src_ip"])
            first_ids.add(id(r))
        if id(r) in notable_ids or id(r) in first_ids:
            rows.append(r)
    for r in rows:
        verdict = r["decision"] + (" (" + ", ".join(r["rules"]) + ")" if r["rules"] else "")
        ev_t = r["event_type"] + (" [first contact]" if id(r) in first_ids else "")
        L.append(_row(r["ts_utc"], r.get("frame_no"), _who(r["src_ip"], cfg), r["summary"], ev_t, verdict,
                      r.get("_outcome", "-")))
    for m in malformed:
        L.append(_row(m["ts_utc"], m.get("frame_no"), m["src_ip"], "malformed Modbus stream", "PROTOCOL_ANOMALY",
                      "; ".join(m["details"]), "-"))
    L.append("")

    # ---- authorized changes
    auth_changes = [r for r in reqs if r["authorized"] and _cat(r) in ("write", "config")]
    L.append("## 6. Authorized changes\n")
    if not auth_changes:
        L.append("None.\n")
    for r in auth_changes:
        L.append(f"- frame {r.get('frame_no')} {r['ts_utc']} {_who(r['src_ip'], cfg)}: {r['summary']} "
                 f"-> {r.get('_outcome', 'no response captured')}"
                 + (f" [{', '.join(r['rules'])}]" if r["rules"] else ""))
    L.append("")
    L.append("## 7. Method and limitations\n")
    L.append("- Each TCP flow to/from the Modbus port was reassembled by sequence number; Ethernet padding was "
             "excluded using the IP total length; retransmissions were skipped.")
    L.append("- Authorization is decided from the source IP (and MAC, where configured) against `config.json`; "
             "an attacker on the same segment who spoofs both IP and MAC of an authorized host would not be "
             "caught by the allowlist rule alone (the MAC-mismatch and multiple-MAC checks catch the common case).")
    L.append("- PLC outcome is taken from the PLC's response with the same Modbus transaction ID on the same TCP "
             "connection. 'ACCEPTED_BY_PLC' means the PLC acknowledged the write; it does not prove the "
             "physical process changed.")
    L.append("- Timestamps come from the capture file and are only as accurate as the capturing host's clock.")
    return "\n".join(L) + "\n"
