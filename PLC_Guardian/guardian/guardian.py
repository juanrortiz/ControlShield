#!/usr/bin/env python3
"""PLC Guardian command line.

  python guardian.py proxy                      inline Modbus proxy: detect + log + block   (exp 2, 3, demo)
  python guardian.py monitor --iface "Ethernet" passive live sniffer: detect + log          (exp 1-3 on a mirror port)
  python guardian.py analyze  capture.pcapng    passive analysis of a capture -> evidence log
  python guardian.py baseline capture.pcapng    learn normal traffic -> baseline.json         (exp 1)
  python guardian.py forensics mixed.pcapng     timeline + findings report                    (exp 4)
  python guardian.py verify logs/guardian_events.jsonl   check the log hash chain
  python guardian.py export logs/guardian_events.jsonl out.csv

Common options: --config config.json  --baseline baseline.json  --log <path>
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from plcguard.config import Config                       # noqa: E402
from plcguard.evidence_log import EvidenceLog, export_csv, verify, utc_iso  # noqa: E402


def _load_baseline(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _console_event(rec: dict) -> None:
    if rec.get("record") == "REQUEST":
        tag = rec["decision"]
        who = rec.get("source_name") or rec["src_ip"]
        print(f"[{tag:5}] {rec['ts_utc']} frame {rec.get('frame_no', '-')}: {who} {rec['summary']} "
              f"-> {rec['event_type']} {rec['rules'] or ''}")
    elif rec.get("record") == "RESPONSE":
        print(f"        {rec['ts_utc']} frame {rec.get('frame_no', '-')}: PLC response -> {rec['outcome']}")
    elif rec.get("record") == "MALFORMED":
        print(f"[ANOM ] {rec['ts_utc']} frame {rec.get('frame_no', '-')}: {rec['src_ip']} {rec['details']}")


def _open_log(path, cfg, sensor, extra=None):
    ev = EvidenceLog(path)
    ev.write_session_start(sensor, cfg.sha256, extra)
    return ev


def _ignore_stop_signals():
    """Stop reacting to SIGTERM/SIGBREAK/SIGINT. Used once shutdown is under way so a second
    signal (including a second Ctrl+C) can't interrupt evidence_log.write() mid-fsync and
    corrupt the hash chain. Callers must only invoke this AFTER the first SIGINT of a run has
    already been through asyncio.run()'s own KeyboardInterrupt handling -- this function does
    not distinguish "first" from "second", so calling it too early would suppress that first
    Ctrl+C's normal behaviour too."""
    for name in ("SIGTERM", "SIGBREAK", "SIGINT"):  # SIGBREAK exists on Windows only (Ctrl+Break)
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), signal.SIG_IGN)


def cmd_proxy(a, cfg):
    from plcguard.proxy import GuardianProxy
    if a.listen:
        host, _, port = a.listen.rpartition(":")
        cfg.data["proxy"]["listen_host"], cfg.data["proxy"]["listen_port"] = host or "0.0.0.0", int(port)
    if a.upstream:
        host, _, port = a.upstream.rpartition(":")
        cfg.data["proxy"]["upstream_host"], cfg.data["proxy"]["upstream_port"] = host, int(port or 502)
    if a.mode:
        cfg.data["enforcement"]["mode"] = a.mode
    ev = _open_log(a.log or cfg["log"]["path"], cfg, "proxy",
                   {"enforcement_mode": cfg["enforcement"]["mode"], "proxy": cfg["proxy"]})
    px = GuardianProxy(cfg, ev, _load_baseline(a.baseline))

    async def _run():
        # serve() runs as a Task (not awaited directly by asyncio.run) so the signal
        # handler below has something it can cancel from outside the coroutine.
        task = asyncio.ensure_future(px.serve())
        loop = asyncio.get_running_loop()          # the loop asyncio.run() is driving right now

        def _stop(signum, frame):
            # Disarm first, before touching the loop: if this signal lands in the narrow
            # window after asyncio.run()'s loop has started closing but before cmd_proxy's
            # outer `finally` runs, loop.call_soon_threadsafe() below raises
            # RuntimeError("Event loop is closed"). If that happened before we disarmed,
            # the exception would escape the handler with the handler still installed and
            # SESSION_END never written. Disarming first means a second signal is a no-op
            # either way.
            _ignore_stop_signals()                 # a second signal must not re-enter here
            try:
                # Never let this raise past us: a raised exception can land inside
                # evidence_log.write() between the fsync and the self.seq/self.prev update
                # and corrupt the hash chain. call_soon_threadsafe() just schedules the
                # cancellation on the loop (safe to call from a signal handler, even though
                # it fires on the same thread as the loop) and lets serve()'s own await
                # raise CancelledError at a clean point.
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass                                # loop already closed/closing; cmd_proxy's finally still runs
        for name in ("SIGTERM", "SIGBREAK"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), _stop)
        try:
            await task
        except asyncio.CancelledError:
            pass

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:                      # first Ctrl+C: asyncio.run()'s own Runner already
        pass                                       # cancelled the main task before raising this; just unwind
    finally:
        # First statement of the outer finally, before anything else: disarm SIGTERM/SIGBREAK
        # *and now SIGINT* so a second Ctrl+C (or one landing mid-write right here) can't
        # interrupt evidence_log.write() and corrupt the hash chain. This only ever runs after
        # the FIRST Ctrl+C has already gone through the normal KeyboardInterrupt path above (or
        # after a SIGTERM/SIGBREAK shutdown), so it never suppresses that first one.
        _ignore_stop_signals()
        ev.write({"record": "SESSION_END", "ts_utc": utc_iso(time.time()), "ts_source": "host_clock",
                  "sensor": "proxy", "stats": px.stats})
        ev.close()
        print(f"\nStopped. {px.stats}. Log: {ev.path}")


def cmd_monitor(a, cfg):
    from plcguard.analyzer import sniff_live
    ev = _open_log(a.log or cfg["log"]["path"], cfg, f"live:{a.iface}")
    print(f"Sniffing tcp port {cfg.plc_port} on {a.iface or 'default interface'} (passive: detect + log, no blocking). Ctrl+C to stop.")
    an = None
    try:
        an = sniff_live(a.iface, cfg, ev, _load_baseline(a.baseline), on_event=_console_event)
    except KeyboardInterrupt:
        pass
    finally:
        ev.write({"record": "SESSION_END", "ts_utc": utc_iso(time.time()), "ts_source": "host_clock",
                  "sensor": f"live:{a.iface}", "stats": dict(an.stats) if an else {}})
        ev.close()


def cmd_analyze(a, cfg):
    from plcguard.analyzer import analyze_pcap
    from plcguard.baseline import sha256_file
    log_path = a.log or os.path.join("logs", os.path.splitext(os.path.basename(a.pcap))[0] + "_events.jsonl")
    ev = _open_log(log_path, cfg, f"pcap:{os.path.basename(a.pcap)}",
                   {"evidence_file": os.path.basename(a.pcap), "evidence_sha256": sha256_file(a.pcap)})
    an = analyze_pcap(a.pcap, cfg, ev, _load_baseline(a.baseline), on_event=None if a.quiet else _console_event)
    ev.write({"record": "SESSION_END", "ts_utc": utc_iso(time.time()), "ts_source": "host_clock",
              "sensor": f"pcap:{os.path.basename(a.pcap)}", "stats": dict(an.stats), "frames": an.frames})
    ev.close()
    print(f"\n{an.frames} frames, stats {dict(an.stats)}\nEvidence log: {log_path}")


def cmd_baseline(a, cfg):
    from plcguard.analyzer import analyze_pcap
    from plcguard.baseline import build_baseline, format_baseline
    an = analyze_pcap(a.pcap, cfg, None)
    b = build_baseline(an, a.pcap)
    out = a.out or "baseline.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(b, fh, indent=2)
    print(format_baseline(b))
    print(f"Saved {out}. Use it with --baseline {out} to alert on deviations.")


def cmd_forensics(a, cfg):
    from plcguard.analyzer import analyze_pcap
    from plcguard.baseline import sha256_file
    from plcguard.forensics import build_report
    out_dir = a.out or os.path.join("reports", os.path.splitext(os.path.basename(a.pcap))[0])
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "events.jsonl")
    if os.path.exists(log_path):
        sys.exit(f"{log_path} already exists; choose another --out so earlier results are preserved.")
    ev = _open_log(log_path, cfg, f"pcap:{os.path.basename(a.pcap)}",
                   {"evidence_file": os.path.basename(a.pcap), "evidence_sha256": sha256_file(a.pcap)})
    an = analyze_pcap(a.pcap, cfg, ev, _load_baseline(a.baseline))
    ev.write({"record": "SESSION_END", "ts_utc": utc_iso(time.time()), "ts_source": "host_clock",
              "sensor": f"pcap:{os.path.basename(a.pcap)}", "stats": dict(an.stats), "frames": an.frames})
    ev.close()
    report = build_report(an, cfg, a.pcap, log_path, ev.prev[:16] + "...")
    rp = os.path.join(out_dir, "report.md")
    with open(rp, "w", encoding="utf-8") as fh:
        fh.write(report)
    export_csv(log_path, os.path.join(out_dir, "events.csv"))
    print(report)
    print(f"Wrote {rp}, {log_path}, {os.path.join(out_dir, 'events.csv')}")


def main(argv=None):
    p = argparse.ArgumentParser(description="PLC Guardian: Modbus/TCP monitoring, forensics and blocking")
    p.add_argument("--config", default=os.path.join(HERE, "config.json"))
    p.add_argument("--baseline", help="baseline.json from the 'baseline' command (adds deviation alerts)")
    p.add_argument("--log", help="evidence log path (overrides config)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("proxy", help="inline Modbus proxy (detect, log, block)")
    s.add_argument("--listen", help="host:port to listen on (default from config)")
    s.add_argument("--upstream", help="PLC host:port (default from config)")
    s.add_argument("--mode", choices=["monitor", "block"], help="override enforcement.mode")
    s = sub.add_parser("monitor", help="passive live sniffer (needs Npcap on Windows / root on Linux)")
    s.add_argument("--iface", help='capture interface, e.g. "Ethernet" (Windows) or eth0')
    s = sub.add_parser("analyze", help="analyze a pcap/pcapng into an evidence log")
    s.add_argument("pcap")
    s.add_argument("-q", "--quiet", action="store_true")
    s = sub.add_parser("baseline", help="learn normal traffic from a clean capture")
    s.add_argument("pcap")
    s.add_argument("-o", "--out")
    s = sub.add_parser("forensics", help="forensic timeline + findings report from a capture")
    s.add_argument("pcap")
    s.add_argument("-o", "--out", help="output directory (default reports/<pcap name>)")
    s = sub.add_parser("verify", help="verify an evidence log's hash chain")
    s.add_argument("logfile")
    s = sub.add_parser("export", help="export an evidence log to CSV")
    s.add_argument("logfile")
    s.add_argument("csv")
    a = p.parse_args(argv)

    if a.cmd == "verify":
        ok, n, bad, msg = verify(a.logfile)
        print(("PASS " if ok else "FAIL ") + msg)
        sys.exit(0 if ok else 1)
    if a.cmd == "export":
        print(f"Exported {export_csv(a.logfile, a.csv)} records to {a.csv}")
        return

    cfg = Config(a.config)
    {"proxy": cmd_proxy, "monitor": cmd_monitor, "analyze": cmd_analyze, "baseline": cmd_baseline,
     "forensics": cmd_forensics}[a.cmd](a, cfg)


if __name__ == "__main__":
    main()
