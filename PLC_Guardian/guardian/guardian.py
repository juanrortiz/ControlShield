#!/usr/bin/env python3
"""PLC Guardian command line.

  python guardian.py proxy                      inline Modbus proxy: detect + log + block   (exp 2, 3, demo)
  python guardian.py httpgate                    inline gate for the HMI's web API (IP allowlist only, no HTTP parsing; D-008)
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
    corrupt the hash chain. Callers must only invoke this AFTER the first stop signal of a run
    has already started the shutdown it is meant to trigger (e.g. from inside the handler that
    signal itself fires, as cmd_proxy's _stop does) -- this function does not distinguish
    "first" from "second", so calling it too early would suppress that first signal's normal
    behaviour too."""
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
        # SIGINT is registered here too (not left to asyncio.Runner's own default handler) so the
        # FIRST Ctrl+C also disarms everything immediately via _ignore_stop_signals() above, same
        # as SIGTERM/SIGBREAK. Without this, a second Ctrl+C arriving while the Runner is still
        # unwinding the cancelled task (and a handle_client task is mid evidence_log.write()) could
        # raise KeyboardInterrupt at an arbitrary point and corrupt the hash chain -- the outer
        # `finally`'s _ignore_stop_signals() call below is too late to protect that window.
        for name in ("SIGTERM", "SIGBREAK", "SIGINT"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), _stop)
        try:
            await task
        except asyncio.CancelledError:
            pass

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        # Normally unreachable now: SIGINT is handled by _stop (registered above) before
        # asyncio.Runner's own SIGINT handler ever gets a chance to fire, so the signal no
        # longer surfaces as a raised KeyboardInterrupt. This remains only as a fallback for
        # the brief window after asyncio.run() starts but before the loop above installs
        # _stop, where a Ctrl+C would still go through the Runner's default handling.
        pass
    finally:
        # First statement of the outer finally, before anything else: disarm SIGTERM/SIGBREAK/SIGINT
        # so a second signal (or one landing mid-write right here) can't interrupt
        # evidence_log.write() and corrupt the hash chain. By the time execution reaches here, the
        # first signal of whichever kind triggered shutdown has already been through _stop (or,
        # for the narrow pre-registration SIGINT window above, through the KeyboardInterrupt path),
        # so this never suppresses that first one.
        _ignore_stop_signals()
        ev.write({"record": "SESSION_END", "ts_utc": utc_iso(time.time()), "ts_source": "host_clock",
                  "sensor": "proxy", "stats": px.stats})
        ev.close()
        print(f"\nStopped. {px.stats}. Log: {ev.path}")


def cmd_httpgate(a, cfg):
    from plcguard.httpgate import HttpGate

    # D-008 architect review round 1, SHOULD-FIX 4: a hot config reload (_apply_overrides,
    # called from HttpGate._maybe_reload) replaces cfg.data wholesale, which would silently
    # drop these CLI overrides the next time config.json changes on disk. Building the
    # override dict once up front and handing it to HttpGate, instead of mutating cfg.data
    # here and never touching it again, lets _maybe_reload re-apply the same overrides
    # after every reload, not just before the first one.
    overrides: dict = {}
    if a.listen:
        host, _, port = a.listen.rpartition(":")
        overrides["listen_host"], overrides["listen_port"] = host or "0.0.0.0", int(port)
    if a.upstream:
        host, _, port = a.upstream.rpartition(":")
        overrides["upstream_host"], overrides["upstream_port"] = host, int(port or 80)
    if a.mode:
        cfg.data["enforcement"]["mode"] = a.mode   # enforcement.mode is shared with cmd_proxy;
        overrides["_enforcement_mode"] = a.mode     # re-applied on reload the same way as the rest

    def _apply_overrides(cfg_obj):
        cfg_obj.data["http_gate"].update({k: v for k, v in overrides.items() if not k.startswith("_")})
        if "_enforcement_mode" in overrides:
            cfg_obj.data["enforcement"]["mode"] = overrides["_enforcement_mode"]

    _apply_overrides(cfg)
    if not cfg.data["http_gate"].get("upstream_host"):
        sys.exit("http_gate.upstream_host is not set (config.json or --upstream HOST:PORT) -- nothing to forward to")
    # D-008 round 1 BLOCKER 1: httpgate gets its OWN default log file (http_gate.log_path),
    # not log.path -- that default is shared with cmd_proxy/cmd_monitor, and two processes
    # appending to one evidence log splits the hash chain. --log still overrides explicitly
    # if the caller really wants a specific file (EvidenceLog's new exclusive-lock check,
    # also from that review, refuses outright if something else already has it open).
    ev = _open_log(a.log or cfg["http_gate"]["log_path"], cfg, "httpgate",
                   {"enforcement_mode": cfg["enforcement"]["mode"], "http_gate": cfg["http_gate"]})
    gw = HttpGate(cfg, ev, on_reload=_apply_overrides)

    async def _run():
        # Same cancellable-Task + signal-handler pattern as cmd_proxy's _run (see its
        # comments for why): serve() runs as a Task so the handler below can cancel it
        # from outside the coroutine, and a second stop signal is disarmed immediately
        # so it can't land mid evidence_log.write() and corrupt the hash chain.
        task = asyncio.ensure_future(gw.serve())
        loop = asyncio.get_running_loop()

        def _stop(signum, frame):
            _ignore_stop_signals()
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass
        for name in ("SIGTERM", "SIGBREAK", "SIGINT"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), _stop)
        try:
            await task
        except asyncio.CancelledError:
            pass

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    finally:
        _ignore_stop_signals()
        # D-008 round 2 should-fix 5: flush any still-pending suppressed-BLOCK counts
        # (sources rate-limited out of the log that never connected again after the
        # interval) into the log and into gw.stats, BEFORE writing SESSION_END -- so the
        # totals in that record and the printed stats below are complete.
        gw.flush_suppressed_blocks()
        ev.write({"record": "SESSION_END", "ts_utc": utc_iso(time.time()), "ts_source": "host_clock",
                  "sensor": "httpgate", "stats": gw.stats})
        ev.close()
        print(f"\nStopped. {gw.stats}. Log: {ev.path}")


def _console_active_response(rec: dict) -> None:
    print(f"[ARESP] {rec['ts_utc']} coil {rec.get('lockout_coil')} on {rec.get('plc_ip')}:{rec.get('plc_port')} "
          f"-> {rec['outcome']} (trigger seq {rec.get('trigger_seq')}, {rec.get('trigger_decision')} "
          f"from {rec.get('trigger_source_name') or rec.get('trigger_src_ip')})")


def cmd_monitor(a, cfg):
    import threading
    from plcguard.active_response import ActiveResponder
    from plcguard.analyzer import sniff_live
    ev = _open_log(a.log or cfg["log"]["path"], cfg, f"live:{a.iface}")
    an = None
    hw_thread = None
    responder = None
    hw_stop = threading.Event()
    hw_cfg = cfg.get("http_watch", {}) or {}
    hw_enabled = bool(hw_cfg.get("enabled", False))
    hw_hmi_ip = hw_cfg.get("hmi_ip")
    if hw_enabled and not hw_hmi_ip:
        # A null/empty hmi_ip would otherwise put None into the trigger key Guardian checks
        # against (D-009 architect review round 2, nit 2) -- silently matching any REQUEST
        # record with no dst_ip rather than failing loudly. Never guessed or defaulted: refuse
        # to enable with an unusable address, same posture as active_response's own "never
        # guessed or defaulted" config validation.
        print("http_watch.enabled is true but http_watch.hmi_ip is empty/null -- http_watch "
              "stays OFF (never guessed or defaulted).")
        hw_enabled = False
    try:
        # extra_triggers (D-009): when http_watch is enabled, a BLOCK verdict FROM http_watch
        # SPECIFICALLY, addressed to the HMI's web port SPECIFICALLY, is also a legitimate
        # trigger -- see active_response.py's __init__ docstring for why this is keyed on
        # (sensor, dst_ip, dst_port), not a flat set of trusted destination IPs (that would
        # have let a Modbus-sourced BLOCK record addressed to the HMI's IP also fire the real
        # PLC lockout write, which is NOT what this feature is for). When disabled (the
        # default), pass nothing and the guard is exactly dst_ip == plc_ip, unchanged from
        # before this parameter existed.
        extra_triggers = {("http_watch", hw_hmi_ip, int(hw_cfg.get("hmi_port", 80)))} if hw_enabled else None
        # ActiveResponder's own construction can raise (I-008 item 4: invalid active_response
        # config, e.g. cooldown_seconds=0 or a weaker-than-BLOCK trigger_decisions entry). That
        # must never crash monitor mode before SESSION_END is written (I-008 item 6) -- fall
        # back to a no-op responder and keep going, with a clear log line either way.
        try:
            responder = ActiveResponder(cfg, ev, extra_triggers=extra_triggers)
        except ValueError as e:
            print(f"active_response config is invalid -- active response stays OFF: {e}")
            responder = ActiveResponder.inactive(cfg, ev, extra_triggers=extra_triggers)

        if responder.active:
            print(f"Active response ENABLED (D-007): a {sorted(responder.trigger_decisions)} verdict will "
                  f"trigger Guardian's own FC5 write to coil {responder.lockout_coil} on "
                  f"{cfg.plc_ip}:{cfg.plc_port} (cooldown {responder.cooldown_seconds}s).")
        elif responder.enabled:
            print("active_response.enabled is true in config but lockout_coil/plc.ip is not "
                  "valid -- active response stays OFF (never guessed or defaulted).")

        def _on_event(rec):
            _console_event(rec)
            if rec.get("record") == "REQUEST":
                ar_rec = responder.maybe_respond(rec)
                if ar_rec:
                    _console_active_response(ar_rec)

        if hw_enabled:
            # Same on_event callback as the Modbus sniffer, feeding the SAME ActiveResponder
            # instance (shared cooldown state) -- see http_watch.py's module docstring for why
            # this is passive-detect-only, never inline blocking. Runs on a background thread
            # since sniff() blocks; degrade gracefully (D-009, mirrors I-008 item 6) if it
            # can't even start (e.g. Npcap/permissions) -- monitor mode must still run its
            # existing Modbus sniffing and write SESSION_END cleanly.
            from plcguard.http_watch import sniff_http_watch

            def _hw_run():
                try:
                    sniff_http_watch(a.iface, cfg, ev, on_event=_on_event, stop_event=hw_stop)
                except Exception as e:                      # noqa: BLE001 -- never crash the run
                    print(f"http_watch sniffer failed to start/stopped unexpectedly: "
                          f"{type(e).__name__}: {e}")

            hw_thread = threading.Thread(target=_hw_run, name="http_watch", daemon=True)
            try:
                hw_thread.start()
                print(f"http_watch ENABLED (D-009): watching tcp port {hw_cfg.get('hmi_port')} on "
                      f"{hw_cfg.get('hmi_ip')} for connections from sources not in authorized_sources.")
            except Exception as e:                           # noqa: BLE001
                print(f"http_watch thread failed to start -- continuing without it: "
                      f"{type(e).__name__}: {e}")
                hw_thread = None

        print(f"Sniffing tcp port {cfg.plc_port} on {a.iface or 'default interface'} (passive: detect + log, no blocking). Ctrl+C to stop.")
        an = sniff_live(a.iface, cfg, ev, _load_baseline(a.baseline), on_event=_on_event)
    except KeyboardInterrupt:
        pass
    finally:
        # First statement of the outer finally, before anything else: disarm SIGTERM/SIGBREAK/
        # SIGINT (same reasoning/pattern as cmd_proxy's finally -- A-016/A-025) so a second
        # Ctrl+C landing during the ~join() window below can't escape it and skip SESSION_END/
        # ev.close() entirely (D-009 architect review round 2, should-fix 1).
        _ignore_stop_signals()
        # Disarm the responder BEFORE joining the http_watch thread (D-009 architect review
        # round 2, BLOCKER 2 item 2): scapy's sniff(stop_filter=...) only checks the stop
        # condition between received packets/timeout slices (see http_watch.py's module
        # docstring), so a packet can still be mid-callback when the join below times out.
        # responder.active = False makes maybe_respond() a no-op immediately regardless of
        # which thread calls it, so even a packet that slips in during this exact window can't
        # fire a real FC5 write after evidence logging has started shutting down.
        if responder is not None:
            responder.active = False
        hw_stop.set()          # ask http_watch's sniff() loop to return (scapy polls stop_filter)
        hw_still_alive = False
        if hw_thread is not None:
            hw_thread.join(timeout=3)   # bounded: shutdown must never hang on this thread
            hw_still_alive = hw_thread.is_alive()
            if hw_still_alive:
                # Don't silently proceed as if the thread is gone (D-009 architect review
                # round 2, BLOCKER 2 item 4) -- it is a daemon thread so it can't block process
                # exit, but SESSION_END must say so for the forensic record.
                print("http_watch thread did not stop within the 3s shutdown timeout; "
                      "continuing shutdown (it is a daemon thread and will not block exit, "
                      "but any event it logs after this point races evidence_log.close()).")
        ev.write({"record": "SESSION_END", "ts_utc": utc_iso(time.time()), "ts_source": "host_clock",
                  "sensor": f"live:{a.iface}", "stats": dict(an.stats) if an else {},
                  "http_watch_thread_stuck_at_shutdown": hw_still_alive})
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
    s = sub.add_parser("httpgate", help="inline TCP-level gate in front of the HMI's web API "
                       "(connection-level IP allowlist only, no HTTP parsing; D-008, partial mitigation for R-004)")
    s.add_argument("--listen", help="host:port to listen on (default from config http_gate.listen_host/listen_port)")
    s.add_argument("--upstream", help="HMI host:port (default from config http_gate.upstream_host/upstream_port)")
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
    {"proxy": cmd_proxy, "httpgate": cmd_httpgate, "monitor": cmd_monitor, "analyze": cmd_analyze,
     "baseline": cmd_baseline, "forensics": cmd_forensics}[a.cmd](a, cfg)


if __name__ == "__main__":
    main()
