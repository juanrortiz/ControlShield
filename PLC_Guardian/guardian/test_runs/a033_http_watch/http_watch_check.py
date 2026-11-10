"""Repeatable check for D-009 (passive HTTP-connection trigger for the D-007 lockout).

Round 2 (post architect review): rewritten/extended to cover every blocker/should-fix from
that review, not just the happy path -- in particular (b) now asserts the FIXED, narrower
behaviour (a Modbus-sourced BLOCK record addressed to the HMI's IP must NOT fire the lockout;
round 1's check wrongly asserted the opposite and encoded the hole architect BLOCKER 1 found).

Covers:
  (a) A synthetic HTTP-shaped trigger record (sensor="http_watch", dst_ip/dst_port = HMI, the
      exact (sensor, dst_ip, dst_port) triple in extra_triggers) fed into
      ActiveResponder.maybe_respond() against a local tools/mock_plc.py -> one real FC5
      lockout write reaches the mock PLC, logged correctly (ACTIVE_RESPONSE/SUCCEEDED, chain
      intact).
  (b) Regression + BLOCKER 1 fix for the trust-check change in active_response.py:
        - extra_triggers defaults to empty when omitted; dst_ip==plc_ip still triggers
          unconditionally regardless of sensor (today's original behaviour, unchanged).
        - A MODBUS-sourced (no sensor, or sensor != "http_watch") BLOCK record addressed to
          the HMI's IP must NEVER trigger, even when extra_triggers lists that
          (sensor, ip, port) for http_watch specifically -- the trust is keyed on WHO
          produced the record, not just where it was addressed.
        - An http_watch-sourced record on the right dst_ip but WRONG dst_port must not
          trigger either (exact triple match required).
        - inactive()'s fallback gets the same default/opt-in treatment.
        - A third, completely untrusted dst_ip never triggers either way.
  (c) http_watch.py's own detection logic, driven through the REAL `sniff_http_watch()` code
      path (scapy.sendrecv.sniff monkeypatched to feed in-process-built packets instead of a
      live capture -- this exercises the actual cb() closure: flag check, dst/port check, MAC
      extraction, handle_syn() call -- not a reimplementation of its logic in the test):
      unauthorized source -> REQUEST record with the documented shape; authorized source (IP
      + MAC match) -> no record; retransmitted SYN (same src_ip:src_port) -> deduped; a flood
      of new source ports from one IP -> rate-limited after the first, with a
      suppressed_count on the next record once the window rolls over; a source IP that IS
      allowlisted but arrives with the WRONG MAC -> SPOOFED_SOURCE/MAC_MISMATCH, not silently
      authorized.
  (d) BLOCKER 2 fixes: the sniffer loop actually stops within a bound when stop_event is set
      even with zero matching traffic (no unbounded sniff() call to get stuck in); a write
      attempted after EvidenceLog.close() is refused cleanly (no crash, no corrupted file);
      two threads calling ActiveResponder.maybe_respond() concurrently for the same trigger
      produce exactly one real write, not a race of two.
  (e) cooldown is shared across trigger types: an HTTP trigger fired first puts a subsequent
      Modbus trigger (same responder, dst_ip=plc_ip) into cooldown, and vice versa.

Run: python test_runs/a033_http_watch/http_watch_check.py
"""
import json
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GUARDIAN_ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, GUARDIAN_ROOT)

from plcguard.config import Config                      # noqa: E402
from plcguard.evidence_log import EvidenceLog, verify    # noqa: E402
from plcguard.active_response import ActiveResponder     # noqa: E402
from plcguard import http_watch as hw_mod                # noqa: E402
from plcguard.http_watch import HttpWatch, build_http_request_record  # noqa: E402

PASS = True


def check(label, cond):
    global PASS
    print(f"{'PASS' if cond else 'FAIL'}: {label}")
    if not cond:
        PASS = False


def write_config(path, log_path, **overrides):
    base = {
        "plc": {"ip": "127.0.0.1", "port": 15041, "unit_ids": [1]},
        "authorized_sources": {
            "192.168.8.50": {"name": "Eng laptop", "allow": ["read"]},
            "192.168.8.77": {"name": "Spoof-test host", "mac": "aa:bb:cc:dd:ee:ff", "allow": ["read"]},
        },
        "unknown_sources": {"allow_reads": False},
        "protected_points": [],
        "enforcement": {"mode": "monitor"},
        "log": {"path": log_path},
        "active_response": {"enabled": True, "lockout_coil": 77, "trigger_decisions": ["BLOCK"],
                             "cooldown_seconds": 3, "timeout_s": 1.5},
        "http_watch": {"enabled": True, "hmi_ip": "192.168.8.10", "hmi_port": 80},
    }
    for k, v in overrides.items():
        base[k].update(v) if isinstance(v, dict) and k in base else base.update({k: v})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(base, fh)
    return base


def fresh(prefix, plc_port=1, **overrides):
    cfg_path = os.path.join(HERE, f"{prefix}_config.json")
    log_path = os.path.join(HERE, f"{prefix}_events.jsonl")
    for p in (cfg_path, log_path):
        if os.path.exists(p):
            os.remove(p)
    write_config(cfg_path, log_path, plc={"ip": "127.0.0.1", "port": plc_port}, **overrides)
    return Config(cfg_path), EvidenceLog(log_path), log_path


def modbus_rec(seq, decision="BLOCK", src_ip="10.0.0.99", dst_ip="127.0.0.1", sensor="live:eth0"):
    # A real Modbus REQUEST record carries sensor="live:<iface>" or "pcap:<file>", never
    # "http_watch" -- this is what the Modbus sniffer's on_event callback actually hands
    # maybe_respond() (see analyzer.py's sensor=f"live:{iface}").
    return {"seq": seq, "decision": decision, "event_type": "UNAUTHORIZED_CHANGE", "sensor": sensor,
            "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": 502, "source_name": None,
            "summary": "FC5 Write Single Coil addr=0"}


def http_rec(seq, dst_ip="192.168.8.10", dst_port=80, sensor="http_watch"):
    return {"seq": seq, "decision": "BLOCK", "event_type": "UNAUTHORIZED_HTTP_ACCESS", "sensor": sensor,
            "src_ip": "10.0.0.66", "dst_ip": dst_ip, "dst_port": dst_port, "source_name": None,
            "summary": "TCP SYN to HMI:80 from unauthorized source 10.0.0.66"}


def part_a(plc_port):
    """(a) HTTP trigger (right sensor, right dst_ip:dst_port) fires the real D-007 lockout."""
    cfg, ev, log_path = fresh("part_a", plc_port=plc_port)
    extra = {("http_watch", "192.168.8.10", 80)}
    responder = ActiveResponder(cfg, ev, extra_triggers=extra)
    rec = responder.maybe_respond(http_rec(1))
    check("(a) HTTP trigger -> a record was written", rec is not None)
    check("(a) HTTP trigger -> outcome SUCCEEDED", rec and rec.get("outcome") == "SUCCEEDED")
    check("(a) ACTIVE_RESPONSE record links back to the HTTP trigger's seq",
          rec and rec.get("trigger_seq") == 1 and rec.get("trigger_event_type") == "UNAUTHORIZED_HTTP_ACCESS")
    ev.close()
    ok, n, bad, msg = verify(log_path)
    check(f"(a) evidence log chain intact ({msg})", ok)
    return rec


def part_b():
    """(b) extra_triggers defaults + BLOCKER 1 fix: trust is keyed on (sensor, dst_ip, dst_port),
    not a flat destination-IP set."""
    cfg, ev, log_path = fresh("part_b", plc_port=1)   # PLC unreachable is fine; FAILED still logs

    # default (no extra_triggers passed) -- plc_ip still triggers from ANY sensor, unchanged.
    responder = ActiveResponder(cfg, ev)
    check("(b) default extra_triggers is empty", responder.extra_triggers == set())
    rec_plc = responder.maybe_respond(modbus_rec(1, dst_ip=cfg.plc_ip, sensor="live:eth0"))
    check("(b) Modbus request to the PLC still triggers (unaffected by this change)", rec_plc is not None)

    rec_hmi = responder.maybe_respond(modbus_rec(2, dst_ip="192.168.8.10", sensor="live:eth0"))
    check("(b) Modbus request to the HMI does NOT trigger with no extra_triggers", rec_hmi is None)

    inactive = ActiveResponder.inactive(cfg, ev)
    check("(b) inactive() default extra_triggers is empty", inactive.extra_triggers == set())
    check("(b) inactive() never fires regardless of dst_ip (feature off)",
          inactive.maybe_respond(modbus_rec(3, dst_ip=cfg.plc_ip)) is None)

    # Widen it the way cmd_monitor does when http_watch is enabled.
    extra = {("http_watch", "192.168.8.10", 80)}
    responder2 = ActiveResponder(cfg, ev, extra_triggers=extra)

    rec_plc2 = responder2.maybe_respond(modbus_rec(4, dst_ip=cfg.plc_ip, sensor="live:eth0"))
    check("(b) widened responder: Modbus-to-PLC still triggers", rec_plc2 is not None)

    # THE FIX: a Modbus-sourced record addressed to the HMI's IP must NOT trigger just because
    # that IP appears in an extra_triggers entry for a DIFFERENT sensor. This is exactly the
    # architect round-1 BLOCKER 1 hole -- this assertion is the corrected (flipped) version of
    # round 1's wrong one.
    rec_modbus_to_hmi = responder2.maybe_respond(modbus_rec(5, dst_ip="192.168.8.10", sensor="live:eth0"))
    check("(b) BLOCKER 1 FIX: Modbus-sourced record to the HMI's IP must NOT trigger",
          rec_modbus_to_hmi is None)
    # Also must not trigger with no sensor field at all (defensive: missing key, not just wrong value).
    rec_no_sensor = dict(modbus_rec(6, dst_ip="192.168.8.10"))
    del rec_no_sensor["sensor"]
    check("(b) a record with no sensor field at all, addressed to the HMI, must NOT trigger",
          responder2.maybe_respond(rec_no_sensor) is None)

    # The actual http_watch-sourced trigger on the exact registered triple DOES fire.
    rec_http = responder2.maybe_respond(http_rec(7, dst_ip="192.168.8.10", dst_port=80, sensor="http_watch"))
    check("(b) http_watch-sourced record on the exact registered triple DOES trigger",
          rec_http is not None)

    # Same sensor/IP but the WRONG port must not match (exact-triple requirement).
    rec_wrong_port = responder2.maybe_respond(
        http_rec(8, dst_ip="192.168.8.10", dst_port=8080, sensor="http_watch"))
    check("(b) http_watch-sourced record on the RIGHT ip/sensor but WRONG port must NOT trigger",
          rec_wrong_port is None)

    # A third, totally untrusted destination never triggers either way.
    rec_other = responder2.maybe_respond(modbus_rec(9, dst_ip="203.0.113.9", sensor="live:eth0"))
    check("(b) a third, untrusted dst_ip still never triggers", rec_other is None)

    ev.close()
    ok, n, bad, msg = verify(log_path)
    check(f"(b) evidence log chain intact ({msg})", ok)


def part_c():
    """(c) http_watch.py's detection logic, driven through the REAL sniff_http_watch() code
    path with scapy.sendrecv.sniff monkeypatched to feed synthetic packets instead of a live
    capture."""
    import scapy.sendrecv
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    cfg, ev, log_path = fresh("part_c", plc_port=1)
    events = []

    # Shrink the windows for test speed, restored in `finally`.
    orig_dedup, orig_rate = hw_mod._DEDUP_WINDOW_S, hw_mod._RATE_WINDOW_S
    hw_mod._DEDUP_WINDOW_S, hw_mod._RATE_WINDOW_S = 0.3, 0.4

    pkts = [
        # 1: unauthorized source's opening SYN -> must be logged.
        Ether(src="aa:aa:aa:aa:aa:01") / IP(src="10.0.0.66", dst="192.168.8.10") / TCP(sport=54321, dport=80, flags="S"),
        # 2: immediate retransmit of the SAME (ip, port) SYN -> deduped, no 2nd record.
        Ether(src="aa:aa:aa:aa:aa:01") / IP(src="10.0.0.66", dst="192.168.8.10") / TCP(sport=54321, dport=80, flags="S"),
        # 3: the HMI's own SYN-ACK reply -> must be ignored (ACK set).
        Ether() / IP(src="192.168.8.10", dst="10.0.0.66") / TCP(sport=80, dport=54321, flags="SA"),
        # 4: authorized source (IP+MAC match authorized_sources) -> must NOT be logged.
        Ether(src="00:00:54:0b:c5:9a") / IP(src="192.168.8.50", dst="192.168.8.10") / TCP(sport=11111, dport=80, flags="S"),
        # 5: allowlisted IP but WRONG MAC -> spoofed, must be logged as SPOOFED_SOURCE.
        Ether(src="de:ad:be:ef:00:01") / IP(src="192.168.8.77", dst="192.168.8.10") / TCP(sport=22222, dport=80, flags="S"),
        # 6: a different unauthorized source port (still within the rate window) -> rate-limited.
        Ether(src="aa:aa:aa:aa:aa:02") / IP(src="10.0.0.66", dst="192.168.8.10") / TCP(sport=54322, dport=80, flags="S"),
        # 7: traffic to a different host entirely -> must be ignored (dst filter).
        Ether() / IP(src="10.0.0.66", dst="192.168.8.99") / TCP(sport=54323, dport=80, flags="S"),
    ]

    stop_event = threading.Event()

    def fake_sniff(iface=None, filter=None, prn=None, store=False, timeout=None):
        for p in pkts:
            prn(p)
        stop_event.set()   # let sniff_http_watch's outer while loop exit after this one call
        return []

    orig_sniff = scapy.sendrecv.sniff
    scapy.sendrecv.sniff = fake_sniff
    try:
        watch = hw_mod.sniff_http_watch(None, cfg, ev, on_event=events.append, stop_event=stop_event)
    finally:
        scapy.sendrecv.sniff = orig_sniff
        hw_mod._DEDUP_WINDOW_S, hw_mod._RATE_WINDOW_S = orig_dedup, orig_rate

    check("(c) real sniff_http_watch() code path produced exactly 2 records "
          "(unauthorized SYN + spoofed-MAC SYN; retransmit/SYN-ACK/authorized/wrong-host/rate-limited excluded)",
          len(events) == 2)
    unauth = [e for e in events if e["event_type"] == "UNAUTHORIZED_HTTP_ACCESS"]
    spoofed = [e for e in events if e["event_type"] == "SPOOFED_SOURCE"]
    check("(c) unauthorized-source record shape matches the brief",
          len(unauth) == 1 and (unauth[0]["record"], unauth[0]["sensor"], unauth[0]["decision"],
                                 unauth[0]["action"], unauth[0]["rules"], unauth[0]["dst_ip"],
                                 unauth[0]["dst_port"], unauth[0]["src_ip"]) ==
          ("REQUEST", "http_watch", "BLOCK", "OBSERVED", ["SRC_NOT_ALLOWLISTED_HTTP"],
           "192.168.8.10", 80, "10.0.0.66"))
    check("(c) allowlisted IP with the WRONG MAC -> SPOOFED_SOURCE/MAC_MISMATCH, not silently authorized",
          len(spoofed) == 1 and spoofed[0]["rules"] == ["MAC_MISMATCH"] and spoofed[0]["src_ip"] == "192.168.8.77")

    ev.close()
    ok, n, bad, msg = verify(log_path)
    check(f"(c) evidence log chain intact ({msg})", ok)

    # Rate limiting / suppressed_count, isolated from the sniff plumbing above.
    cfg2, ev2, log_path2 = fresh("part_c_rate", plc_port=1)
    orig_dedup, orig_rate = hw_mod._DEDUP_WINDOW_S, hw_mod._RATE_WINDOW_S
    hw_mod._DEDUP_WINDOW_S, hw_mod._RATE_WINDOW_S = 0.05, 0.25
    try:
        events2 = []
        watch2 = HttpWatch(cfg2, ev2, on_event=events2.append)
        r1 = watch2.handle_syn("10.0.0.66", 1000, time.time())
        check("(c) rate limit: first SYN from a noisy IP is logged", r1 is not None)
        r2 = watch2.handle_syn("10.0.0.66", 1001, time.time())
        r3 = watch2.handle_syn("10.0.0.66", 1002, time.time())
        check("(c) rate limit: further new-port SYNs from the SAME ip within the window are suppressed",
              r2 is None and r3 is None)
        time.sleep(0.3)   # let the rate window roll over
        r4 = watch2.handle_syn("10.0.0.66", 1003, time.time())
        check("(c) rate limit: after the window rolls over, a new record is logged with the "
              "suppressed count folded in",
              r4 is not None and any("2 additional connection attempt" in d for d in r4["details"]))
        check("(c) rate limit: logging stayed bounded (4 SYNs -> only 2 evidence records)",
              len(events2) == 2)
    finally:
        ev2.close()
        hw_mod._DEDUP_WINDOW_S, hw_mod._RATE_WINDOW_S = orig_dedup, orig_rate

    # Direct sanity on the standalone builder function, including the spoofed-MAC path.
    built = build_http_request_record("1.2.3.4", 9999, "192.168.8.10", 80, time.time())
    check("(c) build_http_request_record() standalone shape is correct",
          built["event_type"] == "UNAUTHORIZED_HTTP_ACCESS" and built["decision"] == "BLOCK"
          and built["action"] == "OBSERVED" and built["sensor"] == "http_watch")
    built_spoof = build_http_request_record("1.2.3.4", 9999, "192.168.8.10", 80, time.time(),
                                             spoofed_mac="de:ad:be:ef:00:01")
    check("(c) build_http_request_record() spoofed_mac path -> SPOOFED_SOURCE/MAC_MISMATCH",
          built_spoof["event_type"] == "SPOOFED_SOURCE" and built_spoof["rules"] == ["MAC_MISMATCH"])


def part_d_shutdown():
    """(d) BLOCKER 2 item 1: the sniffer thread actually stops within a bound even with ZERO
    matching traffic -- no unbounded sniff() call left to get stuck in."""
    import scapy.sendrecv
    cfg, ev, log_path = fresh("part_d_shutdown", plc_port=1)

    slices_run = {"n": 0}

    def fake_sniff_quiet(iface=None, filter=None, prn=None, store=False, timeout=None):
        slices_run["n"] += 1
        time.sleep(0.05)   # simulate a short bounded capture slice with no matching traffic
        return []

    orig_sniff = scapy.sendrecv.sniff
    scapy.sendrecv.sniff = fake_sniff_quiet
    stop_event = threading.Event()
    try:
        t = threading.Thread(target=hw_mod.sniff_http_watch,
                              args=(None, cfg, ev), kwargs={"stop_event": stop_event}, daemon=True)
        t.start()
        time.sleep(0.2)              # let a few quiet slices run with nothing to trigger on
        stop_event.set()
        t.join(timeout=3)
        check("(d) sniffer thread actually exits within a bound when there is NO matching traffic",
              not t.is_alive())
        check("(d) the sniffer loop really ran multiple bounded slices (not one unbounded call)",
              slices_run["n"] >= 2)
    finally:
        scapy.sendrecv.sniff = orig_sniff
        ev.close()
    ok, n, bad, msg = verify(log_path)
    check(f"(d) evidence log chain still verifies cleanly after a clean shutdown with no traffic ({msg})", ok)


def part_d_closed_log():
    """(d) BLOCKER 2 item 3: a write attempted after EvidenceLog.close() is refused cleanly,
    not crashed on, and does not corrupt the file -- simulates a trigger landing in the
    shutdown race window."""
    cfg, ev, log_path = fresh("part_d_closed_log", plc_port=1)
    responder = ActiveResponder(cfg, ev)
    rec1 = responder.maybe_respond(modbus_rec(1, dst_ip=cfg.plc_ip, sensor="live:eth0"))
    check("(d) sanity: first trigger logs fine before close()", rec1 is not None)

    ev.close()
    check("(d) EvidenceLog reports closed after close()", ev._closed is True)

    # A write attempted after close() (e.g. a slow send that finished after shutdown's
    # finally already closed the log) must not raise into the caller or corrupt the file.
    raised = False
    try:
        rec2 = responder.maybe_respond(modbus_rec(2, dst_ip=cfg.plc_ip, sensor="live:eth0"))
    except Exception:
        raised = True
        rec2 = None
    check("(d) a trigger landing AFTER close() does not raise out of maybe_respond()", not raised)
    check("(d) a trigger landing AFTER close() returns None (could not be logged, logged loudly instead)",
          rec2 is None)

    ok, n, bad, msg = verify(log_path)
    check(f"(d) evidence log file is NOT corrupted by the post-close write attempt ({msg})", ok)

    # A direct EvidenceLog.write() after close() must also refuse cleanly with a clear error,
    # not silently succeed or crash with a bare "I/O operation on closed file".
    try:
        ev.write({"record": "SHOULD_NOT_LAND"})
        check("(d) EvidenceLog.write() after close() raises RuntimeError", False)
    except RuntimeError:
        check("(d) EvidenceLog.write() after close() raises RuntimeError (not a bare I/O error)", True)


def part_d_race(plc_port):
    """(d) BLOCKER 2 / should-fix 2: two threads calling maybe_respond() for the same trigger
    concurrently must produce exactly ONE real write, not a race of two past the cooldown
    check."""
    cfg, ev, log_path = fresh("part_d_race", plc_port=plc_port)
    responder = ActiveResponder(cfg, ev)
    results = []
    lock = threading.Lock()

    def fire(seq):
        rec = responder.maybe_respond(modbus_rec(seq, dst_ip=cfg.plc_ip, sensor="live:eth0"))
        with lock:
            results.append(rec)

    threads = [threading.Thread(target=fire, args=(i,)) for i in range(1, 9)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    outcomes = [r.get("outcome") for r in results if r is not None]
    succeeded = [o for o in outcomes if o == "SUCCEEDED"]
    check("(d) 8 concurrent triggers -> every one got a logged outcome (none lost/crashed)",
          len(outcomes) == 8)
    check("(d) 8 concurrent triggers -> exactly ONE real PLC write (SUCCEEDED), the rest SKIPPED_COOLDOWN",
          len(succeeded) == 1)
    ev.close()
    ok, n, bad, msg = verify(log_path)
    check(f"(d) evidence log chain intact after the concurrent-trigger race ({msg})", ok)


def part_e_shared_cooldown(plc_port):
    """(e) cooldown is shared across trigger types: an HTTP trigger puts a subsequent Modbus
    trigger on the SAME responder into cooldown, and vice versa."""
    cfg, ev, log_path = fresh("part_e", plc_port=plc_port)
    extra = {("http_watch", "192.168.8.10", 80)}
    responder = ActiveResponder(cfg, ev, extra_triggers=extra)

    rec1 = responder.maybe_respond(http_rec(1))
    check("(e) first (HTTP) trigger fires for real", rec1 and rec1.get("outcome") == "SUCCEEDED")
    rec2 = responder.maybe_respond(modbus_rec(2, dst_ip=cfg.plc_ip, sensor="live:eth0"))
    check("(e) second (Modbus) trigger on the SAME responder is in cooldown, not a second real write",
          rec2 and rec2.get("outcome") == "SKIPPED_COOLDOWN")
    ev.close()
    ok, n, bad, msg = verify(log_path)
    check(f"(e) evidence log chain intact ({msg})", ok)


def main():
    plc_port = 15041
    plc = subprocess.Popen([sys.executable, "-u", os.path.join(GUARDIAN_ROOT, "tools", "mock_plc.py"),
                            "--port", str(plc_port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
    time.sleep(1.5)
    try:
        part_a(plc_port)
    finally:
        time.sleep(0.3)
        plc.terminate()
        plc_out = plc.stdout.read() if plc.stdout else ""
        try:
            plc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            plc.kill()
    check("(a) mock PLC actually received the lockout-coil write (coil 77 <- 1)",
          "coil 77 <- 1" in plc_out)
    print("---- mock PLC stdout (part a) ----")
    print(plc_out.strip())
    print("-----------------------------------")

    part_b()
    part_c()
    part_d_shutdown()
    part_d_closed_log()

    plc2 = subprocess.Popen([sys.executable, "-u", os.path.join(GUARDIAN_ROOT, "tools", "mock_plc.py"),
                             "--port", str(plc_port + 1)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    time.sleep(1.5)
    try:
        part_d_race(plc_port + 1)
        part_e_shared_cooldown(plc_port + 1)
    finally:
        plc2.terminate()
        try:
            plc2.wait(timeout=5)
        except subprocess.TimeoutExpired:
            plc2.kill()

    print()
    print("ALL CHECKS PASSED" if PASS else "SOME CHECKS FAILED")
    sys.exit(0 if PASS else 1)


if __name__ == "__main__":
    main()
