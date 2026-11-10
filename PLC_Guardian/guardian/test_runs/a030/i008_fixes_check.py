"""Repeatable check for A-030 (fixes the I-008 architect-review FAIL on A-028's D-007 active
response). Direct-module level, same style as test_runs/a028/active_response_unit_check.py --
localhost / tools/mock_plc.py / stub servers only, never a real network address.

Covers the BLOCKER + SHOULD-FIX items from the review, one section each:
  (a) item 1: a reply with a short/truncated body, wrong TID, wrong unit, or a mismatched echo
      is logged FAILED, never SUCCEEDED (a tiny stub server stands in for the PLC so each bad
      reply shape can be produced on demand -- mock_plc.py never sends anything but a correct
      echo, so it can't exercise this).
  (b) item 2: a BLOCK-worthy REQUEST whose dst_ip is NOT the configured PLC never triggers a
      write at all.
  (c) item 3: a REQUEST from Guardian's own IP, or one that would clear the lockout coil, is
      skipped as a trigger (not just skipped-with-a-log-record) regardless of decision.
  (d) item 4: invalid active_response config (cooldown_seconds=0, trigger_decisions containing
      a weaker-than-BLOCK decision) is rejected at construction, not silently accepted.
  (e) item 5: an authorized source clearing coil 7 (the lockout coil) now evaluates to ALERT,
      not a plain AUTHORIZED_CHANGE, via policy.Policy.evaluate() directly.
  (f) item 6: a bad active_response config no longer crashes `guardian.py monitor` before
      SESSION_END is written.

Run: python test_runs/a030/i008_fixes_check.py
"""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GUARDIAN_ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, GUARDIAN_ROOT)

from plcguard.active_response import ActiveResponder, build_fc5, send_fc5   # noqa: E402
from plcguard.config import Config                                          # noqa: E402
from plcguard.evidence_log import EvidenceLog, verify                       # noqa: E402
from plcguard.modbus import parse_frame                                     # noqa: E402
from plcguard.policy import Policy                                          # noqa: E402

PASS = True


def check(label, cond):
    global PASS
    print(f"{'PASS' if cond else 'FAIL'}: {label}")
    if not cond:
        PASS = False


def write_config(path, **overrides):
    base = {
        "plc": {"ip": "127.0.0.1", "port": 15050, "unit_ids": [1]},
        "authorized_sources": {},
        "unknown_sources": {"allow_reads": False},
        "protected_points": [],
        "enforcement": {"mode": "monitor"},
        "log": {"path": os.path.join(HERE, "scratch_events.jsonl")},
        "active_response": {"enabled": True, "lockout_coil": 77, "trigger_decisions": ["BLOCK"],
                             "cooldown_seconds": 3, "timeout_s": 1.5},
    }
    for k, v in overrides.items():
        base[k].update(v) if isinstance(v, dict) and k in base else base.update({k: v})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(base, fh)
    return base


def fake_request(seq, decision="BLOCK", src_ip="10.0.0.99", dst_ip="127.0.0.1",
                  category=None, table=None, address=None, values=None):
    rec = {"seq": seq, "decision": decision, "event_type": "UNAUTHORIZED_CHANGE",
           "src_ip": src_ip, "dst_ip": dst_ip, "source_name": None,
           "summary": "FC5 Write Single Coil"}
    if category is not None:
        rec["category"] = category
    if table is not None:
        rec["table"] = table
    if address is not None:
        rec["address"] = address
    if values is not None:
        rec["values"] = values
    return rec


# ---------------------------------------------------------------------------------------------
# (a) item 1: bad PLC replies must never be logged SUCCEEDED
# ---------------------------------------------------------------------------------------------

def _one_shot_server(reply_fn):
    """Binds 127.0.0.1:0, accepts exactly one connection, reads the 12-byte FC5 write-single-
    coil request (7-byte MBAP header + 5-byte PDU), and sends back whatever `reply_fn(header,
    pdu)` returns (None = send nothing, just close). Returns the bound port; the server thread
    exits on its own after the one exchange."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve():
        try:
            srv.settimeout(5)
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            conn.settimeout(5)
            req = b""
            while len(req) < 12:
                chunk = conn.recv(12 - len(req))
                if not chunk:
                    break
                req += chunk
            reply = reply_fn(req[:7], req[7:12]) if len(req) >= 12 else None
            if reply:
                conn.sendall(reply)
        except OSError:
            pass
        finally:
            conn.close()
            srv.close()

    threading.Thread(target=_serve, daemon=True).start()
    return port


def _case_short_body(req_header, req_pdu):
    tid, _proto, _length, unit = struct.unpack(">HHHB", req_header)
    # Declares a full 6-byte length (unit + 5-byte PDU echo) but only actually sends 2 of those
    # 5 PDU bytes before the server closes the connection -- a real PLC never does this; it's
    # here purely to prove send_fc5() doesn't silently accept a truncated body (the old
    # `while len(body) < length - 1: ... if not chunk: break` let this through as "success").
    return struct.pack(">HHHB", tid, 0, len(req_pdu) + 1, unit) + req_pdu[:2]


def _case_wrong_tid(req_header, req_pdu):
    tid, _proto, _length, unit = struct.unpack(">HHHB", req_header)
    return struct.pack(">HHHB", (tid + 1) & 0xFFFF, 0, len(req_pdu) + 1, unit) + req_pdu


def _case_wrong_unit(req_header, req_pdu):
    tid, _proto, _length, unit = struct.unpack(">HHHB", req_header)
    return struct.pack(">HHHB", tid, 0, len(req_pdu) + 1, (unit + 1) & 0xFF) + req_pdu


def _case_mismatched_echo(req_header, req_pdu):
    tid, _proto, _length, unit = struct.unpack(">HHHB", req_header)
    bad_pdu = bytearray(req_pdu)
    bad_pdu[-1] ^= 0xFF   # flip a bit of the echoed value -> no longer the same write
    return struct.pack(">HHHB", tid, 0, len(bad_pdu) + 1, unit) + bytes(bad_pdu)


def check_bad_replies():
    print("\n-- (a) item 1: bad PLC replies are never logged SUCCEEDED --")
    cases = [
        ("short/truncated body", _case_short_body),
        ("wrong transaction ID", _case_wrong_tid),
        ("wrong unit ID", _case_wrong_unit),
        ("mismatched echo", _case_mismatched_echo),
    ]
    for label, reply_fn in cases:
        port = _one_shot_server(reply_fn)
        try:
            send_fc5("127.0.0.1", port, 1, 7, True, 2.0)
            check(f"send_fc5() raises for a {label}", False)
        except Exception as e:
            check(f"send_fc5() raises for a {label} ({type(e).__name__})", True)

    # And through the full ActiveResponder path: outcome must be FAILED, never SUCCEEDED.
    log_path = os.path.join(HERE, "scratch_bad_reply_events.jsonl")
    cfg_path = os.path.join(HERE, "scratch_bad_reply_config.json")
    for p in (log_path, cfg_path):
        if os.path.exists(p):
            os.remove(p)
    port = _one_shot_server(_case_mismatched_echo)
    write_config(cfg_path, plc={"ip": "127.0.0.1", "port": port}, log={"path": log_path},
                 active_response={"enabled": True, "lockout_coil": 7, "trigger_decisions": ["BLOCK"],
                                   "cooldown_seconds": 1, "timeout_s": 2})
    cfg = Config(cfg_path)
    ev = EvidenceLog(log_path)
    responder = ActiveResponder(cfg, ev)
    rec = responder.maybe_respond(fake_request(1))
    ev.close()
    check("mismatched-echo reply -> ActiveResponse outcome is FAILED",
          rec is not None and rec.get("outcome") == "FAILED")
    check("mismatched-echo reply -> outcome is never SUCCEEDED",
          rec is not None and rec.get("outcome") != "SUCCEEDED")


# ---------------------------------------------------------------------------------------------
# (b) item 2: wrong dst_ip must never trigger a write
# ---------------------------------------------------------------------------------------------

def check_dst_ip_guard():
    print("\n-- (b) item 2: REQUEST not addressed to the configured PLC never triggers --")
    accepted = threading.Event()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _watch():
        srv.settimeout(2)
        try:
            conn, _ = srv.accept()
            accepted.set()
            conn.close()
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=_watch, daemon=True).start()

    cfg_path = os.path.join(HERE, "scratch_dstip_config.json")
    log_path = os.path.join(HERE, "scratch_dstip_events.jsonl")
    for p in (cfg_path, log_path):
        if os.path.exists(p):
            os.remove(p)
    write_config(cfg_path, plc={"ip": "127.0.0.1", "port": port}, log={"path": log_path})
    cfg = Config(cfg_path)
    ev = EvidenceLog(log_path)
    responder = ActiveResponder(cfg, ev)

    rec = responder.maybe_respond(fake_request(1, dst_ip="203.0.113.50"))   # not the PLC
    ev.close()
    time.sleep(0.5)   # give the watcher thread a moment, if it were going to fire at all
    check("BLOCK to a non-PLC dst_ip -> maybe_respond() returns None", rec is None)
    check("BLOCK to a non-PLC dst_ip -> no evidence record written at all",
          os.path.getsize(log_path) == 0)
    check("BLOCK to a non-PLC dst_ip -> the real PLC stub never even saw a connection",
          not accepted.is_set())


# ---------------------------------------------------------------------------------------------
# (c) item 3: self-trigger guard
# ---------------------------------------------------------------------------------------------

def check_self_trigger_guard():
    print("\n-- (c) item 3: Guardian's own traffic / a lockout-clearing write never re-triggers --")
    cfg_path = os.path.join(HERE, "scratch_self_config.json")
    log_path = os.path.join(HERE, "scratch_self_events.jsonl")
    for p in (cfg_path, log_path):
        if os.path.exists(p):
            os.remove(p)
    # Port 1 so a real send (if the guard failed to stop it) fails fast rather than hanging --
    # the point of this check is that the attempt never happens at all.
    write_config(cfg_path, plc={"ip": "127.0.0.1", "port": 1}, log={"path": log_path},
                 active_response={"enabled": True, "lockout_coil": 7, "trigger_decisions": ["BLOCK"],
                                   "cooldown_seconds": 1, "timeout_s": 1})
    cfg = Config(cfg_path)
    ev = EvidenceLog(log_path)
    responder = ActiveResponder(cfg, ev)
    responder.own_ip = "10.0.0.5"   # pin it instead of depending on this host's live routing

    rec1 = responder.maybe_respond(fake_request(1, src_ip="10.0.0.5"))
    check("REQUEST whose src_ip is Guardian's own IP -> maybe_respond() returns None", rec1 is None)

    rec2 = responder.maybe_respond(fake_request(2, src_ip="192.168.8.50", category="write",
                                                 table="coil", address=7, values=[0]))
    check("write that would clear the lockout coil -> maybe_respond() returns None", rec2 is None)
    check("neither case wrote any evidence record", os.path.getsize(log_path) == 0)

    # Sanity: the SAME config, a normal attacker from a different IP writing somewhere else,
    # DOES still get evaluated as a trigger (it just fails fast against port 1 -- that's the
    # existing unreachable-PLC path, already covered by a028, not re-litigated here). Must run
    # before ev.close() -- maybe_respond() still writes an evidence record for this one.
    rec3 = responder.maybe_respond(fake_request(3, src_ip="203.0.113.7"))
    check("an unrelated attacker IP still gets evaluated as a trigger (attempt made)", rec3 is not None)
    ev.close()


# ---------------------------------------------------------------------------------------------
# (d) item 4: config validation
# ---------------------------------------------------------------------------------------------

def check_config_validation():
    print("\n-- (d) item 4: invalid active_response config is rejected, not silently accepted --")
    cfg_path = os.path.join(HERE, "scratch_cfg_cooldown0.json")
    write_config(cfg_path, active_response={"enabled": True, "lockout_coil": 7,
                                             "trigger_decisions": ["BLOCK"], "cooldown_seconds": 0})
    cfg = Config(cfg_path)
    try:
        ActiveResponder(cfg, EvidenceLog(os.path.join(HERE, "scratch_cfg_cooldown0.jsonl")))
        check("cooldown_seconds=0 raises ValueError at construction", False)
    except ValueError as e:
        check(f"cooldown_seconds=0 raises ValueError at construction ({e})", True)

    cfg_path2 = os.path.join(HERE, "scratch_cfg_alert.json")
    write_config(cfg_path2, active_response={"enabled": True, "lockout_coil": 7,
                                              "trigger_decisions": ["ALERT"], "cooldown_seconds": 3})
    cfg2 = Config(cfg_path2)
    try:
        ActiveResponder(cfg2, EvidenceLog(os.path.join(HERE, "scratch_cfg_alert.jsonl")))
        check("trigger_decisions=['ALERT'] without opt-in raises ValueError", False)
    except ValueError as e:
        check(f"trigger_decisions=['ALERT'] without opt-in raises ValueError ({e})", True)

    # The explicit opt-in flag makes the same trigger_decisions value acceptable.
    cfg_path3 = os.path.join(HERE, "scratch_cfg_alert_optin.json")
    write_config(cfg_path3, active_response={"enabled": True, "lockout_coil": 7,
                                              "trigger_decisions": ["ALERT"], "cooldown_seconds": 3,
                                              "allow_weaker_than_block_trigger": True})
    cfg3 = Config(cfg_path3)
    try:
        r3 = ActiveResponder(cfg3, EvidenceLog(os.path.join(HERE, "scratch_cfg_alert_optin.jsonl")))
        check("trigger_decisions=['ALERT'] WITH explicit opt-in is accepted", r3.active)
    except ValueError:
        check("trigger_decisions=['ALERT'] WITH explicit opt-in is accepted", False)

    # Disabled responder must never crash construction even with the same bad values.
    cfg_path4 = os.path.join(HERE, "scratch_cfg_disabled_bad.json")
    write_config(cfg_path4, active_response={"enabled": False, "lockout_coil": 7,
                                              "trigger_decisions": ["ALERT"], "cooldown_seconds": 0})
    cfg4 = Config(cfg_path4)
    try:
        r4 = ActiveResponder(cfg4, EvidenceLog(os.path.join(HERE, "scratch_cfg_disabled_bad.jsonl")))
        check("same bad values but enabled=false does not raise, and stays inactive", not r4.active)
    except ValueError:
        check("same bad values but enabled=false does not raise, and stays inactive", False)


# ---------------------------------------------------------------------------------------------
# (e) item 5: coil 7 clear from an authorized source -> ALERT, not plain AUTHORIZED_CHANGE
# ---------------------------------------------------------------------------------------------

def check_coil7_protected_point():
    print("\n-- (e) item 5: clearing coil 7 from an authorized source is ALERT --")
    cfg_path = os.path.join(HERE, "scratch_policy_config.json")
    write_config(cfg_path,
                 authorized_sources={"192.168.8.50": {"name": "Engineering laptop",
                                                        "allow": ["read", "write", "config"]}},
                 protected_points=[{"name": "%M7 PLCGUARD", "table": "coil", "start": 7, "end": 7,
                                     "min": 1, "max": 1, "enabled": True}])
    cfg = Config(cfg_path)
    policy = Policy(cfg)

    def _mbap_frame(pdu: bytes, unit: int = 1) -> bytes:
        return struct.pack(">HHHB", 1, 0, len(pdu) + 1, unit) + pdu

    pdu_off = build_fc5(7, False)              # FC5 write coil 7 = OFF (clears the lockout)
    frame = parse_frame(_mbap_frame(pdu_off), True)
    v = policy.evaluate(frame, "192.168.8.50")
    check("clearing coil 7 from an authorized source -> decision is ALERT", v.decision == "ALERT")
    check("clearing coil 7 from an authorized source -> flagged VALUE_OUT_OF_RANGE",
          "VALUE_OUT_OF_RANGE" in v.rules)
    check("clearing coil 7 from an authorized source -> NOT a plain AUTHORIZED_CHANGE "
          "(event_type stays, but decision escalates past ALLOW)", v.decision != "ALLOW")

    pdu_on = build_fc5(7, True)                # setting it back ON (re-locking) is in-range
    frame_on = parse_frame(_mbap_frame(pdu_on), True)
    v_on = policy.evaluate(frame_on, "192.168.8.50")
    check("re-locking coil 7 (write 1) from an authorized source stays ALLOW",
          v_on.decision == "ALLOW")


# ---------------------------------------------------------------------------------------------
# (f) item 6: bad active_response config must not crash cmd_monitor before SESSION_END
# ---------------------------------------------------------------------------------------------

def check_monitor_survives_bad_config():
    print("\n-- (f) item 6: a bad active_response config does not crash `guardian.py monitor` --")
    LOOPBACK_IFACE = r"\Device\NPF_Loopback"
    plc_port = 15051
    cfg_path = os.path.join(HERE, "scratch_badmon_config.json")
    log_path = os.path.join(HERE, "scratch_badmon_events.jsonl")
    stdout_path = os.path.join(HERE, "scratch_badmon_stdout.txt")
    for p in (cfg_path, log_path, stdout_path):
        if os.path.exists(p):
            os.remove(p)
    cfg = {
        "plc": {"ip": "127.0.0.1", "port": plc_port, "unit_ids": [1]},
        "authorized_sources": {}, "unknown_sources": {"allow_reads": False},
        "protected_points": [], "enforcement": {"mode": "monitor"},
        "log": {"path": log_path},
        # Deliberately invalid: cooldown_seconds=0 -> ActiveResponder() raises ValueError.
        "active_response": {"enabled": True, "lockout_coil": 7, "trigger_decisions": ["BLOCK"],
                             "cooldown_seconds": 0, "timeout_s": 1},
    }
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)

    plc = subprocess.Popen([sys.executable, "-u", os.path.join(GUARDIAN_ROOT, "tools", "mock_plc.py"),
                            "--port", str(plc_port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
    time.sleep(1.0)

    mon_out = open(stdout_path, "w", encoding="utf-8")
    monitor = subprocess.Popen(
        [sys.executable, "-u", os.path.join(GUARDIAN_ROOT, "guardian.py"),
         "--config", cfg_path, "--log", log_path, "monitor", "--iface", LOOPBACK_IFACE],
        stdout=mon_out, stderr=subprocess.STDOUT, cwd=GUARDIAN_ROOT)
    time.sleep(3)   # let it get past construction, print its messages, and reach sniff_live()

    monitor.terminate()
    try:
        monitor.wait(timeout=10)
    except subprocess.TimeoutExpired:
        monitor.kill()
    plc.terminate()
    try:
        plc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        plc.kill()
    mon_out.close()

    with open(stdout_path, encoding="utf-8") as fh:
        mon_text = fh.read()
    print("---- guardian.py monitor stdout (bad config) ----")
    print(mon_text.strip())
    print("---------------------------------------------------")

    check("monitor printed the 'active_response config is invalid' fallback message",
          "active_response config is invalid" in mon_text)
    check("monitor still reached the sniffing banner -- i.e. it did NOT crash at "
          "ActiveResponder construction, which is the actual I-008 item 6 bug",
          "Sniffing tcp port" in mon_text)

    # NOTE on SESSION_END: like live_monitor_integration_check.py (A-028), this test stops the
    # subprocess with terminate() (forceful TerminateProcess on Windows), which does not run
    # Python's `finally` block -- so it proves nothing either way about SESSION_END, same
    # caveat that test already documents. The two checks above are what actually exercise the
    # item 6 fix (a bad config raising BEFORE the outer try/finally used to skip SESSION_END
    # unconditionally; now it doesn't even get that far before falling back).
    ok, _n, _bad, msg = verify(log_path)
    check(f"evidence log chain intact regardless ({msg})", ok)


def main():
    check_bad_replies()
    check_dst_ip_guard()
    check_self_trigger_guard()
    check_config_validation()
    check_coil7_protected_point()
    check_monitor_survives_bad_config()

    print()
    print("ALL CHECKS PASSED" if PASS else "SOME CHECKS FAILED")
    sys.exit(0 if PASS else 1)


if __name__ == "__main__":
    main()
