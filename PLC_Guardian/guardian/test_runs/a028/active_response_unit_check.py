"""Repeatable check for A-028 (D-007 active response), direct-module level.

Exercises plcguard/active_response.py's ActiveResponder directly against a running
tools/mock_plc.py, with synthetic REQUEST records standing in for what analyzer._handle_frame
would hand it from a real BLOCK verdict. This is the level the brief's fallback applies to:
localhost only, no live packet sniffing here (see live_monitor_integration_check.py for that).

Covers:
  1. A BLOCK-decision record -> one real FC5 write reaches the mock PLC, and one
     ACTIVE_RESPONSE record (outcome SUCCEEDED) is written to the evidence log, hash-chained
     with everything else.
  2. A second BLOCK-decision record inside cooldown_seconds -> no second PLC write, logged
     as SKIPPED_COOLDOWN.
  3. Pointing the lockout write at an unreachable port -> outcome FAILED, raises nothing,
     returns promptly (bounded by timeout_s), and is still logged.
  4. active_response.enabled = false -> maybe_respond() is a no-op (returns None, no log
     record, no socket ever opened) even for a BLOCK record.

Run: python test_runs/a028/active_response_unit_check.py
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GUARDIAN_ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, GUARDIAN_ROOT)

from plcguard.config import Config          # noqa: E402
from plcguard.evidence_log import EvidenceLog, verify  # noqa: E402
from plcguard.active_response import ActiveResponder   # noqa: E402

PASS = True


def check(label, cond):
    global PASS
    print(f"{'PASS' if cond else 'FAIL'}: {label}")
    if not cond:
        PASS = False


def write_config(path, **overrides):
    base = {
        "plc": {"ip": "127.0.0.1", "port": 15040, "unit_ids": [1]},
        "authorized_sources": {},
        "unknown_sources": {"allow_reads": False},
        "protected_points": [],
        "enforcement": {"mode": "monitor"},
        "log": {"path": os.path.join(HERE, "unit_check_events.jsonl")},
        "active_response": {"enabled": True, "lockout_coil": 77, "trigger_decisions": ["BLOCK"],
                             "cooldown_seconds": 3, "timeout_s": 1.5},
    }
    for k, v in overrides.items():
        base[k].update(v) if isinstance(v, dict) and k in base else base.update({k: v})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(base, fh)
    return base


def fake_request(seq, decision="BLOCK", src_ip="10.0.0.99", dst_ip="127.0.0.1"):
    # dst_ip defaults to the mock PLC's IP used throughout this file (A-030 I-008 item 2: only
    # a REQUEST actually addressed to the configured PLC may trigger the lockout write).
    return {"seq": seq, "decision": decision, "event_type": "UNAUTHORIZED_CHANGE",
            "src_ip": src_ip, "dst_ip": dst_ip, "source_name": None,
            "summary": "FC5 Write Single Coil addr=0"}


def main():
    plc_port = 15040
    plc = subprocess.Popen([sys.executable, "-u", os.path.join(GUARDIAN_ROOT, "tools", "mock_plc.py"),
                            "--port", str(plc_port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
    time.sleep(1.5)

    # --- Part 1 & 2: success + cooldown ---------------------------------------------------
    cfg_path = os.path.join(HERE, "unit_check_config.json")
    log_path = os.path.join(HERE, "unit_check_events.jsonl")
    for p in (cfg_path, log_path):
        if os.path.exists(p):
            os.remove(p)
    write_config(cfg_path, plc={"ip": "127.0.0.1", "port": plc_port})
    cfg = Config(cfg_path)
    ev = EvidenceLog(log_path)

    responder = ActiveResponder(cfg, ev)
    check("active_response.active is True when enabled + int coil", responder.active)

    rec1 = responder.maybe_respond(fake_request(1))
    check("first BLOCK -> a record was written", rec1 is not None)
    check("first BLOCK -> outcome SUCCEEDED", rec1 and rec1.get("outcome") == "SUCCEEDED")

    rec2 = responder.maybe_respond(fake_request(2))
    check("second BLOCK inside cooldown -> a record was written", rec2 is not None)
    check("second BLOCK inside cooldown -> outcome SKIPPED_COOLDOWN",
          rec2 and rec2.get("outcome") == "SKIPPED_COOLDOWN")

    # Non-triggering decision must not fire at all.
    rec3 = responder.maybe_respond(fake_request(3, decision="ALLOW"))
    check("ALLOW decision -> no record (doesn't trigger)", rec3 is None)

    ev.close()
    ok, n, bad, msg = verify(log_path)
    check(f"evidence log chain intact after unit test ({msg})", ok)

    # Confirm the ACTIVE_RESPONSE record type, and that exactly one real PLC write happened.
    with open(log_path, encoding="utf-8") as fh:
        recs = [json.loads(l) for l in fh if l.strip()]
    ar_recs = [r for r in recs if r.get("record") == "ACTIVE_RESPONSE"]
    check("exactly 2 ACTIVE_RESPONSE records logged (1 succeeded + 1 skipped)", len(ar_recs) == 2)
    check("first ACTIVE_RESPONSE links to trigger seq 1", ar_recs and ar_recs[0].get("trigger_seq") == 1)

    time.sleep(0.3)
    plc.terminate()
    plc_out = plc.stdout.read() if plc.stdout else ""
    try:
        plc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        plc.kill()
    check("mock PLC actually received the lockout-coil write (coil 77 <- 1)",
          "coil 77 <- 1" in plc_out)
    print("---- mock PLC stdout ----")
    print(plc_out.strip())
    print("--------------------------")

    # --- Part 3: unreachable PLC must fail cleanly, not hang -------------------------------
    unreachable_cfg_path = os.path.join(HERE, "unit_check_config_unreachable.json")
    unreachable_log_path = os.path.join(HERE, "unit_check_events_unreachable.jsonl")
    for p in (unreachable_cfg_path, unreachable_log_path):
        if os.path.exists(p):
            os.remove(p)
    write_config(unreachable_cfg_path, plc={"ip": "127.0.0.1", "port": 1},  # nothing listens there
                 log={"path": unreachable_log_path})
    cfg2 = Config(unreachable_cfg_path)
    ev2 = EvidenceLog(unreachable_log_path)
    responder2 = ActiveResponder(cfg2, ev2)
    t0 = time.monotonic()
    rec_fail = responder2.maybe_respond(fake_request(1))
    elapsed = time.monotonic() - t0
    ev2.close()
    check("unreachable PLC -> outcome FAILED (not a crash)", rec_fail and rec_fail.get("outcome") == "FAILED")
    check(f"unreachable PLC -> returned promptly ({elapsed:.2f}s, bounded by timeout_s=1.5)",
          elapsed < 5)
    ok2, n2, bad2, msg2 = verify(unreachable_log_path)
    check(f"evidence log chain intact after failure case ({msg2})", ok2)

    # --- Part 4: fully inert when disabled --------------------------------------------------
    disabled_cfg_path = os.path.join(HERE, "unit_check_config_disabled.json")
    disabled_log_path = os.path.join(HERE, "unit_check_events_disabled.jsonl")
    for p in (disabled_cfg_path, disabled_log_path):
        if os.path.exists(p):
            os.remove(p)
    write_config(disabled_cfg_path, active_response={"enabled": False, "lockout_coil": 77,
                                                      "trigger_decisions": ["BLOCK"], "cooldown_seconds": 3},
                 log={"path": disabled_log_path})
    cfg3 = Config(disabled_cfg_path)
    ev3 = EvidenceLog(disabled_log_path)
    responder3 = ActiveResponder(cfg3, ev3)
    check("active_response.active is False when enabled=false", not responder3.active)
    rec_disabled = responder3.maybe_respond(fake_request(1))
    check("disabled feature -> maybe_respond returns None (no-op)", rec_disabled is None)
    ev3.close()
    check("disabled feature -> no evidence record written at all",
          os.path.getsize(disabled_log_path) == 0)

    print()
    print("ALL CHECKS PASSED" if PASS else "SOME CHECKS FAILED")
    sys.exit(0 if PASS else 1)


if __name__ == "__main__":
    main()
