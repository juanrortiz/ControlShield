"""Full-stack check for A-028: `guardian.py monitor` (live scapy sniff, not a direct module
call) seeing a real attacker frame on the wire and firing active response through it.

This DOES exercise live packet sniffing: Npcap exposes a loopback adapter on this host
(`\\Device\\NPF_Loopback`, confirmed present via scapy's get_if_list()), and a quick probe
showed scapy's sniff() does see 127.0.0.1 TCP traffic through it in this environment, so the
usual "scapy can't see loopback on Windows" caveat does not apply here -- this is genuine
live-sniff coverage, not the direct-module fallback (see active_response_unit_check.py for
that level). localhost / mock_plc.py only, never a real network address.

Sequence:
  1. Start tools/mock_plc.py on a local port (stands in for the PLC -- both the traffic
     Guardian is watching and the lockout write land on it).
  2. Start `guardian.py monitor --iface \\Device\\NPF_Loopback` as a subprocess against a
     test config.json with active_response enabled and authorized_sources empty (so any
     write is BLOCK via SRC_NOT_ALLOWLISTED).
  3. Send one FC5 "attacker" write directly to the mock PLC (NOT through Guardian -- monitor
     mode is passive, it only watches).
  4. Confirm: an ACTIVE_RESPONSE record appears in the evidence log, the mock PLC's own
     stdout shows it actually received the lockout-coil write, and `guardian.py verify`
     reports the chain intact.

The monitor subprocess is stopped with terminate() (process kill), not Ctrl+C, because
scapy's blocking sniff() has no CLI-exposed timeout; this only forgoes the SESSION_END
record (verify() does not require one), not integrity of the records already fsync'd.

Run: python test_runs/a028/live_monitor_integration_check.py
"""
import json
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GUARDIAN_ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, GUARDIAN_ROOT)

LOOPBACK_IFACE = r"\Device\NPF_Loopback"
PLC_PORT = 15041
LOCKOUT_COIL = 88

PASS = True


def check(label, cond):
    global PASS
    print(f"{'PASS' if cond else 'FAIL'}: {label}")
    if not cond:
        PASS = False


ATTACKER_SRC = "127.0.0.2"   # distinct from 127.0.0.1 (what Guardian's own lockout write uses
                             # as its source on this box) so A-030's own-IP self-trigger guard in
                             # active_response.py has something real to tell apart from the
                             # "attacker" -- Windows treats all of 127.0.0.0/8 as loopback, no
                             # extra interface config needed (confirmed in this environment).


def send_fc5_write(host, port, addr, timeout=3.0):
    """Unauthorized-looking FC5 write, same wire layout as tools/modbus_client.py, sent from
    ATTACKER_SRC rather than the default 127.0.0.1 outbound address."""
    pdu = struct.pack(">BHH", 5, addr, 0xFF00)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.bind((ATTACKER_SRC, 0))
        s.connect((host, port))
        s.sendall(struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu)
        s.recv(256)
    finally:
        s.close()


def main():
    cfg_path = os.path.join(HERE, "live_check_config.json")
    log_path = os.path.join(HERE, "live_check_events.jsonl")
    mon_stdout_path = os.path.join(HERE, "live_check_monitor_stdout.txt")
    for p in (cfg_path, log_path, mon_stdout_path):
        if os.path.exists(p):
            os.remove(p)

    cfg = {
        "plc": {"ip": "127.0.0.1", "port": PLC_PORT, "unit_ids": [1]},
        "authorized_sources": {},                       # nothing authorized -> any write is BLOCK
        "unknown_sources": {"allow_reads": False},
        "protected_points": [],
        "enforcement": {"mode": "monitor"},
        "log": {"path": log_path, "log_allowed_reads": False},
        "active_response": {"enabled": True, "lockout_coil": LOCKOUT_COIL,
                             "trigger_decisions": ["BLOCK"], "cooldown_seconds": 5, "timeout_s": 2},
    }
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)

    plc = subprocess.Popen([sys.executable, "-u", os.path.join(GUARDIAN_ROOT, "tools", "mock_plc.py"),
                            "--port", str(PLC_PORT)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
    time.sleep(1.5)

    mon_out = open(mon_stdout_path, "w", encoding="utf-8")
    monitor = subprocess.Popen(
        [sys.executable, os.path.join(GUARDIAN_ROOT, "guardian.py"),
         "--config", cfg_path, "--log", log_path, "monitor", "--iface", LOOPBACK_IFACE],
        stdout=mon_out, stderr=subprocess.STDOUT, cwd=GUARDIAN_ROOT)
    time.sleep(3)   # let scapy's sniff() attach to the loopback adapter before traffic starts

    try:
        send_fc5_write("127.0.0.1", PLC_PORT, 0)
        time.sleep(3)   # give the analyzer + ActiveResponder time to process and fire
    finally:
        monitor.terminate()
        try:
            monitor.wait(timeout=10)
        except subprocess.TimeoutExpired:
            monitor.kill()
        plc.terminate()
        plc_out = plc.stdout.read() if plc.stdout else ""
        try:
            plc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            plc.kill()
    mon_out.close()

    with open(mon_stdout_path, encoding="utf-8") as fh:
        mon_text = fh.read()
    print("---- guardian.py monitor stdout ----")
    print(mon_text.strip())
    print("---- mock PLC stdout ----")
    print(plc_out.strip())
    print("-------------------------------------")

    check("evidence log file was created", os.path.exists(log_path) and os.path.getsize(log_path) > 0)
    recs = []
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8") as fh:
            recs = [json.loads(l) for l in fh if l.strip()]
    req_recs = [r for r in recs if r.get("record") == "REQUEST"]
    ar_recs = [r for r in recs if r.get("record") == "ACTIVE_RESPONSE"]
    check("live sniff saw the attacker's FC5 frame and logged a REQUEST", len(req_recs) >= 1)
    check("that REQUEST was decided BLOCK", req_recs and req_recs[0].get("decision") == "BLOCK")
    check("an ACTIVE_RESPONSE record was written", len(ar_recs) >= 1)
    check("ACTIVE_RESPONSE outcome is SUCCEEDED", ar_recs and ar_recs[0].get("outcome") == "SUCCEEDED")
    if ar_recs and req_recs:
        check("ACTIVE_RESPONSE links to the triggering REQUEST's seq",
              ar_recs[0].get("trigger_seq") == req_recs[0].get("seq"))
    check(f"mock PLC actually received the lockout write (coil {LOCKOUT_COIL} <- 1)",
          f"coil {LOCKOUT_COIL} <- 1" in plc_out)

    # Chain check via the actual CLI, per the brief.
    verify_out = subprocess.run([sys.executable, os.path.join(GUARDIAN_ROOT, "guardian.py"),
                                 "verify", log_path], capture_output=True, text=True, cwd=GUARDIAN_ROOT)
    print("---- guardian.py verify ----")
    print(verify_out.stdout.strip())
    check("guardian.py verify reports PASS", verify_out.stdout.strip().startswith("PASS") and verify_out.returncode == 0)

    print()
    print("ALL CHECKS PASSED" if PASS else "SOME CHECKS FAILED")
    sys.exit(0 if PASS else 1)


if __name__ == "__main__":
    main()
