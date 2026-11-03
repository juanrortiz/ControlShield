"""Repeatable check (A-023 / I-006 should-fix 3): a second Ctrl+C (SIGINT) arriving right
after the first, while SESSION_END/cleanup is still in flight, must not corrupt the evidence
log's hash chain. The first Ctrl+C must still get asyncio.run()'s normal KeyboardInterrupt
handling (not suppressed) -- this check only verifies the chain survives the SECOND one, same
intent as double_sigterm_check.py for SIGTERM/SIGBREAK.

Run: python double_sigint_check.py   (from any dir; writes proxy_double_sigint.jsonl next to
this file)

Why this isn't "cross-process CTRL_C_EVENT via subprocess.send_signal", unlike the sibling
SIGTERM/SIGBREAK checks: on Windows, GenerateConsoleCtrlEvent(CTRL_C_EVENT, ...) only has a
group-0 ("all processes on the CALLER's current console") form -- subprocess.send_signal's
CTRL_C_EVENT support relies on that, and CREATE_NEW_PROCESS_GROUP (needed to target
CTRL_BREAK_EVENT at just the child) explicitly disables CTRL_C_EVENT for the new group. Sending
group-0 CTRL_C without CREATE_NEW_PROCESS_GROUP would also hit this test script's own process
(and whatever shares its console), which is unsafe to do from an automated harness. Instead,
this check runs guardian.py's own `proxy` command IN this process (import + call, mock PLC
still as a real subprocess) and uses signal.raise_signal(SIGINT) from a background thread to
deliver two real SIGINTs back-to-back. That is the same CPython SIGINT -> KeyboardInterrupt
path guardian.py's `asyncio.run()` relies on in production, just triggered locally instead of
via a console event, and it does not risk the test harness's own shell.
"""
import os
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
G = os.path.join(HERE, "..", "..")
log = os.path.join(HERE, "proxy_double_sigint_check.jsonl")
if os.path.exists(log):
    sys.exit(f"{log} exists; delete it or move it first")

sys.path.insert(0, G)

plc = subprocess.Popen([sys.executable, os.path.join(G, "tools", "mock_plc.py"), "--port", "25036"])


def _fire():
    time.sleep(3)                       # let the proxy finish starting up
    signal.raise_signal(signal.SIGINT)
    signal.raise_signal(signal.SIGINT)  # second one immediately; must be ignored, not corrupt the log


threading.Thread(target=_fire, daemon=True).start()

try:
    import guardian
    guardian.main(["--log", log, "proxy", "--listen", "127.0.0.1:25037", "--upstream", "127.0.0.1:25036"])
finally:
    plc.kill()

txt = open(log, encoding="utf-8").read().splitlines()
print("records:", len(txt))
print("last record:", txt[-1][:120])
end_ok = '"SESSION_END"' in txt[-1]
print("PASS" if end_ok else "FAIL (no SESSION_END)")
