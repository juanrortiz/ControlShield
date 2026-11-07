"""Repeatable check (A-016 round 2, items 2/11): a second SIGBREAK/SIGTERM sent right after the
first one, while SESSION_END/cleanup is still in flight, must not skip SESSION_END or corrupt the
evidence log's hash chain.
Run: python double_sigterm_check.py   (from any dir; writes proxy_double_sigterm.jsonl next to this file)
Windows: true SIGTERM cannot be delivered to another process; CTRL_BREAK_EVENT (-> SIGBREAK) is used.
"""
import os, signal, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
G = os.path.join(HERE, "..", "..")
log = os.path.join(HERE, "proxy_double_sigterm.jsonl")
if os.path.exists(log):
    sys.exit(f"{log} exists; delete it or move it first")
flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
plc = subprocess.Popen([sys.executable, os.path.join(G, "tools", "mock_plc.py"), "--port", "25022"])
px = subprocess.Popen([sys.executable, os.path.join(G, "guardian.py"), "--log", log, "proxy",
                       "--listen", "127.0.0.1:25023", "--upstream", "127.0.0.1:25022"],
                      creationflags=flags, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    time.sleep(3)
    sig = signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM
    px.send_signal(sig)
    px.send_signal(sig)         # fire a second one immediately; must be ignored, not corrupt the log
    out, _ = px.communicate(timeout=15)
finally:
    plc.kill()
print(out.strip()[-300:])
txt = open(log, encoding="utf-8").read().splitlines()
print("records:", len(txt))
print("last record:", txt[-1][:120])
end_ok = '"SESSION_END"' in txt[-1]
print("PASS" if end_ok else "FAIL (no SESSION_END)")
