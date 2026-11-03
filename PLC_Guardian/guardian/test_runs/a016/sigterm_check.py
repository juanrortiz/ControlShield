"""Repeatable check (A-016 defect 3): proxy must write SESSION_END when stopped by a signal.
Run: python sigterm_check.py   (from any dir; writes proxy_sigterm.jsonl next to this file)
Windows: true SIGTERM cannot be delivered to another process; CTRL_BREAK_EVENT (-> SIGBREAK) is used instead.
"""
import os, signal, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
G = os.path.join(HERE, "..", "..")
log = os.path.join(HERE, "proxy_sigterm.jsonl")
if os.path.exists(log):
    sys.exit(f"{log} exists; delete it or move it first")
flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
plc = subprocess.Popen([sys.executable, os.path.join(G, "tools", "mock_plc.py"), "--port", "25020"])
px = subprocess.Popen([sys.executable, os.path.join(G, "guardian.py"), "--log", log, "proxy",
                       "--listen", "127.0.0.1:25021", "--upstream", "127.0.0.1:25020"],
                      creationflags=flags, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    time.sleep(3)
    px.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
    out, _ = px.communicate(timeout=15)
finally:
    plc.kill()
print(out.strip()[-300:])
txt = open(log, encoding="utf-8").read().splitlines()
print("last record:", txt[-1][:120])
print("PASS" if '"SESSION_END"' in txt[-1] else "FAIL")
