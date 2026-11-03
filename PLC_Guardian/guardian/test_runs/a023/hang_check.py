"""Repeatable check (A-023 / I-006 should-fix 1): proxy must not hang on shutdown when a
client (simulating a live HMI) is still connected. On Python 3.12.1+, Server.wait_closed()
blocks until every open client connection closes too; `async with server: await
server.serve_forever()` relies on that implicitly in its __aexit__. This check keeps a raw
socket connected to the proxy's listen port, sends SIGTERM/SIGBREAK, and times how long the
proxy process takes to exit -- it must be a few seconds, not a hang.
Run: python hang_check.py   (from any dir; writes proxy_hang.jsonl next to this file)
Windows: true SIGTERM cannot be delivered to another process; CTRL_BREAK_EVENT (-> SIGBREAK)
is used instead.
"""
import os, signal, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
G = os.path.join(HERE, "..", "..")
log = os.path.join(HERE, "proxy_hang.jsonl")
if os.path.exists(log):
    sys.exit(f"{log} exists; delete it or move it first")

flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
plc = subprocess.Popen([sys.executable, os.path.join(G, "tools", "mock_plc.py"), "--port", "25030"])
px = subprocess.Popen([sys.executable, os.path.join(G, "guardian.py"), "--log", log, "proxy",
                       "--listen", "127.0.0.1:25031", "--upstream", "127.0.0.1:25030"],
                      creationflags=flags, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
TIMEOUT_S = 10   # generous; a hang means it never returns at all, not that it's merely slow
hmi = None
try:
    time.sleep(3)                                   # let the proxy and mock PLC come up
    hmi = socket.create_connection(("127.0.0.1", 25031), timeout=5)   # simulated live HMI, left open
    time.sleep(1)                                    # make sure the connection is accepted/tracked
    t0 = time.monotonic()
    px.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
    try:
        out, _ = px.communicate(timeout=TIMEOUT_S)
        elapsed = time.monotonic() - t0
        hung = False
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - t0
        hung = True
        px.kill()
        out, _ = px.communicate()
finally:
    if hmi:
        hmi.close()
    plc.kill()

print(out.strip()[-300:])
print(f"shutdown took {elapsed:.1f}s (limit {TIMEOUT_S}s)")
if hung:
    print("FAIL (proxy hung with a live client connection)")
    sys.exit(1)

txt = open(log, encoding="utf-8").read().splitlines()
print("last record:", txt[-1][:120])
end_ok = '"SESSION_END"' in txt[-1]
print("PASS" if end_ok and not hung else "FAIL")
