"""Repeatable check (A-025 / I-006(3) residual): the A-023 fix wired SIGINT disarming into
cmd_proxy's outer `finally`, but left the FIRST Ctrl+C handled by asyncio.Runner's own default
SIGINT handling rather than the shared `_stop` handler SIGTERM/SIGBREAK already use. That left a
window open: a second Ctrl+C arriving before the outer `finally` runs -- while asyncio.Runner is
still unwinding the cancelled main task and a handle_client task could be mid
`evidence_log.write()` for a RESPONSE record -- could still raise KeyboardInterrupt at an
arbitrary point and corrupt the hash chain. double_sigint_check.py (A-023) does not catch this
because it fires both signals with no traffic in flight, so there's nothing for the second
signal to land on top of. This check keeps a client connection sending a steady stream of FC5
write requests (so evlog.write() is actively being called) and fires two SIGINT in quick
succession, then verifies: the proxy didn't hang, SESSION_END was written, and the hash chain
still verifies intact.

Run: python double_sigint_under_load_check.py          (single run)
     python double_sigint_under_load_check.py --loop 10 (repeat 10x, report pass rate -- timing
                                                          of the second signal relative to the
                                                          in-flight write is racy by nature)

Same in-process signal.raise_signal(SIGINT) approach as a023/double_sigint_check.py, and for the
same reason: see that file's docstring for why cross-process CTRL_C_EVENT is unsafe to use from
an automated harness on Windows.
"""
import argparse
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
G = os.path.join(HERE, "..", "..")
sys.path.insert(0, G)


def run_once(idx, listen_port, plc_port):
    log = os.path.join(HERE, f"proxy_double_sigint_load_{idx}.jsonl")
    if os.path.exists(log):
        os.remove(log)

    plc = subprocess.Popen([sys.executable, os.path.join(G, "tools", "mock_plc.py"), "--port", str(plc_port)])
    time.sleep(2)                                       # let the mock PLC come up

    stop_traffic = threading.Event()

    def _traffic():
        # A steady stream of FC5 (write single coil) requests against the proxy, so
        # evlog.write() for REQUEST/RESPONSE records is actively in progress when the
        # signals below arrive. Source is 127.0.0.1, not in authorized_sources, so these
        # are expected to be logged (and likely BLOCKed) rather than forwarded -- that's
        # fine, the point is the evlog.write() calls, not the enforcement outcome.
        try:
            s = socket.create_connection(("127.0.0.1", listen_port), timeout=5)
        except OSError:
            return
        tid = 0
        try:
            while not stop_traffic.is_set():
                tid = (tid + 1) & 0xFFFF
                pdu = bytes([5]) + struct.pack(">HH", 0, 0xFF00)
                frame = struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1) + pdu
                s.sendall(frame)
                try:
                    s.recv(256)
                except OSError:
                    break
        except OSError:
            pass
        finally:
            s.close()

    traffic_thread = threading.Thread(target=_traffic, daemon=True)

    def _fire():
        time.sleep(3)                      # let the proxy start and traffic get flowing
        traffic_thread.start()
        time.sleep(0.5)                    # make sure at least one write() has happened
        signal.raise_signal(signal.SIGINT)
        signal.raise_signal(signal.SIGINT)  # second one immediately, mid-shutdown, mid-traffic

    threading.Thread(target=_fire, daemon=True).start()

    t0 = time.monotonic()
    hung = False
    try:
        import guardian
        guardian.main(["--log", log, "proxy", "--listen", f"127.0.0.1:{listen_port}",
                       "--upstream", f"127.0.0.1:{plc_port}"])
    except SystemExit:
        pass
    finally:
        elapsed = time.monotonic() - t0
        stop_traffic.set()
        plc.kill()
        plc.wait(timeout=5)

    if elapsed > 20:                       # generous; a hang means it never returns, not just slow
        hung = True

    if not os.path.exists(log):
        return False, f"no log written (elapsed {elapsed:.1f}s, hung={hung})"
    txt = open(log, encoding="utf-8").read().splitlines()
    if not txt:
        return False, "log is empty"
    end_ok = '"SESSION_END"' in txt[-1]

    from plcguard.evidence_log import verify
    ok, _n, _bad_seq, msg = verify(log)

    detail = f"records={len(txt)} elapsed={elapsed:.1f}s hung={hung} session_end={end_ok} verify={msg}"
    return (end_ok and not hung and ok), detail


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", type=int, default=1, help="number of repeated runs")
    a = ap.parse_args()

    passes = 0
    for i in range(a.loop):
        ok, detail = run_once(i, 25040 + i * 2, 25041 + i * 2)
        print(f"run {i}: {'PASS' if ok else 'FAIL'} -- {detail}")
        if ok:
            passes += 1

    print(f"\n{passes}/{a.loop} passed")
    print("PASS" if passes == a.loop else "FAIL")
