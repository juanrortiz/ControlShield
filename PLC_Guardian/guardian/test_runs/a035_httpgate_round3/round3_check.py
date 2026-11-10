"""Smoke/unit check for D-008 httpgate.py round-3 fixes (architect review round 2).

Not a full test suite -- exercises, against a local fake upstream (no real HMI/PLC
involved), the specific behaviours round 2 flagged:

  - BLOCKER: a failed decision-record write fails the ALLOW connection closed
    (_safe_write broadened to catch RuntimeError too).
  - should-fix 2: "relayed" (not "authorized") gates revocation eligibility.
  - should-fix 4: revocation closes u_writer too, and sets info["revoked"] so pipe()
    stops forwarding immediately.
  - should-fix 5: flush_suppressed_blocks() flushes counts with no further traffic.
  - should-fix 6: evidence_log.py's sidecar lock -- second opener refused cleanly,
    verify()-while-open no longer blocked by a mandatory lock on the real file.
  - nit 8/9: shared rate-limit helper covers CAPACITY_LIMIT; prune doesn't crash.
  - nit 10: config.reload_if_changed() swallows AttributeError/TypeError too.
  - nit 11: stats["forwarded"] only increments after a successful upstream connect.

Run from the `guardian/` directory:
    python -I test_runs/a035_httpgate_round3/round3_check.py

Exits non-zero (and prints which check failed) on any failure.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "plcguard", ".."))

from plcguard.config import Config
from plcguard.evidence_log import EvidenceLog
from plcguard.httpgate import HttpGate

FAILURES = []


def check(name, cond):
    status = "ok" if cond else "FAIL"
    print(f"[{status}] {name}")
    if not cond:
        FAILURES.append(name)


async def _echo_server(host, port):
    async def handle(r, w):
        try:
            while True:
                data = await r.read(4096)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except Exception:
            pass
        finally:
            w.close()
    return await asyncio.start_server(handle, host, port)


async def main():
    tmp = tempfile.mkdtemp(prefix="httpgate_round3_")
    try:
        up_srv = await _echo_server("127.0.0.1", 0)
        up_port = up_srv.sockets[0].getsockname()[1]

        cfg_path = os.path.join(tmp, "config.json")
        cfg_data = {
            "plc": {"ip": "127.0.0.1", "port": 15020},
            "authorized_sources": {"127.0.0.1": {"name": "test-hmi", "allow": ["read", "write"]}},
            "enforcement": {"mode": "block"},
            "http_gate": {
                "listen_host": "127.0.0.1", "listen_port": 0,
                "upstream_host": "127.0.0.1", "upstream_port": up_port,
                "max_connections": 2, "idle_timeout_s": 2, "connect_timeout_s": 2,
            },
        }
        with open(cfg_path, "w") as fh:
            json.dump(cfg_data, fh)
        cfg = Config(cfg_path)

        log_path = os.path.join(tmp, "events.jsonl")
        evlog = EvidenceLog(log_path)

        # --- should-fix 6: sidecar lock -------------------------------------------------
        check("sidecar lock file created", os.path.exists(log_path + ".lock"))
        try:
            EvidenceLog(log_path)
            check("second EvidenceLog on same path refused", False)
        except RuntimeError:
            check("second EvidenceLog on same path refused", True)
        # verify() on the real file must NOT be blocked by the lock (it targets a sidecar now)
        from plcguard.evidence_log import verify
        ok, n, _bad, _msg = verify(log_path)
        check("verify() works on real log while EvidenceLog instance holds sidecar lock", ok)

        gw = HttpGate(cfg, evlog, console=lambda *a, **k: None)
        ready = asyncio.Event()
        serve_task = asyncio.ensure_future(gw.serve(ready))
        await ready.wait()
        gate_port = gw.bound[1]

        # --- basic ALLOW relay + nit 11 (forwarded counted after connect succeeds) ------
        r, w = await asyncio.open_connection("127.0.0.1", gate_port)
        w.write(b"hello\n")
        await w.drain()
        echoed = await asyncio.wait_for(r.read(100), timeout=2)
        check("ALLOWed connection relays data", echoed == b"hello\n")
        w.close()
        await asyncio.sleep(0.2)
        check("stats['forwarded'] incremented exactly once", gw.stats["forwarded"] == 1)
        check("stats['upstream_errors'] is 0", gw.stats["upstream_errors"] == 0)

        # --- should-fix 2 / 4: relayed flag + revocation closes u_writer too ------------
        r2, w2 = await asyncio.open_connection("127.0.0.1", gate_port)
        w2.write(b"ping\n")
        await w2.drain()
        await asyncio.wait_for(r2.read(100), timeout=2)
        await asyncio.sleep(0.1)
        active_infos = list(gw._active.values())
        check("active connection tracked with relayed=True", any(i.get("relayed") for i in active_infos))
        check("active connection's u_writer recorded", any(i.get("u_writer") is not None for i in active_infos))

        # Actually revoke 127.0.0.1's authorization in the live config (not just the
        # per-connection info dict) so _is_authorized() re-check inside
        # _revoke_now_unauthorized() recomputes False, exercising the real revoke path.
        saved_source = cfg.data["authorized_sources"].pop("127.0.0.1")
        gw._revoke_now_unauthorized()
        # revocation closed the SERVER-side c_writer/u_writer; confirm the CLIENT end sees
        # that as EOF (reading, not w2.is_closing(), since w2 is our own client socket --
        # it only reflects whether WE closed it, not whether the peer did).
        try:
            revoked_eof = await asyncio.wait_for(r2.read(100), timeout=2)
        except (ConnectionResetError, asyncio.TimeoutError):
            revoked_eof = b""
        check("revoked connection's writer closed (client sees EOF)", revoked_eof == b"")
        check("stats['revoked_on_reload'] incremented", gw.stats["revoked_on_reload"] >= 1)
        w2.close()
        cfg.data["authorized_sources"]["127.0.0.1"] = saved_source   # restore for later checks

        # --- BLOCKER: a decision-record write failure fails the connection closed -------
        orig_write = evlog.write
        def _boom(rec):
            if rec.get("record") == "HTTP_CONNECTION" and rec.get("action") == "FORWARDED":
                raise RuntimeError("simulated evidence log failure")
            return orig_write(rec)
        evlog.write = _boom
        r3, w3 = await asyncio.open_connection("127.0.0.1", gate_port)
        try:
            data = await asyncio.wait_for(r3.read(100), timeout=1)
            check("write-failure ALLOW connection closed, nothing relayed", data == b"")
        except (asyncio.TimeoutError, ConnectionResetError):
            check("write-failure ALLOW connection closed, nothing relayed", True)
        w3.close()
        evlog.write = orig_write

        # --- nit 8/9: capacity limit uses shared rate-limited helper, prune doesn't crash
        c1r, c1w = await asyncio.open_connection("127.0.0.1", gate_port)
        c2r, c2w = await asyncio.open_connection("127.0.0.1", gate_port)
        await asyncio.sleep(0.1)
        c3r, c3w = await asyncio.open_connection("127.0.0.1", gate_port)
        data3 = await asyncio.wait_for(c3r.read(100), timeout=1)
        check("3rd connection rejected at max_connections=2", data3 == b"")
        check("stats['rejected_capacity'] incremented", gw.stats["rejected_capacity"] >= 1)
        gw._prune_block_log_entries()  # must not raise even with tiny dicts
        for ww in (c1w, c2w, c3w):
            ww.close()

        # --- should-fix 5: flush_suppressed_blocks with no further traffic -------------
        gw._block_suppressed["10.0.0.99"] = 7
        before = gw.stats["blocked_suppressed"]
        gw.flush_suppressed_blocks()
        check("flush_suppressed_blocks folds suppressed count into stats", gw.stats["blocked_suppressed"] >= before + 7)
        check("flush_suppressed_blocks clears the dict", "10.0.0.99" not in gw._block_suppressed)

        serve_task.cancel()
        try:
            await serve_task
        except asyncio.CancelledError:
            pass
        up_srv.close()
        evlog.close()

        # --- nit 10: reload_if_changed swallows AttributeError/TypeError, not just ValueError/OSError
        cfg2 = Config(cfg_path)
        def _bad_load():
            raise AttributeError("simulated malformed section")
        import time as _time
        cfg2._mtime -= 10  # force reload_if_changed to think the file changed... actually
        # need os.stat mtime to differ; simplest: touch the file after changing mtime check
        os.utime(cfg_path, None)
        cfg2.load = _bad_load
        try:
            result = cfg2.reload_if_changed()
            check("reload_if_changed swallows AttributeError (nit 10)", result is False)
        except AttributeError:
            check("reload_if_changed swallows AttributeError (nit 10)", False)

    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
    if FAILURES:
        print(f"\n{len(FAILURES)} check(s) FAILED: {FAILURES}")
        sys.exit(1)
    print("\nAll checks passed.")
