"""Tamper-evident, append-only evidence log (JSON Lines + SHA-256 hash chain).

Every record carries `prev_hash` (hash of the previous record) and `hash`
(SHA-256 over prev_hash + the canonical JSON of this record without `hash`).
Editing, deleting or reordering any line breaks the chain from that point on,
which `verify()` reports. This makes tampering *evident*; it does not prevent it.
For stronger integrity, copy the log to write-once media or hash it into the
case notes at the end of each experiment.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import socket
import sys
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64


def _acquire_exclusive_lock(path: str):
    """Refuse to open a log file that's already open (by this or another process).

    Two independent EvidenceLog instances appending to the same path each keep their
    own in-memory seq/prev state; the first write from the second one lands with a
    prev_hash that doesn't match what the first one just wrote, splitting the hash
    chain with no error until the next `verify()` (D-008 architect review round 1,
    BLOCKER 1 -- found because httpgate.py's own log.path default was the same file
    proxy.py/monitor use). An OS-level exclusive lock, held for the life of the file
    handle and released automatically on close(), turns that into an immediate,
    obvious failure at startup instead of a silent chain break discovered later.

    D-008 round 2 should-fix 6: lock a tiny SIDECAR file (`path + ".lock"`), never the
    real log file's own bytes. Locking the real file on Windows is a mandatory
    OS-level lock that blocks even a read-only opener (e.g. `guardian.py verify` on a
    still-running log) -- avoidable, since nothing else needs to lock the real file.
    This also lets the caller take the lock BEFORE `verify()`/reading the last line,
    closing a narrow TOCTOU window where a second process's read could land mid-write
    or hit a lock conflict and surface as a raw, confusing PermissionError instead of
    this clean RuntimeError. Returns the open sidecar file handle (keep it referenced
    for the life of the EvidenceLog instance -- closing it releases the lock).
    """
    lock_path = path + ".lock"
    fh = open(lock_path, "a+")
    try:
        if sys.platform == "win32":
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        fh.close()
        raise RuntimeError(
            f"Evidence log {path} is already open by another Guardian process "
            f"(could not get an exclusive lock on {lock_path}: {e}). Two writers on "
            f"one log file corrupts the hash chain -- point this run at a different "
            f"--log path."
        ) from e
    return fh


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canon(rec: dict) -> str:
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), default=str)


def _digest(prev_hash: str, rec: dict) -> str:
    return hashlib.sha256((prev_hash + _canon(rec)).encode("utf-8")).hexdigest()


class EvidenceLog:
    def __init__(self, path: str):
        self.path = path
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        self._lock = threading.Lock()
        self._closed = False   # set under _lock by close(); write() checks it under the same
                                # lock (D-009 architect review round 2, BLOCKER 2 item 3) so a
                                # write racing a concurrent close() either lands cleanly before
                                # the file handle is closed or is refused with a clear error --
                                # never partially written to an already-closed handle.
        # D-008 round 2 should-fix 6: take the sidecar lock FIRST -- before anything else
        # (os.path.exists, verify(), reading the last line) touches the real log -- so a
        # concurrent second process is refused cleanly right here instead of racing this
        # one's verify()/read against its in-progress write.
        self._lock_fh = _acquire_exclusive_lock(path)
        try:
            self.seq, self.prev = 0, GENESIS
            if os.path.exists(path) and os.path.getsize(path) > 0:
                ok, n, bad, msg = verify(path)
                if not ok:
                    raise RuntimeError(f"Existing log {path} fails verification ({msg}). "
                                       f"Preserve it as evidence and start a new log file.")
                last = _last_line(path)
                rec = json.loads(last)
                self.seq, self.prev = rec["seq"], rec["hash"]
            self._fh = open(path, "a", encoding="utf-8", newline="\n")
        except Exception:
            self._lock_fh.close()
            raise

    def write(self, record: dict) -> dict:
        with self._lock:
            if self._closed:
                # Refuse cleanly rather than writing to (or crashing on) an already-closed file
                # handle -- a background sniffer thread (e.g. http_watch.py) can still be
                # mid-callback for a brief window after cmd_monitor's shutdown path calls
                # close(); without this check that write() would raise a bare
                # "ValueError: I/O operation on closed file" from inside os.fsync(), or worse,
                # interleave with a half-finished close(). The caller (active_response.py's
                # _log()) catches this and logs the loss loudly instead of crashing the thread.
                raise RuntimeError(f"EvidenceLog {self.path} is closed; refusing to write "
                                    f"record {record.get('record')!r} after close()")
            rec = dict(record)
            rec["seq"] = self.seq + 1
            rec["prev_hash"] = self.prev
            rec["hash"] = _digest(self.prev, rec)
            self._fh.write(_canon(rec) + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self.seq, self.prev = rec["seq"], rec["hash"]
            return rec

    def write_session_start(self, sensor: str, config_sha256: str, extra: dict | None = None) -> dict:
        import time
        rec = {
            "record": "SESSION_START",
            "ts_utc": utc_iso(time.time()),
            "ts_source": "host_clock",
            "sensor": sensor,
            "host": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "config_sha256": config_sha256,
        }
        if extra:
            rec.update(extra)
        return self.write(rec)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            try:
                self._fh.close()
            except Exception:
                pass
            try:
                self._lock_fh.close()   # releases the sidecar lock (D-008 round 2 should-fix 6)
            except Exception:
                pass


def _last_line(path: str) -> str:
    """Read only the tail of the file (records are well under 64 KiB each)."""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - 65536))
        lines = [ln for ln in fh.read().decode("utf-8", "replace").splitlines() if ln.strip()]
        return lines[-1]


def verify(path: str):
    """Return (ok, records_checked, first_bad_seq, message)."""
    prev, n = GENESIS, 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                return False, n, None, f"line {lineno}: not valid JSON"
            h = rec.pop("hash", None)
            if rec.get("prev_hash") != prev:
                return False, n, rec.get("seq"), f"line {lineno} (seq {rec.get('seq')}): prev_hash does not link to previous record"
            if rec.get("seq") != n + 1:
                return False, n, rec.get("seq"), f"line {lineno}: sequence gap (expected {n + 1}, got {rec.get('seq')})"
            if _digest(prev, rec) != h:
                return False, n, rec.get("seq"), f"line {lineno} (seq {rec.get('seq')}): content hash mismatch (record altered)"
            prev, n = h, n + 1
    return True, n, None, f"OK: {n} records, chain intact, head {prev[:16]}..."


CSV_FIELDS = ["seq", "record", "ts_utc", "ts_source", "sensor", "frame_no", "src_ip", "src_mac", "src_port",
              "dst_ip", "dst_port", "source_name", "tid", "unit", "fc", "fc_name", "category", "address",
              "quantity", "values", "summary", "event_type", "decision", "authorized", "action", "rules",
              "details", "outcome", "hash"]


def export_csv(path: str, out_path: str) -> int:
    n = 0
    with open(path, encoding="utf-8") as fh, open(out_path, "w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            for k in ("values", "rules", "details"):
                if isinstance(rec.get(k), list):
                    rec[k] = "; ".join(map(str, rec[k]))
            w.writerow(rec)
            n += 1
    return n
