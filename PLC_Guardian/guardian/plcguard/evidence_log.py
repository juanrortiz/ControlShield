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
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64


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

    def write(self, record: dict) -> dict:
        with self._lock:
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
        try:
            self._fh.close()
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
