#!/usr/bin/env python3
"""
plc_blackbox.py -- black-box PLC recon for PLC Guardian Experiment 5.

Adapted from a black-box discovery/inference tool. Differences from a gray-box
run (Experiments 3/4): this script is given nothing about the register map,
%M4, %MW0, unit IDs, or which addresses matter. It starts from only an IP and
finds out what it can from the wire, the same way an attacker with no prior
knowledge of this PLC would.

READ-ONLY by design: no FC5/FC6/FC15/FC16/FC23 write is ever sent. Discovery
uses nmap (not a hand-rolled port scan) so the recon step matches a real
attacker's tool, per team decision. Run this only against the lab PLC on the
isolated lab network (project-log/03_DECISIONS.md, CLAUDE.md evidence rules).

Pinned to pymodbus==3.16 API (keyword `count=`, no `slave=` -- see
project-log/06_REFERENCE.md "Known traps"). Re-check signatures if pymodbus
is upgraded.

SECTIONS (search for these headers):
  SECTION 1: NMAP DISCOVERY   -- shell out to `nmap --script modbus-discover`
  SECTION 2: ENUMERATION      -- sweep the four Modbus address spaces, all
                                  live unit IDs (no assumption of unit 1)
  SECTION 3: INFERENCE        -- poll over time, classify behavior, find
                                  packed 32-bit floats, find correlated pairs
  SECTION 4: PIPELINE         -- ties 1-3 together, writes a Markdown report
  SECTION 5: CLI / MAIN

USAGE
-----
    python plc_blackbox.py --host 192.168.8.11 --units 1 255 -o OUTDIR

Methodology notes worth citing in the report (see run_pipeline() and the
original tool this was adapted from):
  - Polling many addresses per cycle can alias a fast-toggling bit (classic
    Nyquist problem).
  - Plain Pearson correlation over a short window can flag two unrelated but
    simultaneously-trending signals as "correlated". Treat it as a lead, not
    proof.
  - The float-pair scanner checks every adjacent offset, including
    misaligned ones, since true alignment isn't known black-box.
  - This script tries EVERY unit ID given (not just 1), because a black-box
    attacker does not know the M221 answers on 255 as well as 1
    (06_REFERENCE.md).
"""
import argparse
import json
import math
import os
import shutil
import struct
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from pymodbus.client import ModbusTcpClient


# ============================================================================
# SECTION 1: NMAP DISCOVERY
# ============================================================================
# A real black-box attacker scans with nmap, not a hand-rolled socket probe.
# We shell out to the actual tool rather than reimplementing it.

ICS_PORTS = "102,502,789,1911,2404,4840,20000,44818"


def run_nmap(host: str, out_dir: str) -> dict:
    """Run nmap's service scan + the modbus-discover NSE script against host.

    Returns {"ok": bool, "raw_path": str|None, "summary": str}. Never raises
    on a missing nmap binary or a failed scan -- the caller should still be
    able to proceed (and report nmap's absence as a finding, since a real
    attacker would have it).
    """
    nmap = shutil.which("nmap")
    result = {"ok": False, "raw_path": None, "summary": ""}
    if not nmap:
        result["summary"] = "nmap not found on PATH -- NOT RUN. Install nmap to run this stage for real."
        return result

    raw_path = os.path.join(out_dir, "nmap_raw.txt")
    cmd = [nmap, "-Pn", "-p", ICS_PORTS, "--script", "modbus-discover,banner",
           "-oN", raw_path, host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        result["summary"] = "nmap timed out after 120s -- NOT RUN."
        return result
    except Exception as exc:  # noqa: BLE001 -- recon code, report don't crash
        result["summary"] = f"nmap failed to run: {exc!r}"
        return result

    result["raw_path"] = raw_path
    result["ok"] = proc.returncode == 0
    result["summary"] = proc.stdout.strip() or proc.stderr.strip()
    return result


# ============================================================================
# SECTION 2: ENUMERATION
# ============================================================================
# With no register map, find out what's there by probing each of the four
# Modbus address spaces one address at a time, for every unit ID we're told
# to try (a black-box attacker doesn't know in advance that the M221 answers
# on 255, not just the default 1 -- 06_REFERENCE.md).

SPACES = {
    "coils": "read_coils",
    "discrete_inputs": "read_discrete_inputs",
    "holding_registers": "read_holding_registers",
    "input_registers": "read_input_registers",
}


def fingerprint_read_device_id(client: ModbusTcpClient, unit: int) -> dict:
    """FC 0x2B read-device-identification, a read, not a write. Many PLCs
    (including possibly the M221 -- UNVERIFIED) don't implement it; a refusal
    is itself a data point, not a crash."""
    try:
        resp = client.read_device_information(read_code=1, device_id=unit)
        if resp.isError():
            return {"supported": False, "detail": str(resp)}
        info = {(k.decode() if isinstance(k, bytes) else k):
                 (v.decode() if isinstance(v, bytes) else v)
                 for k, v in resp.information.items()}
        return {"supported": True, "info": info}
    except Exception as exc:  # noqa: BLE001
        return {"supported": False, "detail": f"exception: {exc!r}"}


def sweep_space(client: ModbusTcpClient, method_name: str, start: int, end: int,
                 unit: int) -> dict:
    method = getattr(client, method_name)
    live = {}
    for addr in range(start, end):
        try:
            resp = method(address=addr, count=1, device_id=unit)
        except TypeError:
            # pymodbus < 3.16 used `slave=` instead of `device_id=`.
            resp = method(address=addr, count=1, slave=unit)
        if not resp.isError():
            value = resp.bits[0] if hasattr(resp, "bits") else resp.registers[0]
            live[addr] = value
    return live


def enumerate_device(host: str, port: int, unit: int, start: int, end: int) -> dict:
    client = ModbusTcpClient(host, port=port)
    if not client.connect():
        return {"error": "could not connect"}
    report = {}
    try:
        for space_name, method_name in SPACES.items():
            report[space_name] = sweep_space(client, method_name, start, end, unit)
    finally:
        client.close()
    return report


# ============================================================================
# SECTION 3: INFERENCE
# ============================================================================
# Poll every live address over time and classify it from its behavior.
# READ ONLY -- no write is ever sent anywhere in this file.

_INFER_SPACES = {
    "coils": ("read_coils", True),
    "discrete_inputs": ("read_discrete_inputs", True),
    "holding_registers": ("read_holding_registers", False),
    "input_registers": ("read_input_registers", False),
}


def poll_live_addresses(host: str, port: int, unit: int, live_map: dict,
                         samples: int = 20, interval: float = 0.3) -> dict:
    client = ModbusTcpClient(host, port=port)
    if not client.connect():
        raise ConnectionError(f"could not connect to {host}:{port}")

    series = {space: {addr: [] for addr in addrs} for space, addrs in live_map.items()}
    try:
        for _ in range(samples):
            for space, (method_name, is_bool) in _INFER_SPACES.items():
                if space not in live_map:
                    continue
                method = getattr(client, method_name)
                for addr in live_map[space]:
                    try:
                        resp = method(address=addr, count=1, device_id=unit)
                    except TypeError:
                        resp = method(address=addr, count=1, slave=unit)
                    if not resp.isError():
                        val = resp.bits[0] if is_bool else resp.registers[0]
                        series[space][addr].append(val)
            time.sleep(interval)
    finally:
        client.close()
    return series


def classify_boolean(values: list) -> str:
    if len(set(values)) == 1:
        return "static (always same value)"
    toggles = sum(1 for a, b in zip(values, values[1:]) if a != b)
    toggle_rate = toggles / max(1, len(values) - 1)
    if toggle_rate > 0.8:
        return "fast-toggling -> likely heartbeat/watchdog bit"
    return "changes occasionally -> likely status/alarm bit"


def classify_numeric(values: list) -> str:
    if len(set(values)) == 1:
        return "static -> likely configuration / setpoint"
    deltas = [abs(b - a) for a, b in zip(values, values[1:])]
    avg_delta = sum(deltas) / len(deltas)
    value_range = max(values) - min(values)
    if value_range == 0:
        return "static -> likely configuration / setpoint"
    smoothness = avg_delta / max(1, value_range)
    if smoothness < 0.35:
        return "smooth, bounded drift -> likely analog process variable (sensor)"
    return "erratic jumps -> maybe raw bits of a multi-register value, or noisy signal"


def try_decode_float_pairs(series: dict) -> dict:
    """Test every adjacent register-address pair as a packed big-endian
    32-bit float; flag ones that look physically plausible and nontrivial."""
    findings = {}
    for space in ("holding_registers", "input_registers"):
        if space not in series:
            continue
        addrs = sorted(series[space].keys())
        for a, b in zip(addrs, addrs[1:]):
            if b != a + 1:
                continue
            hi_vals = series[space][a]
            lo_vals = series[space][b]
            if len(hi_vals) != len(lo_vals) or not hi_vals:
                continue
            floats = []
            ok = True
            for hi, lo in zip(hi_vals, lo_vals):
                try:
                    raw = struct.pack(">HH", hi, lo)
                    f = struct.unpack(">f", raw)[0]
                except struct.error:
                    ok = False
                    break
                if f != f or abs(f) > 1e6:  # NaN or implausibly large
                    ok = False
                    break
                floats.append(f)
            if not ok or all(f == 0.0 for f in floats):
                continue
            deltas = [abs(y - x) for x, y in zip(floats, floats[1:])]
            avg_delta = sum(deltas) / max(1, len(deltas))
            value_range = max(floats) - min(floats) or 1.0
            smoothness = avg_delta / value_range
            if smoothness < 0.4:
                findings[f"{space}[{a}:{b}]"] = {
                    "decoded_values": [round(f, 3) for f in floats],
                    "verdict": "plausible packed 32-bit float (big-endian)",
                }
    return findings


def _flatten_series(series: dict) -> dict:
    flat = {}
    for space, addrs in series.items():
        for addr, values in addrs.items():
            flat[f"{space}[{addr}]"] = [float(v) for v in values]
    return flat


def pearson(x: list, y: list) -> float:
    n = len(x)
    if n < 2:
        return 0.0
    mean_x, mean_y = sum(x) / n, sum(y) / n
    cov = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))
    var_x = sum((xi - mean_x) ** 2 for xi in x)
    var_y = sum((yi - mean_y) ** 2 for yi in y)
    denom = (var_x * var_y) ** 0.5
    return cov / denom if denom else 0.0


def find_correlations(series: dict, threshold: float = 0.7) -> list:
    flat = _flatten_series(series)
    labels = list(flat.keys())
    results = []
    for i in range(len(labels)):
        for j in range(i + 1, len(labels)):
            a, b = labels[i], labels[j]
            if len(set(flat[a])) == 1 or len(set(flat[b])) == 1:
                continue
            r = pearson(flat[a], flat[b])
            if abs(r) >= threshold:
                results.append((a, b, round(r, 3)))
    return sorted(results, key=lambda t: -abs(t[2]))


def build_behavior_report(series: dict) -> dict:
    report = {"classifications": {}, "packed_float_candidates": {}, "correlations": []}
    for space, addrs in series.items():
        is_bool = _INFER_SPACES[space][1]
        for addr, values in addrs.items():
            label = f"{space}[{addr}]"
            if not values:
                report["classifications"][label] = "no data (device stopped responding)"
                continue
            report["classifications"][label] = (
                classify_boolean(values) if is_bool else classify_numeric(values)
            )
    report["packed_float_candidates"] = try_decode_float_pairs(series)
    report["correlations"] = find_correlations(series)
    return report


# ============================================================================
# SECTION 4: PIPELINE
# ============================================================================

def run_pipeline(host: str, port: int, units: list, address_range: tuple,
                  samples: int, interval: float, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    result = {"host": host, "port": port, "units_tried": units, "per_unit": {}}

    print(f"\n{'=' * 60}\nSTEP 1: nmap discovery (port {port} and common ICS ports)\n{'=' * 60}")
    nmap_result = run_nmap(host, out_dir)
    print(nmap_result["summary"] or "(no output)")
    result["nmap"] = nmap_result

    for unit in units:
        print(f"\n{'=' * 60}\nUnit ID {unit}\n{'=' * 60}")
        udata = {}

        print(f"\nSTEP 2: FC 0x2B device identification (unit {unit})")
        client = ModbusTcpClient(host, port=port)
        if client.connect():
            udata["device_identification"] = fingerprint_read_device_id(client, unit)
            client.close()
        else:
            udata["device_identification"] = {"supported": False, "detail": "could not connect"}
        print(json.dumps(udata["device_identification"], indent=2))

        print(f"\nSTEP 3: Enumeration (range {address_range}, unit {unit})")
        live = enumerate_device(host, port, unit, address_range[0], address_range[1])
        udata["live_addresses"] = live
        total_live = sum(len(v) for v in live.values()) if "error" not in live else 0
        for space, values in live.items() if "error" not in live else []:
            print(f"  {space}: {len(values)} live address(es) -> {sorted(values.keys())}")
        if "error" in live or total_live == 0:
            print(f"  No live addresses on unit {unit} in this range.")
            result["per_unit"][unit] = udata
            continue

        print(f"\nSTEP 4: Behavioral inference ({samples} samples, {interval}s apart, unit {unit})")
        series = poll_live_addresses(host, port, unit, live, samples=samples, interval=interval)
        behavior = build_behavior_report(series)
        udata["behavior_report"] = behavior

        print("\n-- Classifications --")
        for label, verdict in behavior["classifications"].items():
            print(f"  {label:<28} {verdict}")
        print("\n-- Packed 32-bit float candidates --")
        if behavior["packed_float_candidates"]:
            for label, info in behavior["packed_float_candidates"].items():
                print(f"  {label}: {info['verdict']}")
        else:
            print("  none found")
        print("\n-- Correlated pairs (|r| >= 0.7) --")
        if behavior["correlations"]:
            for a, b, r in behavior["correlations"]:
                print(f"  {a}  <->  {b}   r={r}")
        else:
            print("  none found")

        result["per_unit"][unit] = udata

    report_path = os.path.join(out_dir, "blackbox_report.json")
    with open(report_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"\nWrote {report_path}")
    return result


def write_markdown_summary(result: dict, out_dir: str) -> str:
    """Plain summary for comparison against project-log/06_REFERENCE.md.
    Does NOT consult that file -- this is the black-box guess, written
    before any comparison to the known map."""
    L = [f"# Black-box recon summary: {result['host']}:{result['port']}\n"]
    nmap = result.get("nmap", {})
    L.append("## nmap discovery\n")
    L.append(f"- Ran: {'yes' if nmap.get('ok') else 'no (see note)'}")
    L.append(f"- {nmap.get('summary', '')[:300]}\n")
    for unit, udata in result.get("per_unit", {}).items():
        L.append(f"## Unit ID {unit}\n")
        did = udata.get("device_identification", {})
        L.append(f"- Device identification (FC 0x2B): "
                  f"{'supported' if did.get('supported') else 'not supported / refused'}")
        live = udata.get("live_addresses", {})
        if "error" in live:
            L.append(f"- Enumeration: {live['error']}\n")
            continue
        for space, addrs in live.items():
            L.append(f"- {space}: {len(addrs)} live address(es): {sorted(addrs.keys())}")
        beh = udata.get("behavior_report", {})
        if beh:
            L.append("\n**Guessed classification (no register map consulted):**\n")
            for label, verdict in beh.get("classifications", {}).items():
                L.append(f"  - `{label}`: {verdict}")
            if beh.get("packed_float_candidates"):
                L.append("\n**Packed-float candidates:**")
                for label, info in beh["packed_float_candidates"].items():
                    L.append(f"  - `{label}`: {info['verdict']}")
            if beh.get("correlations"):
                L.append("\n**Correlated pairs:**")
                for a, b, r in beh["correlations"]:
                    L.append(f"  - `{a}` <-> `{b}` (r={r})")
        L.append("")
    text = "\n".join(L) + "\n"
    path = os.path.join(out_dir, "blackbox_summary.md")
    with open(path, "w") as f:
        f.write(text)
    return path


# ============================================================================
# SECTION 5: CLI / MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Black-box Modbus/TCP recon for PLC Guardian Experiment 5. "
                     "Read-only. Run only against the lab PLC on the isolated lab network."
    )
    parser.add_argument("--host", required=True, help="Target host (the lab PLC's IP).")
    parser.add_argument("--port", type=int, default=502, help="Modbus TCP port (default 502).")
    parser.add_argument("--units", type=int, nargs="+", default=[1, 255],
                         help="Unit IDs to try (default: 1 255 -- do not assume "
                              "only one; see project-log/06_REFERENCE.md).")
    parser.add_argument("--range", type=int, nargs=2, default=[0, 20], metavar=("START", "END"),
                         help="Address range to enumerate per space, e.g. --range 0 50.")
    parser.add_argument("--samples", type=int, default=20, help="Poll samples for inference.")
    parser.add_argument("--interval", type=float, default=0.3, help="Seconds between poll samples.")
    parser.add_argument("-o", "--out", default="blackbox_out", help="Output directory.")
    args = parser.parse_args()

    print(f"Black-box recon against {args.host}:{args.port} (units {args.units}). "
          f"READ ONLY. Confirm this is the lab PLC on the isolated lab network before proceeding.")
    result = run_pipeline(args.host, args.port, args.units, tuple(args.range),
                           args.samples, args.interval, args.out)
    md_path = write_markdown_summary(result, args.out)
    print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()
