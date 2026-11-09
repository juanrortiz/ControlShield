#!/usr/bin/env python3
"""
plc_discovery.py -- all-in-one black-box PLC discovery & inference tool.

Pinned to pymodbus==3.7.4 (see requirements.txt / the comment near the top
of each section below) -- the client/server API has changed names across
versions (slave= vs device_id=, ModbusSlaveContext vs ModbusDeviceContext),
so if you upgrade pymodbus, re-check these signatures before assuming this
still runs unchanged.

USAGE
-----
Self-contained demo (starts a fake PLC in the background, runs the full
pipeline against it, no second terminal and no real hardware needed):

    python plc_discovery.py --demo

Against a real device:

    python plc_discovery.py --host 192.168.1.50 --port 502

Run just the fake PLC in the foreground (e.g. if you want a separate
terminal/session to repeatedly test against, Modbus-poll tool, etc.):

    python plc_discovery.py --simulator-only

With no arguments at all, it runs --demo.

WHAT'S INSIDE (search for these section headers)
--------------------------------------------------
  SECTION 1: SIMULATOR     -- a fake PLC, for validating this tool's guesses
                               against ground truth you control
  SECTION 2: DISCOVERY     -- ICS port scanning
  SECTION 3: FINGERPRINT   -- Modbus "read device identification"
  SECTION 4: ENUMERATION   -- sweep the four Modbus address spaces
  SECTION 5: INFERENCE     -- poll over time, classify behavior, find
                               packed 32-bit floats, find correlated pairs
  SECTION 6: PIPELINE      -- ties stages 2-5 together into one report
  SECTION 7: CLI / MAIN    -- argument parsing and entry point

See the bottom of the file for ground-truth register map used by the
simulator, and the "methodology notes" docstring on run_pipeline() for
known limitations worth citing in a report (sampling aliasing, spurious
correlation, misaligned register-pair noise).
"""
import argparse
import asyncio
import json
import math
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from pymodbus.client import ModbusTcpClient
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server import StartAsyncTcpServer


# ============================================================================
# SECTION 1: SIMULATOR
# ============================================================================
# A fake PLC used ONLY so you can validate the pipeline's guesses against
# ground truth you control, instead of brute-forcing a real device.
#
# Simulated "plant" (the pipeline does NOT get to see this -- compare its
# guesses against this after running):
#
#   Coils (co)             address  meaning
#     0                      heartbeat        toggles every cycle (fast bit)
#     1                      pump_run         on when tank_level > 50
#
#   Discrete inputs (di)
#     0                      high_level_alarm true when tank_level > 80
#
#   Holding registers (hr)  -- read/write, config-like
#     0                      temperature_setpoint   static, x10 scaled
#     1                      flow_setpoint           static
#     2-3                    calibration_offset      static 32-bit float
#
#   Input registers (ir)    -- read-only, process variables
#     0                      temperature_pv   drifts slowly toward setpoint
#     1                      tank_level_pv    slow oscillation 0-100
#     2-3                    flow_rate_pv     32-bit float, nonzero only
#                                              while pump_run is on

SIM_HOST = "127.0.0.1"
SIM_PORT = 5020  # unprivileged port, no root/sudo needed


def _float_to_regs(value: float):
    """Pack a 32-bit float into two big-endian 16-bit registers."""
    raw = struct.pack(">f", value)
    hi, lo = struct.unpack(">HH", raw)
    return [hi, lo]


def _build_sim_context():
    co = ModbusSequentialDataBlock(0, [0] * 20)
    di = ModbusSequentialDataBlock(0, [0] * 20)
    hr = ModbusSequentialDataBlock(0, [0] * 20)
    ir = ModbusSequentialDataBlock(0, [0] * 20)

    slave = ModbusSlaveContext(di=di, co=co, ir=ir, hr=hr)
    context = ModbusServerContext(slaves=slave, single=True)

    slave.setValues(3, 0, [650])                 # hr0 temperature_setpoint
    slave.setValues(3, 1, [120])                  # hr1 flow_setpoint
    slave.setValues(3, 2, _float_to_regs(1.5))    # hr2-3 calibration_offset
    slave.setValues(4, 0, [200])                  # ir0 temperature_pv starts at 20.0C

    return context, slave


async def _sim_plant_loop(slave: ModbusSlaveContext, stop_event: asyncio.Event):
    """Background task that makes the fake plant behave like a real one."""
    t = 0.0
    heartbeat = 0
    while not stop_event.is_set():
        t += 1
        heartbeat ^= 1
        slave.setValues(1, 0, [heartbeat])  # co0 heartbeat

        tank_level = 50 + 48 * math.sin(t / 15.0)
        slave.setValues(4, 1, [int(tank_level)])  # ir1 tank_level_pv

        pump_run = 1 if tank_level > 50 else 0
        slave.setValues(1, 1, [pump_run])  # co1 pump_run

        high_alarm = 1 if tank_level > 80 else 0
        slave.setValues(2, 0, [high_alarm])  # di0 high_level_alarm

        setpoint = slave.getValues(3, 0, 1)[0] / 10.0
        prev_temp_raw = slave.getValues(4, 0, 1)[0]
        prev_temp = prev_temp_raw / 10.0 if prev_temp_raw else setpoint
        new_temp = prev_temp + (setpoint - prev_temp) * 0.1
        slave.setValues(4, 0, [int(new_temp * 10)])  # ir0 temperature_pv

        flow = (45 + 5 * math.sin(t / 3.0)) if pump_run else 0.0
        slave.setValues(4, 2, _float_to_regs(flow))  # ir2-3 flow_rate_pv

        await asyncio.sleep(0.5)


async def _simulator_main(stop_event: asyncio.Event, ready_event: threading.Event):
    context, slave = _build_sim_context()
    identity = ModbusDeviceIdentification(
        info_name={
            "VendorName": "Acme Industrial",
            "ProductCode": "ACM-PLC-2200",
            "VendorUrl": "https://example.invalid/acme",
            "ProductName": "Acme Series 2200 Controller",
            "ModelName": "2200-R3",
            "MajorMinorRevision": "3.2.1",
        }
    )
    plant_task = asyncio.create_task(_sim_plant_loop(slave, stop_event))
    # StartAsyncTcpServer blocks until the server is stopped; signal "ready"
    # right before we call it since binding happens synchronously inside.
    ready_event.set()
    try:
        await StartAsyncTcpServer(context, identity=identity, address=(SIM_HOST, SIM_PORT))
    finally:
        stop_event.set()
        await plant_task


def start_simulator_in_background() -> threading.Thread:
    """Run the fake PLC in a daemon thread with its own event loop.

    Returns the thread. It's a daemon thread, so it's killed automatically
    when the main process exits -- no explicit shutdown needed for a
    one-shot demo run.
    """
    stop_event_holder = {}

    def runner():
        async def _run():
            stop_event = asyncio.Event()
            stop_event_holder["stop"] = stop_event
            ready_event = threading.Event()
            ready_event_holder["ready"] = ready_event
            await _simulator_main(stop_event, ready_event)

        asyncio.run(_run())

    ready_event_holder = {}
    thread = threading.Thread(target=runner, daemon=True)
    thread.start()

    # wait for the thread to create its ready_event, then wait for it to fire
    for _ in range(100):
        if "ready" in ready_event_holder:
            break
        time.sleep(0.02)
    ready_event_holder.get("ready", threading.Event()).wait(timeout=5)
    time.sleep(0.2)  # small extra margin for the listening socket to be accept()-ready
    return thread


def run_simulator_foreground():
    print(f"Simulated PLC listening on {SIM_HOST}:{SIM_PORT} (Ctrl+C to stop)")
    asyncio.run(_simulator_main(asyncio.Event(), threading.Event()))


# ============================================================================
# SECTION 2: DISCOVERY
# ============================================================================
# Find hosts speaking known ICS protocols, rather than sweeping every port.

ICS_PORTS = {
    502: "Modbus TCP",
    102: "S7comm (Siemens)",
    44818: "EtherNet/IP",
    20000: "DNP3",
    2404: "IEC 60870-5-104",
    789: "Red Lion Crimson",
    1911: "Niagara Fox",
    4840: "OPC UA",
}


def check_port(host: str, port: int, timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def scan_host(host: str, ports: dict = None, timeout: float = 0.5) -> list:
    """Return [(port, protocol_name), ...] for every ICS port open on host."""
    ports = ports or ICS_PORTS
    found = []
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        futures = {
            pool.submit(check_port, host, port, timeout): (port, name)
            for port, name in ports.items()
        }
        for fut in as_completed(futures):
            port, name = futures[fut]
            if fut.result():
                found.append((port, name))
    return sorted(found)


# ============================================================================
# SECTION 3: FINGERPRINT
# ============================================================================
# Modbus function code 0x2B (Read Device Identification) is designed for
# self-identification and needs no prior knowledge of the device. Many real
# PLCs don't implement it -- the failure (and its exception code) is itself
# a clue, so we report it rather than crash.

def fingerprint(host: str, port: int = 502, slave: int = 1) -> dict:
    client = ModbusTcpClient(host, port=port)
    result = {"host": host, "port": port, "device_identification": None, "notes": []}

    if not client.connect():
        result["notes"].append("Could not open TCP connection.")
        return result

    try:
        resp = client.read_device_information(read_code=1, slave=slave)
        if resp.isError():
            result["notes"].append(f"Device identification not supported or refused: {resp}")
        else:
            info = {
                (k.decode() if isinstance(k, bytes) else k):
                (v.decode() if isinstance(v, bytes) else v)
                for k, v in resp.information.items()
            }
            result["device_identification"] = info
    except Exception as exc:  # noqa: BLE001 -- broad on purpose, this is discovery code
        result["notes"].append(f"Exception while fingerprinting: {exc!r}")
    finally:
        client.close()

    return result


# ============================================================================
# SECTION 4: ENUMERATION
# ============================================================================
# With no register map, find out what's there by probing each of the four
# Modbus address spaces one address at a time.

SPACES = {
    "coils": "read_coils",
    "discrete_inputs": "read_discrete_inputs",
    "holding_registers": "read_holding_registers",
    "input_registers": "read_input_registers",
}


def sweep_space(client: ModbusTcpClient, method_name: str, start: int, end: int,
                 slave: int = 1) -> dict:
    method = getattr(client, method_name)
    live = {}
    for addr in range(start, end):
        resp = method(address=addr, count=1, slave=slave)
        if not resp.isError():
            value = resp.bits[0] if hasattr(resp, "bits") else resp.registers[0]
            live[addr] = value
    return live


def enumerate_device(host: str, port: int = 502, start: int = 0, end: int = 50,
                      slave: int = 1) -> dict:
    client = ModbusTcpClient(host, port=port)
    if not client.connect():
        return {"error": "could not connect"}

    report = {}
    try:
        for space_name, method_name in SPACES.items():
            report[space_name] = sweep_space(client, method_name, start, end, slave)
    finally:
        client.close()
    return report


# ============================================================================
# SECTION 5: INFERENCE
# ============================================================================
# The actual "black box" part: poll every live address over time and
# classify it from its behavior. Only reads -- see the module docstring for
# the safety note on writing test values.

_INFER_SPACES = {
    "coils": ("read_coils", True),
    "discrete_inputs": ("read_discrete_inputs", True),
    "holding_registers": ("read_holding_registers", False),
    "input_registers": ("read_input_registers", False),
}


def poll_live_addresses(host: str, port: int, live_map: dict, samples: int = 20,
                         interval: float = 0.3, slave: int = 1) -> dict:
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
                    resp = method(address=addr, count=1, slave=slave)
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
    32-bit float; flag ones that look physically plausible and nontrivial.
    """
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
            if not ok:
                continue
            if all(f == 0.0 for f in floats):
                # Two unrelated zero/unused registers also decode to 0.0 --
                # not evidence of a packed float, just absence of signal.
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
# SECTION 6: PIPELINE
# ============================================================================

def run_pipeline(host: str, port: int, address_range=(0, 20), samples: int = 20,
                  interval: float = 0.3):
    """Run discovery -> fingerprint -> enumeration -> inference end to end
    and print a report.

    Methodology notes worth citing in a report (see README for the full
    discussion with example output):
      - Polling many addresses per cycle can alias a fast-toggling bit
        (classic Nyquist problem) -- a true heartbeat can misclassify as
        "changes occasionally" if the sweep itself takes longer than the
        bit's toggle period.
      - Plain Pearson correlation over a short window can flag two
        unrelated but simultaneously-trending signals as strongly
        correlated. Treat correlation as a lead to investigate, not proof
        of a causal link.
      - The float-pair scanner checks every adjacent offset, including
        misaligned ones, since true alignment isn't known in black-box
        conditions. A genuine packed value stands out by moving smoothly
        and plausibly, not merely by decoding without error.
    """
    print(f"\n{'=' * 60}\nSTEP 1: Discovery\n{'=' * 60}")
    open_ports = scan_host(host)
    if open_ports:
        for p, name in open_ports:
            print(f"  OPEN  {p:<6} {name}")
    else:
        print(f"  No ICS ports from the standard list were open; proceeding "
              f"anyway against {host}:{port} since it was given explicitly.")

    print(f"\n{'=' * 60}\nSTEP 2: Fingerprinting\n{'=' * 60}")
    fp = fingerprint(host, port)
    print(json.dumps(fp, indent=2))

    print(f"\n{'=' * 60}\nSTEP 3: Register/coil enumeration (range {address_range})\n{'=' * 60}")
    live = enumerate_device(host, port, start=address_range[0], end=address_range[1])
    for space, values in live.items():
        print(f"  {space}: {len(values)} live address(es) -> {sorted(values.keys())}")

    total_live = sum(len(v) for v in live.values())
    if total_live == 0:
        print("\nNo live addresses found in this range -- widen address_range and retry.")
        return None

    print(f"\n{'=' * 60}\nSTEP 4: Behavioral inference ({samples} samples, "
          f"{interval}s apart -- ~{samples * interval:.0f}s)\n{'=' * 60}")
    series = poll_live_addresses(host, port, live, samples=samples, interval=interval)
    report = build_behavior_report(series)

    print("\n-- Classifications --")
    for label, verdict in report["classifications"].items():
        print(f"  {label:<28} {verdict}")

    print("\n-- Packed 32-bit float candidates --")
    if report["packed_float_candidates"]:
        for label, info in report["packed_float_candidates"].items():
            print(f"  {label}: {info['verdict']}")
            print(f"    sample values: {info['decoded_values'][:6]}...")
    else:
        print("  none found")

    print("\n-- Correlated pairs (|r| >= 0.7) --")
    if report["correlations"]:
        for a, b, r in report["correlations"]:
            print(f"  {a}  <->  {b}   r={r}")
    else:
        print("  none found")

    return {"fingerprint": fp, "live_addresses": live, "behavior_report": report}


# ============================================================================
# SECTION 7: CLI / MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="All-in-one black-box PLC discovery & inference tool."
    )
    parser.add_argument("--host", default=None, help="Target host (real device).")
    parser.add_argument("--port", type=int, default=502, help="Target port (default 502).")
    parser.add_argument("--demo", action="store_true",
                         help="Start the built-in fake PLC and run the pipeline "
                              "against it. Default behavior if no --host is given.")
    parser.add_argument("--simulator-only", action="store_true",
                         help="Just run the fake PLC in the foreground; run the "
                              "pipeline against it separately/later.")
    parser.add_argument("--samples", type=int, default=20,
                         help="Number of poll samples for behavioral inference.")
    parser.add_argument("--interval", type=float, default=0.3,
                         help="Seconds between poll samples.")
    parser.add_argument("--range", type=int, nargs=2, default=[0, 20], metavar=("START", "END"),
                         help="Address range to enumerate, e.g. --range 0 50.")
    args = parser.parse_args()

    if args.simulator_only:
        run_simulator_foreground()
        return

    if args.host:
        run_pipeline(args.host, args.port, address_range=tuple(args.range),
                     samples=args.samples, interval=args.interval)
        return

    # default: self-contained demo
    print("No --host given -- starting the built-in fake PLC and running the "
          "pipeline against it (use --host to target a real device instead).")
    start_simulator_in_background()
    run_pipeline(SIM_HOST, SIM_PORT, address_range=tuple(args.range),
                 samples=args.samples, interval=args.interval)


if __name__ == "__main__":
    main()
