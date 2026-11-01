#!/usr/bin/env python3
"""Tiny Modbus/TCP client for lab testing (stands in for the HMI or the simulated attacker).

Lab use only: run it against the lab PLC / mock PLC on the isolated ICS network.

    python tools/modbus_client.py 192.168.8.11 read-hr 0 10
    python tools/modbus_client.py 192.168.8.11 read-coils 0 8
    python tools/modbus_client.py 192.168.8.11 write-reg 0 75
    python tools/modbus_client.py 192.168.8.11 write-regs 0 1 2 3
    python tools/modbus_client.py 192.168.8.11 write-coil 0 1
    python tools/modbus_client.py 127.0.0.1:5020 read-hr 0 4 --unit 1

Options: --unit N (default 1), --bind IP (choose the source address on a multi-homed host)
"""
import argparse
import socket
import struct
import sys

EXC = {1: "Illegal Function", 2: "Illegal Data Address", 3: "Illegal Data Value",
       4: "Server Device Failure", 11: "Gateway Target Failed to Respond"}


def build(op, args):
    a = [int(x) for x in args]
    if op == "read-hr":
        return struct.pack(">BHH", 3, a[0], a[1])
    if op == "read-coils":
        return struct.pack(">BHH", 1, a[0], a[1])
    if op == "write-reg":
        return struct.pack(">BHH", 6, a[0], a[1])
    if op == "write-coil":
        return struct.pack(">BHH", 5, a[0], 0xFF00 if a[1] else 0)
    if op == "write-regs":
        vals = a[1:]
        return struct.pack(f">BHHB{len(vals)}H", 16, a[0], len(vals), len(vals) * 2, *vals)
    raise SystemExit(f"unknown op {op}")


def request(host, port, unit, pdu, tid=1, bind=None, timeout=3.0):
    s = socket.create_connection((host, port), timeout=timeout,
                                 source_address=(bind, 0) if bind else None)
    try:
        s.sendall(struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu)
        hdr = b""
        while len(hdr) < 7:
            chunk = s.recv(7 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        length = struct.unpack(">H", hdr[4:6])[0]
        body = b""
        while len(body) < length - 1:
            chunk = s.recv(length - 1 - len(body))
            if not chunk:
                break
            body += chunk
        return body
    finally:
        s.close()


def describe(resp):
    if resp is None:
        return "connection closed with no response"
    fc = resp[0]
    if fc & 0x80:
        return f"EXCEPTION {resp[1]} ({EXC.get(resp[1], '?')})"
    if fc == 3:
        n = resp[1] // 2
        return f"registers = {list(struct.unpack(f'>{n}H', resp[2:2 + 2 * n]))}"
    if fc == 1:
        return f"coil bytes = {resp[2:].hex()}"
    return f"OK (echo {resp.hex()})"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="host or host:port")
    ap.add_argument("op", choices=["read-hr", "read-coils", "write-reg", "write-regs", "write-coil"])
    ap.add_argument("args", nargs="+")
    ap.add_argument("--unit", type=int, default=1)
    ap.add_argument("--bind")
    a = ap.parse_args()
    host, _, port = a.target.partition(":")
    try:
        print(describe(request(host, int(port or 502), a.unit, build(a.op, a.args), bind=a.bind)))
    except OSError as e:
        sys.exit(f"error: {e}")
