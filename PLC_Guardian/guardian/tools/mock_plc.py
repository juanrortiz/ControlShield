#!/usr/bin/env python3
"""Minimal Modbus/TCP server that stands in for the M221 when the real PLC isn't available.

    python tools/mock_plc.py --port 5020

Supports FC 1, 3, 5, 6, 15, 16 on 100 coils / 100 holding registers; everything else
returns exception 01. Writes are printed so you can see what actually reached the "PLC".
Standard library only.
"""
import argparse
import asyncio
import struct

COILS = [0] * 100
HREGS = [0] * 100


def handle(pdu: bytes) -> bytes:
    fc = pdu[0]
    try:
        if fc in (1, 3):
            addr, qty = struct.unpack(">HH", pdu[1:5])
            if fc == 1:
                bits = COILS[addr:addr + qty]
                if len(bits) != qty:
                    return bytes([fc | 0x80, 2])
                out = bytearray((qty + 7) // 8)
                for i, b in enumerate(bits):
                    out[i // 8] |= b << (i % 8)
                return bytes([fc, len(out)]) + bytes(out)
            regs = HREGS[addr:addr + qty]
            if len(regs) != qty:
                return bytes([fc | 0x80, 2])
            return bytes([fc, qty * 2]) + struct.pack(f">{qty}H", *regs)
        if fc == 5:
            addr, v = struct.unpack(">HH", pdu[1:5])
            COILS[addr] = 1 if v == 0xFF00 else 0
            print(f"[mock PLC] coil {addr} <- {COILS[addr]}")
            return pdu[:5]
        if fc == 6:
            addr, v = struct.unpack(">HH", pdu[1:5])
            HREGS[addr] = v
            print(f"[mock PLC] holding {addr} <- {v}")
            return pdu[:5]
        if fc == 15:
            addr, qty, bc = struct.unpack(">HHB", pdu[1:6])
            for i in range(qty):
                COILS[addr + i] = (pdu[6 + i // 8] >> (i % 8)) & 1
            print(f"[mock PLC] coils {addr}..{addr + qty - 1} <- {COILS[addr:addr + qty]}")
            return pdu[:5]
        if fc == 16:
            addr, qty, bc = struct.unpack(">HHB", pdu[1:6])
            HREGS[addr:addr + qty] = list(struct.unpack(f">{qty}H", pdu[6:6 + bc]))
            print(f"[mock PLC] holding {addr}..{addr + qty - 1} <- {HREGS[addr:addr + qty]}")
            return pdu[:5]
    except (struct.error, IndexError):
        return bytes([(fc | 0x80) & 0xFF, 3])
    return bytes([(fc | 0x80) & 0xFF, 1])


async def client(reader, writer):
    try:
        while True:
            hdr = await reader.readexactly(7)
            tid, pid, length, unit = struct.unpack(">HHHB", hdr)
            pdu = await reader.readexactly(length - 1)
            resp = handle(pdu)
            writer.write(struct.pack(">HHHB", tid, 0, len(resp) + 1, unit) + resp)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()


async def main(host, port, ready=None):
    srv = await asyncio.start_server(client, host, port)
    print(f"[mock PLC] listening on {host}:{srv.sockets[0].getsockname()[1]}")
    if ready:
        ready.set()
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5020)
    a = ap.parse_args()
    try:
        asyncio.run(main(a.host, a.port))
    except KeyboardInterrupt:
        pass
