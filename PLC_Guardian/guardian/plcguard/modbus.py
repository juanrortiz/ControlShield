"""Modbus/TCP decoding (MBAP header + PDU) for PLC Guardian.

Wire layout of every Modbus/TCP frame (all fields big-endian):

    offset  size  field
    0       2     Transaction ID   (echoed back in the response)
    2       2     Protocol ID      (always 0x0000 for Modbus; anything else is suspicious)
    4       2     Length           (number of bytes that follow: unit id + PDU)
    6       1     Unit ID
    7       1     Function code    (high bit set in a response = exception)
    8..           Function-specific data

Only the standard library is used so the decoder runs anywhere (proxy, pcap, tests).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field, asdict
from typing import Optional

MBAP_LEN = 7          # TID(2) + PID(2) + LEN(2) + UNIT(1)
MAX_LENGTH_FIELD = 254  # Modbus PDU max 253 bytes + unit id

FC_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    11: "Get Comm Event Counter",
    12: "Get Comm Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Encapsulated Interface Transport (Device ID)",
    90: "Schneider FC 0x5A (engineering / programming)",
}

# Category drives policy. "write" = changes process data; "config" = changes the
# controller itself (programming, run/stop, diagnostics that can reset counters).
READ_FCS = {1, 2, 3, 4, 7, 11, 12, 17, 20, 24, 43}
WRITE_FCS = {5, 6, 15, 16, 21, 22, 23}
CONFIG_FCS = {8, 90}

# Which data table a function code touches (used for protected-register checks).
FC_TABLE = {
    1: "coil", 5: "coil", 15: "coil",
    2: "discrete_input",
    3: "holding", 6: "holding", 16: "holding", 22: "holding", 23: "holding", 24: "holding",
    4: "input",
}

EXCEPTION_NAMES = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Server Device Failure",
    5: "Acknowledge",
    6: "Server Device Busy",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Device Failed to Respond",
}

# FC 0x5A sub-codes as documented for Schneider UMAS (Modicon M340/M580).
# [UNVERIFIED] for the M221: SoMachine/Machine Expert Basic also rides on FC 0x5A
# but its sub-protocol is not confirmed to match UMAS. Used as a hint only.
UMAS_HINTS = {
    0x01: "INIT_COMM", 0x02: "READ_ID", 0x03: "READ_PROJECT_INFO", 0x04: "READ_PLC_INFO",
    0x10: "TAKE_PLC_RESERVATION", 0x11: "RELEASE_PLC_RESERVATION", 0x12: "KEEP_ALIVE",
    0x20: "READ_MEMORY_BLOCK", 0x22: "READ_VARIABLES", 0x23: "WRITE_VARIABLES",
    0x24: "READ_COILS_REGISTERS", 0x25: "WRITE_COILS_REGISTERS",
    0x30: "INITIALIZE_UPLOAD", 0x31: "UPLOAD_BLOCK", 0x32: "END_STRATEGY_UPLOAD",
    0x33: "INITIALIZE_DOWNLOAD", 0x34: "DOWNLOAD_BLOCK", 0x35: "END_DOWNLOAD",
    0x40: "START_PLC", 0x41: "STOP_PLC", 0x50: "MONITOR_PLC", 0x58: "CHECK_PLC",
}


def fc_category(fc: int) -> str:
    if fc & 0x80:
        return "exception"
    if fc in READ_FCS:
        return "read"
    if fc in WRITE_FCS:
        return "write"
    if fc in CONFIG_FCS:
        return "config"
    return "unknown"


@dataclass
class ModbusFrame:
    tid: int
    pid: int
    length: int
    unit: int
    fc: int
    data: bytes
    is_request: bool
    fc_name: str = ""
    category: str = ""
    table: Optional[str] = None
    address: Optional[int] = None
    quantity: Optional[int] = None
    values: Optional[list] = None
    read_address: Optional[int] = None       # FC 23 only
    read_quantity: Optional[int] = None      # FC 23 only
    exception_code: Optional[int] = None
    exception_name: Optional[str] = None
    subcode: Optional[int] = None            # FC 90 sub-function
    subcode_hint: Optional[str] = None
    anomalies: list = field(default_factory=list)

    @property
    def raw(self) -> bytes:
        return struct.pack(">HHHBB", self.tid, self.pid, self.length, self.unit, self.fc) + self.data

    def write_targets(self):
        """Yield (table, address, value) for every point a write request changes."""
        if not self.is_request or self.address is None or not self.values:
            return
        if self.fc == 22:  # mask write: value = (current AND and_mask) OR (or_mask AND NOT and_mask)
            yield (self.table, self.address, None)
            return
        for i, v in enumerate(self.values):
            yield (self.table, self.address + i, v)

    def summary(self) -> str:
        if self.category == "exception":
            return f"EXCEPTION fc=0x{self.fc:02x} code={self.exception_code} ({self.exception_name})"
        s = f"FC{self.fc} {self.fc_name}"
        if self.address is not None:
            s += f" addr={self.address}"
        if self.quantity is not None:
            s += f" qty={self.quantity}"
        if self.values is not None and self.is_request and self.category == "write":
            vals = self.values if len(self.values) <= 8 else self.values[:8] + ["..."]
            s += f" values={vals}"
        if self.subcode is not None:
            s += f" sub=0x{self.subcode:02x}"
            if self.subcode_hint:
                s += f" ({self.subcode_hint}?)"
        return s

    def to_dict(self) -> dict:
        d = asdict(self)
        d["data"] = self.data.hex()
        return d


def _bits(data: bytes, count: int) -> list:
    out = []
    for i in range(count):
        byte = i // 8
        if byte >= len(data):
            break
        out.append((data[byte] >> (i % 8)) & 1)
    return out


def _decode_request(f: ModbusFrame) -> None:
    d, fc = f.data, f.fc
    try:
        if fc in (1, 2, 3, 4):
            f.address, f.quantity = struct.unpack(">HH", d[:4])
        elif fc == 5:
            f.address, raw = struct.unpack(">HH", d[:4])
            f.quantity = 1
            if raw == 0xFF00:
                f.values = [1]
            elif raw == 0x0000:
                f.values = [0]
            else:
                f.values = [raw]
                f.anomalies.append(f"INVALID_COIL_VALUE_0x{raw:04x}")
        elif fc == 6:
            f.address, v = struct.unpack(">HH", d[:4])
            f.quantity, f.values = 1, [v]
        elif fc == 15:
            f.address, f.quantity, bc = struct.unpack(">HHB", d[:5])
            f.values = _bits(d[5:5 + bc], f.quantity)
            if bc != (f.quantity + 7) // 8 or len(d) - 5 != bc:
                f.anomalies.append("BYTE_COUNT_MISMATCH")
        elif fc == 16:
            f.address, f.quantity, bc = struct.unpack(">HHB", d[:5])
            regs = d[5:5 + bc]
            f.values = list(struct.unpack(f">{len(regs) // 2}H", regs[: len(regs) // 2 * 2]))
            if bc != f.quantity * 2 or len(d) - 5 != bc:
                f.anomalies.append("BYTE_COUNT_MISMATCH")
        elif fc == 22:
            f.address, and_m, or_m = struct.unpack(">HHH", d[:6])
            f.quantity, f.values = 1, [and_m, or_m]
        elif fc == 23:
            f.read_address, f.read_quantity, f.address, f.quantity, bc = struct.unpack(">HHHHB", d[:9])
            regs = d[9:9 + bc]
            f.values = list(struct.unpack(f">{len(regs) // 2}H", regs[: len(regs) // 2 * 2]))
        elif fc == 90:
            if len(d) >= 2:
                f.subcode = d[1]
                f.subcode_hint = UMAS_HINTS.get(d[1])
    except struct.error:
        f.anomalies.append("TRUNCATED_PDU")


def _decode_response(f: ModbusFrame) -> None:
    d, fc = f.data, f.fc
    try:
        if fc & 0x80:
            f.exception_code = d[0] if d else None
            f.exception_name = EXCEPTION_NAMES.get(f.exception_code, "Unknown")
        elif fc in (1, 2):
            bc = d[0]
            f.values = _bits(d[1:1 + bc], bc * 8)
        elif fc in (3, 4, 23):
            bc = d[0]
            regs = d[1:1 + bc]
            f.values = list(struct.unpack(f">{len(regs) // 2}H", regs[: len(regs) // 2 * 2]))
            f.quantity = len(f.values)
        elif fc in (5, 6):
            f.address, v = struct.unpack(">HH", d[:4])
            f.values = [v]
        elif fc in (15, 16):
            f.address, f.quantity = struct.unpack(">HH", d[:4])
        elif fc == 90 and len(d) >= 2:
            f.subcode = d[1]
    except (struct.error, IndexError):
        f.anomalies.append("TRUNCATED_PDU")


def parse_frame(buf: bytes, is_request: bool) -> ModbusFrame:
    """Parse exactly one complete MBAP frame (caller guarantees len == 6 + length)."""
    tid, pid, length, unit, fc = struct.unpack(">HHHBB", buf[:8])
    f = ModbusFrame(tid=tid, pid=pid, length=length, unit=unit, fc=fc, data=bytes(buf[8:]),
                    is_request=is_request)
    base_fc = fc & 0x7F
    f.fc_name = FC_NAMES.get(base_fc, f"Unknown FC {base_fc}")
    f.category = fc_category(fc)
    f.table = FC_TABLE.get(base_fc)
    if pid != 0:
        f.anomalies.append(f"NONZERO_PROTOCOL_ID_0x{pid:04x}")
    if is_request and fc & 0x80:
        f.anomalies.append("EXCEPTION_BIT_IN_REQUEST")
    if f.category == "unknown":
        f.anomalies.append(f"UNKNOWN_FUNCTION_CODE_{fc}")
    if is_request:
        _decode_request(f)
    else:
        _decode_response(f)
    return f


def split_frames(buf: bytes):
    """Split a byte stream into complete MBAP frames.

    Returns (frames_bytes_list, remainder, error). `error` is set when the stream is not
    valid Modbus/TCP (bad length field); the caller should stop parsing that stream.
    """
    frames, i = [], 0
    while len(buf) - i >= MBAP_LEN + 1:
        length = struct.unpack(">H", buf[i + 4:i + 6])[0]
        if length < 2 or length > MAX_LENGTH_FIELD:
            return frames, b"", f"BAD_MBAP_LENGTH_{length}"
        total = 6 + length
        if len(buf) - i < total:
            break
        frames.append(bytes(buf[i:i + total]))
        i += total
    return frames, bytes(buf[i:]), None


def build_exception(req: ModbusFrame, code: int) -> bytes:
    """Build the Modbus exception response Guardian sends back when it blocks a request."""
    return struct.pack(">HHHBBB", req.tid, 0, 3, req.unit, (req.fc | 0x80) & 0xFF, code)
