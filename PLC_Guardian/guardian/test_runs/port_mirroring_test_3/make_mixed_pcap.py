"""Build a SYNTHETIC mixed capture for Experiments 3/4: real Port_mirroring_test_3 traffic
plus injected sessions (clearly synthetic: every injected frame carries TTL 99)."""
import struct, sys
from scapy.all import rdpcap, wrpcap, Ether, IP, TCP, Raw

PLC_IP, PLC_MAC = "192.168.8.11", "00:80:f4:54:1d:67"
HMI_IP, HMI_MAC = "192.168.8.10", "00:00:54:0b:c5:9a"
ATK_IP, ATK_MAC = "192.168.8.99", "00:e0:4c:1d:3d:70"

def session(t, cip, cmac, cport, pdus, unit=255):
    """TCP handshake + one Modbus request/response per pdu (PLC echoes writes = accepted)."""
    out, cs, ss = [], 1000, 5000
    def pk(src, smac, dst, dmac, sp, dp, fl, seq, ack, pl=b""):
        p = Ether(src=smac, dst=dmac)/IP(src=src, dst=dst, ttl=99)/TCP(sport=sp, dport=dp, flags=fl, seq=seq, ack=ack)
        return p/Raw(pl) if pl else p
    def at(p, dt):
        nonlocal t; t += dt; p.time = t; out.append(p)
    at(pk(cip, cmac, PLC_IP, PLC_MAC, cport, 502, "S", cs, 0), 0); cs += 1
    at(pk(PLC_IP, PLC_MAC, cip, cmac, 502, cport, "SA", ss, cs), .001); ss += 1
    at(pk(cip, cmac, PLC_IP, PLC_MAC, cport, 502, "A", cs, ss), .001)
    for tid, (pdu, rsp) in enumerate(pdus, 1):
        req = struct.pack(">HHHB", tid, 0, len(pdu)+1, unit) + pdu
        at(pk(cip, cmac, PLC_IP, PLC_MAC, cport, 502, "PA", cs, ss, req), .05); cs += len(req)
        r = rsp if rsp is not None else pdu
        resp = struct.pack(">HHHB", tid, 0, len(r)+1, unit) + r
        at(pk(PLC_IP, PLC_MAC, cip, cmac, 502, cport, "PA", ss, cs, resp), .002); ss += len(resp)
    at(pk(cip, cmac, PLC_IP, PLC_MAC, cport, 502, "FA", cs, ss), .01)
    return out

src, dst = sys.argv[1], sys.argv[2]
pk = rdpcap(src); t0 = float(pk[0].time)
def fc15(addr, bits):
    v = sum(b << i for i, b in enumerate(bits))
    return struct.pack(">BHHBB", 15, addr, len(bits), 1, v), struct.pack(">BHH", 15, addr, len(bits))
def fc5(addr, on):  return struct.pack(">BHH", 5, addr, 0xFF00 if on else 0)
def fc6(addr, val): return struct.pack(">BHH", 6, addr, val)
inj = []
# Register map: %M2 Start=coil 2, %M3 Stop=coil 3, %M4 Maintenance bypass=coil 4, %M5 Reset=coil 5, %MW0 tank level=HR 0
# S1 t+2  Authorized change: HMI (real MAC) presses Start, %M2=1 via FC15 (how the HMI writes Start)
inj += session(t0+2.0, HMI_IP, HMI_MAC, 50001, [fc15(2, [1])])
# S2 t+4  Authorized source, unsafe action: HMI turns maintenance bypass ON (%M4=1)
inj += session(t0+4.0, HMI_IP, HMI_MAC, 50002, [(fc5(4, 1), None)])
# S3 t+6  Unauthorized host .99: bypass ON, Start ON, then overwrite the level reading (%MW0=0) -> overflow attack
inj += session(t0+6.0, ATK_IP, ATK_MAC, 50003, [(fc5(4, 1), None), (fc5(2, 1), None), (fc6(0, 0), None)])
# S4 t+8  Spoofing: .99's NIC uses the HMI's IP and clears Stop (%M3=0)
inj += session(t0+8.0, HMI_IP, ATK_MAC, 50004, [(fc5(3, 0), None)])
# S5 t+10 Configuration attempt: .99 sends FC90 sub 0x41 (STOP_PLC in UMAS; [UNVERIFIED] for M221)
inj += session(t0+10.0, ATK_IP, ATK_MAC, 50005, [(bytes([90, 0x00, 0x41]), bytes([90, 0x00, 0xFE]))])
# S6 t+11 Authorized source, read-only point: HMI writes %MW0=0 (tank level is computed by the PLC)
inj += session(t0+11.0, HMI_IP, HMI_MAC, 50006, [(fc6(0, 0), None)])
allp = sorted(list(pk) + inj, key=lambda p: float(p.time))
wrpcap(dst, allp)
print(f"{len(pk)} real + {len(inj)} injected = {len(allp)} frames -> {dst}")
