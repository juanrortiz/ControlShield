"""Replay the HMI's real request PDUs from the capture (plus attacker writes) through the
Guardian proxy -> mock PLC, and report which ones get through. Loopback only."""
import json, socket, struct, subprocess, sys, time, os
from scapy.all import rdpcap, TCP, IP
cfg_in, pcap, guardian_dir, tag = sys.argv[1:5]
pdus = []
for p in rdpcap(pcap):
    if TCP in p and p[TCP].dport == 502 and p[IP].src == "192.168.8.10":
        pl = bytes(p[TCP].payload)[: p[IP].len - p[IP].ihl*4 - p[TCP].dataofs*4]
        if len(pl) >= 8 and pl[7:] not in [x for x in pdus]:
            pdus.append(pl[7:])      # unique PDUs: FC1, FC3, FC90/0x74
c = json.load(open(cfg_in))
hmi = c["authorized_sources"].pop("192.168.8.10"); hmi.pop("mac", None)
c["authorized_sources"]["127.0.0.1"] = hmi                      # loopback stands in for the HMI
c["proxy"].update(listen_host="127.0.0.1", listen_port=15021, upstream_host="127.0.0.1", upstream_port=15020)
c["enforcement"]["mode"] = "block"; c["log"]["path"] = f"logs/proxy_{tag}.jsonl"
cfgp = f"config_proxytest_{tag}.json"; json.dump(c, open(os.path.join(guardian_dir, cfgp), "w"), indent=2)
mock = subprocess.Popen([sys.executable, "tools/mock_plc.py", "--port", "15020"], cwd=guardian_dir, stdout=subprocess.DEVNULL)
prox = subprocess.Popen([sys.executable, "guardian.py", "--config", cfgp, "proxy"], cwd=guardian_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
def send(pdu, bind, unit=255):
    s = socket.create_connection(("127.0.0.1", 15021), timeout=3, source_address=(bind, 0))
    s.sendall(struct.pack(">HHHB", 7, 0, len(pdu)+1, unit) + pdu); r = s.recv(260); s.close()
    if not r: return "connection closed"
    fc = r[7]
    return f"EXCEPTION code {r[8]}" if fc & 0x80 else "forwarded, PLC answered OK"
names = {1: "FC1 read %M2..%M5", 3: "FC3 read %MW0..%MW1", 90: "FC90 sub 0x74 poll"}
for pdu in pdus:
    print(f"  HMI      {names.get(pdu[0], pdu.hex()):28} -> {send(pdu, '127.0.0.1')}  [real poll from capture]")
tests = [  # register map: %M2 Start=coil 2, %M3 Stop=coil 3, %M4 bypass=coil 4, %MW0 level=HR 0
    ("HMI",      "127.0.0.1", "FC15 %M2=1 Start",           struct.pack(">BHHBB", 15, 2, 1, 1, 1)),
    ("HMI",      "127.0.0.1", "FC5 %M4=1 bypass ON",         struct.pack(">BHH", 5, 4, 0xFF00)),
    ("HMI",      "127.0.0.1", "FC6 %MW0=0 (read-only)",      struct.pack(">BHH", 6, 0, 0)),
    ("HMI",      "127.0.0.1", "FC90 sub 0x41 (STOP?)",       bytes([90, 0, 0x41])),
    ("ATTACKER", "127.0.0.2", "FC5 %M4=1 bypass ON",         struct.pack(">BHH", 5, 4, 0xFF00)),
    ("ATTACKER", "127.0.0.2", "FC5 %M2=1 Start",             struct.pack(">BHH", 5, 2, 0xFF00)),
    ("ATTACKER", "127.0.0.2", "FC6 %MW0=0 fake level",       struct.pack(">BHH", 6, 0, 0)),
    ("ATTACKER", "127.0.0.2", "FC1 read %M2..%M5",           struct.pack(">BHH", 1, 2, 4))]
for who, ip, label, pdu in tests:
    print(f"  {who:8} {label:28} -> {send(pdu, ip)}")
prox.terminate(); mock.terminate(); time.sleep(.5)
