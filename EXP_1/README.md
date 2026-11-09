# EXP_1 — Network reconnaissance with Nmap

Run these commands from the authorized attacker workstation (`192.168.8.99`),
against the isolated lab PLC (`192.168.8.11`) and HMI (`192.168.8.10`).
This experiment measures service exposure and Guardian's response to scanning.
Capture normal HMI operation separately before beginning reconnaissance.

## Setup

Install Nmap on the attacker workstation. The examples below use Bash on Linux.
From the repository root:

```bash
cd EXP_1
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "results/$RUN_ID"
nmap --version > "results/$RUN_ID/nmap_version.txt"
ip -brief address
```

Verify the lab interface name and its assigned address. Replace `eth0` below
if needed; `192.168.8.99` should be the workstation's actual lab address.
The first two commands use raw-packet options and require suitable privileges
(typically `sudo` on Linux). `-S` specifies a source address; it does not assign
that address to the interface. The `-sT` commands use the OS-selected source
address, so verify that the lab route selects `192.168.8.99`.

Start Guardian/Wireshark capture before each selected scan and record its UTC
start/end time. Run one scan at a time; the last command includes the HMI scan
from command 3, so document whether these are separate trials or alternatives.

## Commands

These preserve your target lists and scan options, adding `sudo` where needed
and `-oA` to save Nmap output. No separate Python script is needed.

```bash
# 1. PLC: low TCP ports (502 is already included in 1-1024).
sudo nmap -n -e eth0 -S 192.168.8.99 -p 1-1024,502 -T2 192.168.8.11 \
  -oA "results/$RUN_ID/01_plc_low_ports"

# 2. HMI: low TCP ports.
sudo nmap -n -e eth0 -S 192.168.8.99 -p 1-1024,502 -T2 192.168.8.10 \
  -oA "results/$RUN_ID/02_hmi_low_ports"

# 3. HMI: selected web/industrial service ports.
nmap -sT -Pn -n -p 80,443,502,44818,8080 --open 192.168.8.10 \
  -oA "results/$RUN_ID/03_hmi_selected_ports"

# 4. HMI and PLC: same selected ports.
nmap -sT -Pn -n -p 80,443,502,44818,8080 --open 192.168.8.10 192.168.8.11 \
  -oA "results/$RUN_ID/04_hmi_plc_selected_ports"
```

Commands 1–2 do not explicitly select a scan technique. Record the privilege
level and Nmap version because the default technique depends on privileges.
Commands 3–4 explicitly use TCP connect scanning (`-sT`) and skip host discovery
(`-Pn`). Only commands 1–2 request timing template `-T2`.

## Evidence and interpretation

`-oA` saves `.nmap`, `.xml`, and `.gnmap` files for each command. Store the
associated PCAP, Guardian alerts, and a `notes.md` alongside them, or record
links to centrally stored evidence. Include the exact command, source/interface,
UTC times, capture location, Guardian configuration, and observed alerts.

An open port establishes a reachable TCP service; a port-number label alone does
not verify its implementation or identify a vulnerability. Keep these scan
results distinct from the normal-operation baseline.

References: [Nmap scan techniques](https://nmap.org/book/man-port-scanning-techniques.html),
[source/interface options](https://nmap.org/book/man-bypass-firewalls-ids.html),
[output formats](https://nmap.org/book/man-output.html).
