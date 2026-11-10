# EXP_1 — Network reconnaissance with Nmap

Run this scan from the authorized attacker workstation (`192.168.8.99`),
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

Verify the lab interface and its assigned address. The TCP connect scan uses
the OS-selected source address, so verify that the lab route selects
`192.168.8.99`.

Start Guardian/Wireshark capture before the scan and record its UTC start/end
time.

## Scan command

Scan the selected ports on both the HMI and PLC, saving Nmap output with `-oA`.
No separate Python script is needed.

```bash
# HMI and PLC: selected web/industrial service ports.
nmap -sT -Pn -n -p 80,443,502,44818,8080 --open 192.168.8.10 192.168.8.11 \
  -oA "results/$RUN_ID/04_hmi_plc_selected_ports"
```

This command explicitly uses TCP connect scanning (`-sT`), skips host discovery
(`-Pn`), and disables DNS resolution (`-n`). It scans TCP ports `80`, `443`,
`502`, `44818`, and `8080` on both targets and displays only open or possibly
open ports (`--open`).

## Evidence and interpretation

`-oA` saves `.nmap`, `.xml`, and `.gnmap` files for the scan. Store the
associated PCAP, Guardian alerts, and a `notes.md` alongside them, or record
links to centrally stored evidence. Include the exact command, source/interface,
UTC times, capture location, Guardian configuration, and observed alerts.

An open port establishes a reachable TCP service; a port-number label alone does
not verify its implementation or identify a vulnerability. Keep these scan
results distinct from the normal-operation baseline.

References: [Nmap scan techniques](https://nmap.org/book/man-port-scanning-techniques.html),
[source/interface options](https://nmap.org/book/man-bypass-firewalls-ids.html),
[output formats](https://nmap.org/book/man-output.html).
