# tshark field reference for PLC Guardian

Field names below were checked with tshark 4.2 on `Port_mirroring_test_3.pcapng` and `mixed_pm3_synthetic.pcap`. Look up anything else with `bash .claude/skills/wireshark-analyze/scripts/ws.sh tshark -G fields` and search the output for `modbus`.

## Frame / link / IP / TCP
| Field | Meaning |
|---|---|
| `frame.number` | Wireshark frame number (cite this) |
| `frame.time_utc` | Absolute time, UTC (contains a comma: use `-E quote=d`) |
| `frame.time_epoch` | Seconds since 1970, easiest for Python |
| `frame.time_relative` | Seconds since first frame |
| `eth.src` / `eth.dst` | MAC addresses (spoofing check) |
| `eth.type` | 0x8899 = Realtek switch loop detection (noise) |
| `ip.src` / `ip.dst` / `ip.ttl` | TTL 99 marks injected frames in the synthetic capture |
| `tcp.srcport` / `tcp.dstport` / `tcp.stream` | Requests go to 502; responses come from 502 |
| `tcp.analysis.retransmission` | Retransmitted segments |

## Modbus/TCP (`mbtcp`) and Modbus PDU (`modbus`)
| Field | Meaning |
|---|---|
| `mbtcp.trans_id` | Transaction ID (HMI always 0) |
| `mbtcp.prot_id` | Protocol ID, must be 0 |
| `mbtcp.len` | MBAP length |
| `mbtcp.unit_id` | Unit ID (HMI 255, pymodbus test 1) |
| `modbus.func_code` | Function code; >=128 = exception reply |
| `modbus.exception_code` | Exception number |
| `modbus.request_frame` | In a response: frame number of its request |
| `modbus.response_time` | Seconds between request and response |
| `modbus.reference_num` | Start address (coil / register) |
| `modbus.bit_cnt` / `modbus.word_cnt` / `modbus.byte_cnt` | Quantity / byte count |
| `modbus.bitval` | Coil values in an FC1 response, from the start address, `True/False` list |
| `modbus.regval_uint16` | Register values in an FC3 response, comma list |
| `modbus.data` | Raw data: FC5 value (`ff00` = ON, `0000` = OFF), FC6 value, FC15 packed bits, FC90 payload |

## Lab constants (from `project-log/06_REFERENCE.md`; re-read it, it may have changed)
| Host | IP | MAC |
|---|---|---|
| PLC | 192.168.8.11:502 | 00:80:f4:54:1d:67 |
| HMI | 192.168.8.10 | 00:00:54:0b:c5:9a |
| Engineering laptop | 192.168.8.50 | a0:ce:c8:62:e9:e1 |
| HMI-config laptop / planned attacker | 192.168.8.99 | 00:e0:4c:1d:3d:70 |

| Point | Modbus |
|---|---|
| `%M2` Start / `%M3` Stop / `%M4` Bypass / `%M5` Reset | coils 2 / 3 / 4 / 5 |
| `%MW0` tank level / `%MW1` unknown | holding registers 0 / 1 |
| HMI poll | FC1 addr 2 qty 4 → FC90 `00 74 01 82 00 00 00 01` → FC3 addr 0 qty 2, every ~250 ms |
