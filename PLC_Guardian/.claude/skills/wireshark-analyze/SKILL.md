---
name: wireshark-analyze
description: Analyzes PLC Guardian packet captures (.pcapng/.pcap) read-only with tshark and capinfos from the local Wireshark install - hash check, traffic overview, Modbus/TCP census, writes, FC 90, exceptions, who-talked-to-the-PLC, spoofed MACs, timelines - and writes cited results to analysis/. Use when the user asks to analyze, inspect, decode, summarize or compare a capture, asks "what's in this pcap", "any writes?", "who talked to the PLC", or a new capture appears in the folder.
---

# Wireshark Analyze (tshark, read-only)

Captures are evidence (CLAUDE.md). This skill only **reads** them.

## How to run the tools (important)
Run **every** Wireshark command through the read-only wrapper, from the Group Project folder, written exactly like this:
```sh
bash .claude/skills/wireshark-analyze/scripts/ws.sh <command> ...
```
`.claude/settings.json` allows this exact prefix without a prompt; any other form (`tshark ...`, a full path, `$TSHARK`, backslashes, `cd` first, a `> file` redirect) will prompt the user. Below, `WS` stands for that prefix; always type it out in full.

| Command | Does |
|---|---|
| `WS check` | Finds the tools, prints paths + version. Run once per session; if tshark is missing, stop and tell the user |
| `WS verify FILE...` | SHA-256 now vs `06_REFERENCE` inventory and the `.sha256` file: MATCH / MISMATCH / NOT IN INVENTORY |
| `WS census FILE` | Modbus requests grouped by src/dst/unit/FC/address/qty (+ FC 90 sub-code) with first/last frame; all writes; request/response/exception/unanswered counts; MACs per IP |
| `WS capinfos [opts] FILE` | capinfos |
| `WS tshark [--out analysis/NAME.csv] -r FILE [opts]` | tshark with `-n` added. Refuses `-w -i -f -F -b -a -o -X` and other write/live/code options. `--out` saves stdout to `.csv/.tsv/.txt/.md/.json` under `analysis/` (use it instead of `>`) |
| `WS sha256 FILE...` | Hash only |

Don't chain with `&&`/`;`/`|` unless every part is allowed; one wrapper call per tool call is simplest. Grouping beyond `census` can be done in Python over an `--out` CSV (that step will prompt; that's fine).

No Wireshark on this machine (e.g. a cloud session): install tshark (`apt-get install -y tshark`), work on a copy, and say so in the output header.

## Steps
1. **Identify + hash:** `WS verify FILE`. MATCH → say so. MISMATCH → stop and report (possible altered evidence). NOT IN INVENTORY → flag as new evidence and offer the inventory row (date, who, scenario, duration/packets, SHA-256). Files named `*synthetic*` or built by a script are **[SYNTHETIC]**, never lab evidence (injected frames in `mixed_pm3_synthetic.pcap` have IP TTL 99).
2. **Overview:** `WS capinfos -c -u -a -e -t -E FILE`, `WS tshark -r FILE -q -z io,phs`, `WS tshark -r FILE -q -z conv,tcp`, and `WS census FILE` for anything with Modbus.
3. **Answer the question** with the recipes below (`reference.md` has field names). Save per-frame data with `--out` and count from the file instead of eyeballing.
4. **Write results** to `analysis/S-###_<topic>.md` (+ CSVs), S-### = current session (highest in `project-log/04_SESSION_LOG.md` + 1 if not started). Header: date, tshark version, "read-only, captures not modified". Every finding cites **file, frame number(s), display filter**. End with a "Reproduce" block holding the exact `WS ...` commands.
5. **Re-run `WS verify FILE`** at the end and state that the SHA-256 is unchanged.
6. New facts (IPs, MACs, registers, FCs) go in the summary as proposed `06_REFERENCE` additions; session-close writes them. Inferences stay `[UNVERIFIED]`.

## Recipes (verified on `Port_mirroring_test_3.pcapng` / `mixed_pm3_synthetic.pcap`, tshark 4.2; prefix each with `WS tshark -r FILE`)
| Question | Options |
|---|---|
| All Modbus frames to CSV | `--out analysis/S-###_<file>_mbtcp.csv` (before `-r`) then `-Y mbtcp -T fields -E header=y -E separator=, -E quote=d -e frame.number -e frame.time_utc -e ip.src -e eth.src -e tcp.srcport -e ip.dst -e tcp.dstport -e mbtcp.trans_id -e mbtcp.unit_id -e modbus.func_code -e modbus.request_frame -e modbus.reference_num -e modbus.bit_cnt -e modbus.word_cnt -e modbus.byte_cnt -e modbus.exception_code -e modbus.data -e modbus.bitval -e modbus.regval_uint16` |
| Who talks to the PLC | `-q -z conv,tcp,tcp.port==502` |
| Any writes? | `-Y "tcp.dstport==502 && modbus.func_code in {5,6,15,16,23}"` (or just `WS census`) |
| Writes from a non-allowlisted host | `-Y "tcp.dstport==502 && modbus.func_code in {5,6,15,16,23} && !(ip.src in {192.168.8.10,192.168.8.50})"` |
| Same IP, different MAC | `WS census` (last section) or `-Y "ip.src==192.168.8.10 && eth.src!=00:00:54:0b:c5:9a" -T fields -e frame.number` |
| FC 90 other than the HMI's 0x74 poll | `-Y "tcp.dstport==502 && modbus.func_code==90 && !(modbus.data contains 00:74)" -T fields -e frame.number -e ip.src -e modbus.data` |
| Exceptions | `-Y "modbus.func_code>=128" -T fields -e frame.number -e ip.src -e modbus.func_code -e modbus.exception_code` |
| Coil states (`%M2`-`%M5`) | `-Y "tcp.srcport==502 && modbus.func_code==1" -T fields -e frame.number -e modbus.request_frame -e modbus.bitval` (`True,True,True,False` = `%M2,%M3,%M4` ON) |
| Tank level `%MW0` over time | `-Y "tcp.srcport==502 && modbus.func_code==3" -T fields -e frame.number -e frame.time_relative -e modbus.regval_uint16` (first value = `%MW0`) |
| Request/response latency | `-Y "tcp.srcport==502" -T fields -e frame.number -e modbus.request_frame -e modbus.response_time` |
| HMI web channel (R-004) | `-Y "http.request" -T fields -e frame.number -e ip.src -e http.request.method -e http.request.uri` |
| Requests per second (figure data) | `-q -z io,stat,1,"mbtcp && tcp.dstport==502"` |
| Full decode of one frame (report appendix) | `-Y "frame.number==N" -V -O mbtcp,modbus` |
| Byte stream of a conversation | `-q -z follow,tcp,hex,STREAM` (stream index from `-T fields -e tcp.stream`) |
| Exclude switch noise | add `&& !(eth.type==0x8899)` to the filter |

Slicing a subset for a teammate needs editcap, which writes a file, so it is not in the wrapper and will prompt: `editcap -r FILE analysis/S-###_<name>_frames_A-B.pcapng A-B` (new file only, never over evidence; hash it and call it derived).

## Traps
- Set syntax needs **commas** in Wireshark 4.2+: `{5,6,15,16,23}`. `{5 6 15 16 23}` (in older notes) errors out.
- `capinfos` and default tshark times are in the **analysis machine's** time zone. Use `frame.time_utc` / `-t ud` for evidence and say "UTC". The HMI's own clock is wrong (31 Dec 1999); never use it.
- `-c N` counts packets **read**, not packets matching `-Y`.
- The HMI uses unit 255 and TID 0; pair requests/responses with `modbus.request_frame`, not TID.
- Mirror captures can miss the TCP handshake (session already open). Wireshark still decodes Modbus; say the SYN isn't in the file.
- A PLC bit can change with no Modbus write (I-004). "No write in the capture" ≠ "nobody changed it".
- Big result sets: save with `--out` and summarize; never paste thousands of rows into the chat.

## Output to the user (≤ 12 lines)
File + SHA-256 status → key findings with frames/filters → where the full write-up is → open questions. Offer to open the interesting frames in the GUI (wireshark-open skill).
