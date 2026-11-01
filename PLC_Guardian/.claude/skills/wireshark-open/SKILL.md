---
name: wireshark-open
description: Launches the Wireshark GUI on a PLC Guardian capture with a display filter applied and/or jumped to a specific frame, so the user can see the packets Claude is citing or take a screenshot for the report. Use when the user says "open it in Wireshark", "show me", "pull up frame N", "launch Wireshark", or wants a figure of the capture for the IEEE report or the demo.
---

# Wireshark Open (GUI)

## Command
From the Group Project folder:
```sh
bash .claude/skills/wireshark-open/scripts/open.sh "<capture>" ["<display filter>"] [<frame>]
```
- Write it exactly like that, from the Group Project folder: `.claude/settings.json` allows this prefix without a prompt.
- Finds Wireshark via `.claude/skills/wireshark-analyze/scripts/wstools.sh` (Windows: `C:\Program Files\Wireshark\Wireshark.exe`).
- Checks the filter with tshark first and prints how many frames match; a bad filter is reported and the GUI is not opened.
- Starts Wireshark **detached** (PowerShell `Start-Process` on Windows), so the command returns at once. Don't wait for the window to close.
- `-g <frame>` jumps to that frame number (the same numbers cited in `analysis/` and `06_REFERENCE`).

## When to use
- After an analysis, to show the evidence behind a finding: open with the exact filter and first frame cited.
- For report/demo figures: pick a filter that tells the story in one screen, then tell the user what to capture (e.g. packet list + expanded Modbus tree). Screenshots are taken by the user.
- To show teammates a capture with a useful starting view.

## Good starting views (from `06_REFERENCE`)
| Purpose | Filter | Frame |
|---|---|---|
| All Modbus | `mbtcp` | |
| HMI poll cycle | `mbtcp && ip.addr==192.168.8.10` | first FC1 request |
| Writes only | `tcp.dstport==502 && modbus.func_code in {5,6,15,16,23}` | first write |
| Attacker activity | `ip.addr==192.168.8.99` | |
| FC 90 not the HMI poll | `modbus.func_code==90 && !(modbus.data contains 00:74)` | |
| Coil states over time | `modbus.func_code==1 && tcp.srcport==502` | |
| Exceptions | `modbus.func_code>=128` | |
| Hide switch noise | append `&& !(eth.type==0x8899)` | |

## Rules
- Evidence stays untouched: Wireshark only reads the file. If the user wants a subset, use **File → Export Specified Packets** to a new file under `analysis/` (or `editcap`, see wireshark-analyze), never **Save** over the original.
- Use comma-separated sets (`{5,6,15,16}`); Wireshark 4.2+ rejects the space-separated form.
- If no GUI is available (cloud session, SSH), say so and give the filter + frame so the user can open it themselves.
- Reply in one or two lines: what was opened, filter, frame, match count.
