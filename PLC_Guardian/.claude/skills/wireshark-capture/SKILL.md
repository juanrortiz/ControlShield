---
name: wireshark-capture
description: Records a new live packet capture on the PLC lab network with dumpcap from the local Wireshark install, auto-stopping after a set time, then hashes it, makes it read-only, writes a run sheet and drafts the Capture inventory row. Use when the user says "start a capture", "capture traffic", "record the baseline", "capture the attack", "run experiment 1/2/3 capture", or needs a new .pcapng for an experiment or the demo.
---

# Wireshark Capture (dumpcap, live)

Runs on the laptop plugged into the lab network (mirror port or inline Guardian). Passive: it listens, it never sends. Any attack traffic during a capture comes from the team's own tools on the isolated lab network only (CLAUDE.md).

## Setup
Run tools from the Group Project folder exactly as written below. `.claude/settings.json` lets the read-only helper (`bash .claude/skills/wireshark-analyze/scripts/ws.sh ...`) run without a prompt, and **always asks** before `capture.sh`, so the user approves every recording.

`bash .claude/skills/wireshark-analyze/scripts/ws.sh check` must show dumpcap. On Windows, Npcap must be installed (comes with Wireshark); if dumpcap says it can't open the adapter, ask the user to run the terminal as Administrator or reinstall Npcap without "admin-only".

## Steps
1. **Confirm the plan with the user** before capturing (one message): experiment / scenario, interface, duration, capture filter (default: **none**, full evidence), who is operating the HMI/attacker. Wait for go-ahead.
2. **Pick the interface.**
   - `bash .claude/skills/wireshark-analyze/scripts/ws.sh ifaces` lists dumpcap interfaces and IPv4 addresses. On Windows the interface is the name in brackets, e.g. `\Device\NPF_{...} (Ethernet 2)` → `"Ethernet 2"`. The lab NIC has a 192.168.8.x address; a mirror-port NIC may have none, so confirm with the user which cable is in which switch port.
   - **Sanity check (no file kept):** `bash .claude/skills/wireshark-analyze/scripts/ws.sh sanity "IFACE" 10`. Seeing `.10 → .11:502` while this laptop is neither end proves the mirror works. Nothing seen → stop and troubleshoot (cable, port, mirror config) before the real run.
3. **Write the run sheet** `captures/<same-name>_runsheet.md` (create it right before starting): experiment number, scenario, operators, capture host + interface + switch port, host clock UTC and whether it is NTP-synced (Windows `w32tm /query /status`), and a table `| time (UTC) | who | action | expected on the wire |` for the user to fill as they act. Exp. 4 uses it as ground truth.
4. **Capture:**
   ```sh
   bash .claude/skills/wireshark-capture/scripts/capture.sh "IFACE" SECONDS SCENARIO_SLUG ["capture filter"]
   ```
   Slug examples: `exp1_baseline`, `exp2_authorized_start`, `exp3_attacker_bypass`, `demo_iter1`. The script stops on its own (max 3600 s; split longer sessions into several runs). For runs over ~2 minutes start it **in the background** and tell the user when it ends. To stop early, the user presses Ctrl+C in that terminal or you stop the background task; dumpcap still closes the file cleanly.
5. **After the capture** the script prints SHA-256, packets, duration, port 502 frame count and a draft inventory row; the capture is now read-only with a `.sha256` file next to it. Then:
   - Add the inventory row to `project-log/06_REFERENCE.md` → Capture inventory (ask who captured if unknown; never invent it).
   - Remind the user to fill the run sheet while it's fresh.
   - Offer a quick analysis (wireshark-analyze skill) or to open it in the GUI (wireshark-open skill).

## Rules
- Never write a capture over an existing file, and never into the project root next to the original evidence; new captures go in `captures/`.
- Never use a capture filter that drops the traffic the experiment is about. Default is unfiltered; `not ether proto 0x8899` (switch noise) is the only filter worth suggesting.
- Timestamps come from the capture host clock. Record its UTC time and sync status in the run sheet; the HMI clock is wrong and is never a time source.
- One capture per scenario. Don't mix the baseline with attack runs unless it's the Exp. 4 mixed capture on purpose (say so in the run sheet).
- If the capture shows 0 packets or no port 502 traffic, report it plainly; don't hash-and-file an empty capture as an experiment result.

## Output to the user (≤ 8 lines)
File, SHA-256, packets/duration, port 502 frames, warnings, and the next step (fill run sheet → analyze).
