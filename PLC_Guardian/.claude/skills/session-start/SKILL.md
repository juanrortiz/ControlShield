---
name: session-start
description: Opens a work session on the PLC Guardian group project by loading the project log, confirming the goal and proposing a plan. Use when the user says "start session", "new session", "pick up where we left off", or states a goal at the start of work.
---

# Session Start

## Steps
1. Read `project-log/01_STATUS.md` and `project-log/02_NEXT_STEPS.md` in full. Scan `03_DECISIONS.md` titles; open only related decisions. Read the relevant parts of `06_REFERENCE.md` and open items in `05_RAID_LOG.md`. Don't read `04_SESSION_LOG.md` unless asked.
2. Check the folder for new files since the last session (new captures, reports). A new `.pcapng` not in the Capture inventory gets flagged.
3. Next session ID = highest S-### in `04_SESSION_LOG.md` + 1.
4. Flag conflicts: goal vs an Accepted decision, out of scope per the brief, a P1 or open Issue that should come first, an upcoming deadline in the brief.

## Output (≤ 15 lines)
```
S-### · <topic>
Goal: <concrete restatement>
Linked: A-### · I-### · D-###
Context: 2–4 bullets from the files
⚠️ <conflict, deadline or higher-priority item, only if any>
Plan:
1. …
2. …
3. Verify: <how we'll know it's right: frame numbers, filter results, test run>
```
End with: "Go ahead, or adjust?"

## Rules
- Never invent IDs or facts not in the files. If files are still templates, say so and offer to fill the brief first.
- If the user says "just do it", give the one-line Goal + Linked, then do the work.
