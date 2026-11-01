---
name: session-close
description: Closes a work session on the PLC Guardian project by updating the project log files directly (session log, decisions, RAID, status, next steps, reference) after the user approves a change summary. Use when the user says "close session", "end session", "wrap up", "log this", or "update the docs".
---

# Session Close (direct-write)

Files are in `project-log/`: `00_PROJECT_BRIEF.md` … `06_REFERENCE.md`.

## Rules
- **History is append-only:** `03_DECISIONS`, `04_SESSION_LOG`, `05_RAID_LOG` get new entries at the end, or a single Status-cell change on an existing row. Never rewrite or delete past entries.
- **State is rewritten within caps:** `01_STATUS` ≤ one screen; `02_NEXT_STEPS` ≤ 15 open items (move lowest P3 to the Parking lot).
- **Reference grows by deltas:** add lines to `06_REFERENCE`; change a line only to correct it.
- **Only what happened:** use this session's real evidence (frame numbers, filters, outputs, hashes). Claude's suggestions are not decisions unless the user agreed.
- **Claimed vs verified:** anything not checked against a capture or test is marked `[REPORTED]` or gets a verify action.
- **Credit teammates** by name when they did the work; owners on actions must be real team members or "Team".
- **Never touch `.pcapng` files.**

## Steps
1. Review this session. Extract: what was produced, what was verified and how, decisions agreed, new/closed risks, assumptions, issues, dependencies, new reference facts (IPs, registers, filters, captures), actions done/created, parking-lot ideas.
2. Get next IDs (S, D, A, R, AS, I, X) by continuing the highest in each file.
3. Draft the changes. Show a **short change summary** (file → what changes) and ask "Write these?"
4. On yes, write the files. Then report: files changed, anything still unverified, suggested focus for next session (≤ 3 lines).

## Session log entry (≤ 8 lines)
```
### S-### · YYYY-MM-DD · <topic>
- **Goal:**
- **Done:**
- **Verified:**
- **Decisions:**
- **RAID:**
- **Next:**
- **Notes:** (optional)
```

## Quality checks
- Every new A-### has an owner and "Done when".
- Every D-### has options, rationale, consequences.
- Every referenced ID exists or is created now.
