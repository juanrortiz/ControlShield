---
name: status-report
description: Produces a short PLC Guardian status update for teammates or the professor from the project log. Use when the user says "status report", "progress update", "what's our status", or needs a checkpoint summary.
---

# Status Report

## Steps
1. Read `01_STATUS.md`, `02_NEXT_STEPS.md`, open items in `05_RAID_LOG.md`, deliverables in `00_PROJECT_BRIEF.md`, and the `04_SESSION_LOG.md` entries since the date the user gives (default: last 7 days).
2. Write the update. Read-only: don't change any files.

## Format (≤ 1 page)
```
PLC Guardian · Status · <date>
Overall: On track / At risk / Behind, with one-line reason
Done since <date>:
- …
Next (owner · due):
- …
Risks / blockers:
- …
Upcoming deadlines:
- …
```

## Rules
- Only claims backed by the log. Anything tagged `[REPORTED]` or `[UNVERIFIED]` keeps its tag.
- Name owners; no internal IDs unless the audience is the team.
