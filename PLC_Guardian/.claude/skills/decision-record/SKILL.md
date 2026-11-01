---
name: decision-record
description: Records a PLC Guardian project decision as a numbered D-### entry with context, options, rationale and consequences. Use when the user says "log decision", "record this decision", "we're going with X", or when the team agrees on a tool, method, scope or design change.
---

# Decision Record

## Worth recording when
- It's hard to reverse (tool choice, detection method, capture setup, report structure).
- It changes scope, a deliverable, or who does what.
- The professor or a teammate may later ask "why this way?"
- It supersedes an earlier decision.

Skip routine choices (file names, formatting).

## Steps
1. Confirm the team actually agreed. If not, record as **Proposed**.
2. Next ID = highest D-### in `project-log/03_DECISIONS.md` + 1.
3. Draft the entry from the template in that file: context (2–3 sentences), at least two real options with pro/con, decision, rationale tied to the brief, consequences and follow-up A-###.
4. If it supersedes D-###, change only that entry's Status to "Superseded by D-###".
5. Show the entry, ask "Write it?", then append it. Add any follow-up actions to `02_NEXT_STEPS.md`.
