---
name: maker-checker
description: Builder implements a Guardian change, you run the checks, architect reviews independently. Repeats until the review passes (max 3 rounds). Use for code changes in guardian/ or tools/.
argument-hint: <task>
---
Task: $ARGUMENTS

Before starting: this folder is not a git repo, so snapshot first. List the files the task will touch and copy them to the scratchpad (`*.bak`) so a diff is possible; never include `.pcap`/`.pcapng`. Check `project-log/03_DECISIONS.md`; if the task conflicts with a decision, say so in one line and ask.

Each round:
1. Send the task (plus any findings from the last round) to builder, with a full brief: exact files it owns, the verification commands, "do not commit", the evidence rules.
2. YOU run the verification commands yourself and print the result (e.g. `python guardian/guardian.py` analyze on a copy of a capture; expected results come from `project-log/01_STATUS.md` such as PM3 150/150 ALLOW). The test command is [UNVERIFIED] until a suite exists; don't trust the builder's report.
3. Send architect only: the task, the binding decisions, the check output, a diff against the snapshot, and paths of new files. It reads the files itself.
4. Print architect's reply, which ends in VERDICT: PASS or FAIL.
5. Print: ROUND <n> COMPLETE: checks exit <code>, verdict <PASS|FAIL>
If FAIL, send the findings to builder for the next round. Stop after 3 rounds and report the blocker.
Never modify, rename or delete captures. Never weaken a check to make it pass. Tell the user which `docs/GUARDIAN_DESIGN.md` sections and project-log entries need updating (session-close does this).
