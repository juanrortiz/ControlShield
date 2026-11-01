# Run sheet: exp1_baseline

| Field | Value |
|---|---|
| Experiment | 1 Normal traffic |
| Scenario | Baseline: HMI polling only, bypass %M4 OFF, level should hold at 80. Expect FC1/FC90 0x74/FC3 from .10, unit 255, no writes. |
| Date | 2026-10-21 |
| Capture file | captures/2026-10-21_exp1_baseline.pcapng |
| Capture host / interface / switch port | Guardian laptop / [fill in] / port 5 (mirror of PLC port 4, both directions) |
| Host clock (UTC) at start, NTP synced? | [fill in: w32tm /query /status] |
| HMI operator | [fill in] |
| Attacker operator (.99) | [fill in, exp3 only] |
| Captured by | [fill in] |
| SHA-256 | [fill in after stop: Get-FileHash .\2026-10-21_exp1_baseline.pcapng -Algorithm SHA256] |

## Ground truth (fill in as you act; use the laptop clock, never the HMI clock)

| Time (local, laptop clock) | Who | Action | Expected on the wire |
|---|---|---|---|
| | | Capture started | |
| | | | |
| | | Capture stopped | |

## Notes
