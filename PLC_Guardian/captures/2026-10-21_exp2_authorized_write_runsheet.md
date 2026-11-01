# Run sheet: exp2_authorized_write

| Field | Value |
|---|---|
| Experiment | 2 Authorized change |
| Scenario | Authorized write from the HMI (.10). Fill in which button / coil. |
| Date | 2026-10-21 |
| Capture file | captures/2026-10-21_exp2_authorized_write.pcapng |
| Capture host / interface / switch port | Guardian laptop / [fill in] / port 5 (mirror of PLC port 4, both directions) |
| Host clock (UTC) at start, NTP synced? | [fill in: w32tm /query /status] |
| HMI operator | [fill in] |
| Attacker operator (.99) | [fill in, exp3 only] |
| Captured by | [fill in] |
| SHA-256 | [fill in after stop: Get-FileHash .\2026-10-21_exp2_authorized_write.pcapng -Algorithm SHA256] |

## Ground truth (fill in as you act; use the laptop clock, never the HMI clock)

| Time (local, laptop clock) | Who | Action | Expected on the wire |
|---|---|---|---|
| | | Capture started | |
| | | | |
| | | Capture stopped | |

## Notes
