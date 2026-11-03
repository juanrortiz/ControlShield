# Run sheet — hmi_q02_overload_flag

- **Scenario:** New HMI flag check. `%Q0.2` (physical output) now sent to the PLC over Modbus so Guardian/Wireshark can see the overload signal that was previously invisible (local/proprietary device output only).
- **Capture host / interface:** This laptop, interface "Ethernet 4" (192.168.8.50)
- **Host clock:** UTC at capture start [see capture header]. `w32tm /query /status`: **NOT synchronized** (Leap Indicator 3); last successful sync 2026-11-02 16:04:59 local (~9.5h before this capture). Timestamps are host-clock-relative; do not treat as NTP-accurate. [UNVERIFIED precision]
- **Duration:** 60s, no capture filter (full evidence)
- **Operators:** Juan Ortiz (HMI/PLC)
- **Expected:** `%Q0.2` visible on the wire (coil read and/or write) in addition to the existing FC1/FC3/FC90 poll pattern; value should reflect overload state (0 = normal, 1 = overload) if the team drives the process into overload during the window.
- **Thresholds (from team, 2026-11-02):** same level signal as `%MW0` (tank level) in `06_REFERENCE.md`. ≥80 = warning (existing stop threshold); >100 = overload (new). `%Q0.2` is expected to assert when `%MW0` crosses 100, not at the existing 80 stop.

| time (UTC) | who | action | expected on the wire |
|---|---|---|---|
| | | capture started | |
| | | | |
| | | | |
| | | capture stopped | |

**Fill this table during/right after the capture — frame numbers and exact actions, not estimates.**
