# EXP_2 — Maintenance-bypass write

`scripts/plc_lab_client.py` is the supplied lab client, copied from
`attackerCode/plc_lab_client.py`. Only its experiment-number comments were
updated. Run it from the authorized attacker workstation (`192.168.8.99`) against
the isolated simulated process on the lab PLC (`192.168.8.11:502`).

## Setup

The examples use Bash on Linux. From the repository root:

```bash
cd EXP_2
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/plc_lab_client.py --help
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "results/$RUN_ID"
python --version > "results/$RUN_ID/environment.txt"
python -m pip freeze >> "results/$RUN_ID/environment.txt"
```

For later sessions, activate the existing environment and create a new `RUN_ID`.
The pinned dependency matches EXP_3 so the two experiments use the same API
version. No other third-party Python packages are imported by this client.

## Run

1. Verify the deployed mapping: zero-based Modbus coil address `4` corresponds
   to `%M4`, the maintenance bypass. The repository records this mapping in
   [Guardian's reference](../PLC_Guardian/project-log/06_REFERENCE.md).
   The client's default unit ID is `1`; verify it against the deployed PLC.
2. Record the initial bypass state and tank level. Establish bypass OFF and
   prepare the normal HMI fill cycle so any resulting process effect can be
   observed. This command changes the bypass; it does not start the fill cycle.
3. Start Guardian/Wireshark capture, then issue the write:

```bash
python scripts/plc_lab_client.py 192.168.8.11 \
  --mode write-coil --coil 4 --value 1 --confirm-simulation-only \
  --log "results/$RUN_ID/attacker_events.jsonl" \
  > "results/$RUN_ID/console.txt" 2>&1
cat "results/$RUN_ID/console.txt"
```

4. Record the write response, readback, HMI/PLC level and overload state, and
   Guardian alerts. Enabling bypass can allow the simulated level past 80%;
   verify the actual process effect rather than assuming it from the write.
5. After observing the trial, restore the established bypass-OFF state:

```bash
python scripts/plc_lab_client.py 192.168.8.11 \
  --mode write-coil --coil 4 --value 0 --confirm-simulation-only \
  --log "results/$RUN_ID/attacker_events.jsonl" \
  > "results/$RUN_ID/restore_console.txt" 2>&1
cat "results/$RUN_ID/restore_console.txt"
```

6. Verify bypass OFF independently in the HMI/PLC, then use the normal HMI reset
   procedure. Setting bypass OFF does not itself reset the tank or alarm. Stop
   the capture after restoration and record UTC end time.

## Evidence and interpretation

Keep the JSONL event log, console outputs, PCAP, Guardian alerts, and `notes.md`
under the run directory, or link to centrally stored evidence. Record the exact
commands, UTC times, initial/final state, unit ID, Guardian configuration, and
process observations. Include restoration traffic in the timeline.

`write-coil` does **not** restore automatically. Its confirmation flag is an
operator acknowledgement; it does not check whether the target is a simulation.
Readback can be unavailable, and the client can log `connection_failed` without
returning a nonzero exit status. Inspect the logs and PLC state. Distinguish a
write attempt, a successful protocol response, a matching readback, and an
independently observed process effect. A Guardian alert alone does not prove
that traffic was blocked.
