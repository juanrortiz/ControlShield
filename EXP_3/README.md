# EXP_3 — PLC discovery and fingerprinting

`scripts/plc_discovery.py` is the supplied `attackerCode/plc_blackbox_test.py`,
renamed to describe its purpose. Only filename references in its documentation
were updated; runtime behavior is unchanged. Run it from the authorized attacker
workstation (`192.168.8.99`) against the isolated lab PLC (`192.168.8.11`).

The pipeline performs four stages: TCP service discovery, Modbus device
identification, coil/register enumeration, and behavioral inference. It sends
Modbus reads, not maintenance-bypass writes. Since the target IP is supplied,
this is discovery of a known host, rather than a zero-knowledge host search.

## Setup

The examples use Bash on Linux. From the repository root:

```bash
cd EXP_3
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/plc_discovery.py --help
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "results/$RUN_ID"
python --version > "results/$RUN_ID/environment.txt"
python -m pip freeze >> "results/$RUN_ID/environment.txt"
```

For later sessions, activate the existing environment and create a new `RUN_ID`.
Keep `pymodbus==3.7.4`: the script imports simulator classes and uses client
signatures from that version, even when targeting the lab PLC.

## Run

Start Guardian/Wireshark capture, record the initial HMI/PLC state and UTC start
time, then run:

```bash
python -u scripts/plc_discovery.py --host 192.168.8.11 --port 502 \
  > "results/$RUN_ID/discovery_report.txt" 2>&1
cat "results/$RUN_ID/discovery_report.txt"
```

This is your supplied command with the new script path and an output file.
The default address range is `0` through `19` (`--range 0 20`, end exclusive),
with 20 polling samples and a 0.3-second pause between sweeps. Total duration
also includes network requests and timeouts. Modbus unit ID defaults to `1`
inside the functions; there is no CLI unit-ID option.

Discovery tries TCP ports `502`, `102`, `44818`, `20000`, `2404`, `789`, `1911`,
and `4840` on the given host. `--port 502` selects the later Modbus stages;
it does not restrict the initial port scan to 502. This differs from EXP_1's
Nmap port lists and does not scan the HMI.

An optional local smoke run uses the built-in fake PLC on `127.0.0.1:5020`:

```bash
python -u scripts/plc_discovery.py --demo \
  > "results/$RUN_ID/local_demo.txt" 2>&1
```

The demo has its own synthetic register map. Keep its output separate from
hardware results; it does not validate the deployed PLC mapping.

## Evidence and interpretation

Save the report, associated PCAP, Guardian alerts, and a `notes.md` in the run
directory, or link to centrally stored evidence. Record the exact command,
UTC times, source IP, Python/package versions, Guardian configuration, observed
PLC state, and any exceptions or incomplete stages. Stop the capture after the
pipeline finishes.

Device identification may be unsupported or refused. An exception or failed
connection is a result to record, not a completed fingerprint. Behavior labels,
float candidates, and correlations are hypotheses; compare them with the actual
PLC program before assigning meaning to addresses. The script prints its report
to the console and does not export the pipeline return value as a JSON file.
