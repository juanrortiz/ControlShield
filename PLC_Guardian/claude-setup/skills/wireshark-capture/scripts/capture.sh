#!/usr/bin/env bash
# Usage (from the Group Project folder):
#   bash .claude/skills/wireshark-capture/scripts/capture.sh <interface> <seconds> <scenario-slug> [capture-filter]
# Captures with dumpcap into captures/<YYYY-MM-DD_HHMMSS>_<slug>.pcapng (never overwrites), stops by itself
# after <seconds>, then hashes the file, writes <file>.sha256, marks the capture read-only and prints a
# draft row for project-log/06_REFERENCE.md -> Capture inventory.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$here/../../wireshark-analyze/scripts/wstools.sh" >/dev/null

if [ $# -lt 3 ]; then sed -n 2,6p "$0"; exit 64; fi
iface=$1; secs=$2; slug=$3; cfilter=${4:-}

[ -n "$DUMPCAP" ] || { echo "dumpcap not found (install Wireshark with Npcap on Windows)" >&2; exit 1; }
case $secs in ''|*[!0-9]*) echo "seconds must be a whole number" >&2; exit 64 ;; esac
[ "$secs" -ge 1 ] && [ "$secs" -le 3600 ] || { echo "seconds must be 1..3600 (split longer runs)" >&2; exit 64; }
slug=$(printf '%s' "$slug" | tr -c 'A-Za-z0-9_-' '_')

mkdir -p captures
out="captures/$(date +%Y-%m-%d_%H%M%S)_${slug}.pcapng"
[ ! -e "$out" ] || { echo "refusing to overwrite $out" >&2; exit 1; }

args=(-i "$iface" -a "duration:$secs" -w "$out")
[ -n "$cfilter" ] && args+=(-f "$cfilter")

start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "Capturing on '$iface' for ${secs}s -> $out"
echo "Capture host clock at start (UTC): $start_utc"
"$DUMPCAP" "${args[@]}"
end_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)

[ -s "$out" ] || { echo "No capture file written - check the interface name and Npcap/permissions." >&2; exit 1; }

sha=$(ws_sha256 "$out")
printf '%s  %s\n' "$sha" "$(basename "$out")" > "$out.sha256"
if [ "$WS_OS" = windows ]; then attrib.exe +R "$(ws_winpath "$out")" >/dev/null 2>&1 || true
else chmod a-w "$out" || true; fi

pk=$("$CAPINFOS" -M -c "$out" 2>/dev/null | awk -F': *' '/Number of packets/{print $2}')
du=$("$CAPINFOS" -M -u "$out" 2>/dev/null | awk -F': *' '/Capture duration/{print $2}')
m502=$("$TSHARK" -n -r "$out" -Y "tcp.port==502" 2>/dev/null | wc -l | tr -d ' ')

echo
echo "Done. Host clock at end (UTC): $end_utc"
echo "File:     $out (read-only)"
echo "SHA-256:  $sha  (also in $out.sha256)"
echo "Packets:  ${pk:-?}   Duration: ${du:-?}   Frames on TCP 502: $m502"
[ "${pk:-0}" = 0 ] && echo "WARNING: 0 packets - wrong interface, cable, or mirror port not configured."
[ "$m502" = 0 ] && echo "WARNING: no Modbus/TCP (port 502) frames in this capture."
echo
echo "Draft inventory row for 06_REFERENCE.md (fill in the brackets):"
echo "| $(basename "$out") | $start_utc - $end_utc UTC | [who] | [scenario: $slug] | ${du:-?} / ${pk:-?} frames | $sha |"
