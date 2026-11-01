#!/usr/bin/env bash
# Read-only front end to the Wireshark tools for PLC Guardian. Claude Code is allowed to run this script
# without asking (see .claude/settings.json), so it must never write to, rename or delete a capture.
#
# Run from the Group Project folder:
#   bash .claude/skills/wireshark-analyze/scripts/ws.sh check
#   bash .claude/skills/wireshark-analyze/scripts/ws.sh verify   FILE...          SHA-256 vs 06_REFERENCE inventory / .sha256 file
#   bash .claude/skills/wireshark-analyze/scripts/ws.sh sha256   FILE...
#   bash .claude/skills/wireshark-analyze/scripts/ws.sh capinfos [capinfos options] FILE...
#   bash .claude/skills/wireshark-analyze/scripts/ws.sh census   FILE             Modbus requests grouped by src/unit/FC/address
#   bash .claude/skills/wireshark-analyze/scripts/ws.sh tshark   [--out analysis/NAME.csv] -r FILE [read-only tshark options]
#   bash .claude/skills/wireshark-analyze/scripts/ws.sh ifaces                     capture interfaces + IPv4 addresses
#   bash .claude/skills/wireshark-analyze/scripts/ws.sh sanity   IFACE [SECONDS]  live 'tcp port 502' peek, max 30 s, no file kept
#
# tshark guard: refuses options that write files, capture live or load code
# (-w -i -f -F -b -a -o -X -k -L -B -I -p -s -y -W -U -C, --export-objects, any other --long option).
# --out writes stdout to a new or existing .csv/.tsv/.txt/.md/.json file under analysis/ only.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$here/wstools.sh" >/dev/null 2>&1

die() { echo "ws.sh: $*" >&2; exit 2; }
need() { [ -n "${!1:-}" ] || die "$1 not found - run: bash .claude/skills/wireshark-analyze/scripts/ws.sh check"; }
is_capture() { case "${1,,}" in *.pcap|*.pcapng|*.cap|*.pcap.gz|*.pcapng.gz|*.erf|*.snoop) return 0;; esac; return 1; }

check_out() {  # $1 = --out target
  local o=$1
  case "$o" in analysis/*) ;; *) die "--out must be under analysis/ (got $o)";; esac
  case "$o" in *..*|*'*'*|*'?'*) die "--out path not allowed: $o";; esac
  case "${o,,}" in *.csv|*.tsv|*.txt|*.md|*.json) ;; *) die "--out must end in .csv .tsv .txt .md or .json";; esac
  is_capture "$o" && die "--out may not be a capture file"
  mkdir -p "$(dirname "$o")"
}

guard_tshark() {  # validates "$@" (tshark args); sets HAVE_R
  HAVE_R=0; local a i c rest
  local takes_arg="rRYeETtzOdjJcSuNMHKGCwifFbaBsyWUoX"   # letters whose value follows
  local forbidden="wifFbaoXkLBIpsyWUC"
  while [ $# -gt 0 ]; do
    a=$1; shift
    case "$a" in
      --color|--no-duplicate-keys) ;;
      --enable-protocol|--disable-protocol|--enable-heuristic|--disable-heuristic) shift ;;
      --enable-protocol=*|--disable-protocol=*|--enable-heuristic=*|--disable-heuristic=*) ;;
      --*) die "tshark option $a is not allowed through ws.sh" ;;
      -?*)
        rest=${a#-}
        for (( i=0; i<${#rest}; i++ )); do
          c=${rest:i:1}
          case "$forbidden" in *"$c"*) die "tshark option -$c is not allowed (writes files, captures live or loads code)";; esac
          if [[ "$takes_arg" == *"$c"* ]]; then
            local val
            if (( i+1 < ${#rest} )); then val=${rest:i+1}; else val=${1-}; shift || true; fi
            if [ "$c" = r ]; then [ -f "$val" ] || die "no such capture: $val"; HAVE_R=1; fi
            if [ "$c" = G ] && [ -z "$val" ]; then :; fi
            break
          fi
        done ;;
      *) die "unexpected tshark argument '$a' (quote filters as one argument)" ;;
    esac
  done
}

inventory_hash() {  # prints the SHA-256 recorded in 06_REFERENCE for basename $1
  local ref=project-log/06_REFERENCE.md
  [ -f "$ref" ] || return 1
  grep -F "$1" "$ref" | grep -oE '\b[0-9a-f]{64}\b' | head -1
}

cmd=${1:-}; shift || true
case "$cmd" in
  check)
    . "$here/wstools.sh" ;;

  sha256)
    [ $# -ge 1 ] || die "usage: ws.sh sha256 FILE..."
    for f in "$@"; do [ -f "$f" ] || die "no such file: $f"; printf '%s  %s\n' "$(ws_sha256 "$f")" "$f"; done ;;

  verify)
    [ $# -ge 1 ] || die "usage: ws.sh verify FILE..."
    rc=0
    for f in "$@"; do
      [ -f "$f" ] || die "no such file: $f"
      h=$(ws_sha256 "$f"); b=$(basename "$f"); inv=$(inventory_hash "$b" || true); side=""
      [ -f "$f.sha256" ] && side=$(grep -oE '\b[0-9a-f]{64}\b' "$f.sha256" | head -1)
      echo "$f"; echo "  SHA-256 now:        $h"
      if [ -n "$inv" ]; then
        if [ "$inv" = "$h" ]; then echo "  06_REFERENCE:       MATCH"; else echo "  06_REFERENCE:       MISMATCH (recorded $inv)"; rc=1; fi
      else echo "  06_REFERENCE:       NOT IN INVENTORY (new evidence?)"; fi
      if [ -n "$side" ]; then
        if [ "$side" = "$h" ]; then echo "  $b.sha256: MATCH"; else echo "  $b.sha256: MISMATCH (recorded $side)"; rc=1; fi
      fi
      case "${b,,}" in *synthetic*) echo "  NOTE: SYNTHETIC test capture, not lab evidence";; esac
    done
    exit $rc ;;

  capinfos)
    need CAPINFOS
    for a in "$@"; do case "$a" in -*) ;; *) [ -f "$a" ] || die "no such file: $a";; esac; done
    "$CAPINFOS" "$@" ;;

  tshark)
    need TSHARK
    out=""
    if [ "${1:-}" = --out ]; then out=${2:-}; [ -n "$out" ] || die "--out needs a path"; shift 2; check_out "$out"; fi
    guard_tshark "$@"
    if [ "$HAVE_R" != 1 ] && [ "${1:-}" != -G ]; then die "tshark needs -r FILE (live capture is not allowed here)"; fi
    pre=(-n); [ "${1:-}" = -G ] && pre=()   # -G must be tshark's first option
    if [ -n "$out" ]; then "$TSHARK" "${pre[@]}" "$@" > "$out"; rc=$?; echo "ws.sh: wrote $out ($(wc -l < "$out" | tr -d ' ') lines)" >&2; exit $rc
    else exec "$TSHARK" "${pre[@]}" "$@"; fi ;;

  census)
    need TSHARK
    f=${1:-}; [ -f "$f" ] || die "usage: ws.sh census FILE"
    echo "# Modbus census: $f"
    echo "# SHA-256 $(ws_sha256 "$f")"
    echo "## Requests (tcp.dstport==502) grouped by source, destination, unit, FC, address, quantity"
    printf 'count\tsrc\tdst\tunit\tfc\taddr\tqty\tfc90_sub\tfirst_frame\tlast_frame\n'
    "$TSHARK" -n -r "$f" -Y "mbtcp && tcp.dstport==502" -T fields -E occurrence=f \
      -e frame.number -e ip.src -e ip.dst -e mbtcp.unit_id -e modbus.func_code -e modbus.reference_num \
      -e modbus.bit_cnt -e modbus.word_cnt -e modbus.data 2>/dev/null |
    awk -F'\t' '{
        qty = ($7 != "") ? $7 : $8; sub90 = ($5 == 90) ? substr($9, 3, 2) : "";
        k = $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6 "\t" qty "\t" sub90;
        n[k]++; if (!(k in first)) { first[k] = $1; order[++m] = k } last[k] = $1 }
      END { for (i = 1; i <= m; i++) { k = order[i]; print n[k] "\t" k "\t" first[k] "\t" last[k] } }'
    echo
    echo "## Writes (FC 5/6/15/16/23)"
    printf 'frame\ttime_utc\tsrc\tsrc_mac\tunit\tfc\taddr\tdata\n'
    "$TSHARK" -n -r "$f" -Y "tcp.dstport==502 && modbus.func_code in {5,6,15,16,23}" -T fields \
      -e frame.number -e frame.time_utc -e ip.src -e eth.src -e mbtcp.unit_id -e modbus.func_code -e modbus.reference_num -e modbus.data 2>/dev/null
    echo
    echo "## Responses"
    req=$("$TSHARK" -n -r "$f" -Y "mbtcp && tcp.dstport==502" 2>/dev/null | wc -l | tr -d ' ')
    rsp=$("$TSHARK" -n -r "$f" -Y "mbtcp && tcp.srcport==502" 2>/dev/null | wc -l | tr -d ' ')
    exc=$("$TSHARK" -n -r "$f" -Y "mbtcp && modbus.func_code>=128" 2>/dev/null | wc -l | tr -d ' ')
    unans=$(comm -23 \
      <("$TSHARK" -n -r "$f" -Y "mbtcp && tcp.dstport==502" -T fields -e frame.number 2>/dev/null | sort) \
      <("$TSHARK" -n -r "$f" -Y "mbtcp && tcp.srcport==502" -T fields -e modbus.request_frame 2>/dev/null | sort) | tr '\n' ' ')
    echo "requests=$req responses=$rsp exceptions=$exc unanswered_request_frames=${unans:-none}"
    echo
    echo "## MACs seen per IP (more than one = check for spoofing)"
    "$TSHARK" -n -r "$f" -Y "ip" -T fields -e ip.src -e eth.src 2>/dev/null | sort -u |
      awk -F'\t' '{ m[$1] = m[$1] (m[$1] ? "," : "") $2; c[$1]++ } END { for (ip in m) print ip "\t" c[ip] "\t" m[ip] }' | sort ;;

  ifaces)
    need DUMPCAP
    echo "## dumpcap -D"; "$DUMPCAP" -D
    echo; echo "## IPv4 addresses"
    if [ "$WS_OS" = windows ]; then
      powershell.exe -NoProfile -Command "Get-NetIPAddress -AddressFamily IPv4 | Sort-Object InterfaceAlias | Format-Table -AutoSize InterfaceAlias,IPAddress,PrefixLength" 2>/dev/null
    elif command -v ip >/dev/null 2>&1; then ip -br -4 addr
    else ifconfig 2>/dev/null | grep -E '^[a-z]|inet '; fi ;;

  sanity)
    need TSHARK
    ifc=${1:-}; secs=${2:-10}
    [ -n "$ifc" ] || die "usage: ws.sh sanity IFACE [SECONDS<=30]"
    case $secs in ''|*[!0-9]*) die "SECONDS must be a number";; esac
    [ "$secs" -ge 1 ] && [ "$secs" -le 30 ] || die "SECONDS must be 1..30"
    echo "Listening on '$ifc' for ${secs}s, filter 'tcp port 502' (nothing is saved)..."
    "$TSHARK" -n -i "$ifc" -a "duration:$secs" -f "tcp port 502" 2>&1 | grep -v -E '^Capturing on|^Running as' | head -25 ;;

  ""|-h|--help|help)
    sed -n 2,20p "$0" ;;
  *)
    die "unknown command '$cmd' (try: ws.sh help)" ;;
esac
