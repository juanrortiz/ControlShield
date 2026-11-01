#!/usr/bin/env bash
# Usage (from the Group Project folder):
#   bash .claude/skills/wireshark-open/scripts/open.sh <capture> ["display filter"] [frame-number]
# Opens the capture in the Wireshark GUI, detached, with an optional display filter and jumping to a frame.
# Validates the filter with tshark first so the GUI doesn't open on a syntax error.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$here/../../wireshark-analyze/scripts/wstools.sh" >/dev/null

[ $# -ge 1 ] || { sed -n 2,5p "$0"; exit 64; }
f=$1; filt=${2:-}; frame=${3:-}
[ -f "$f" ] || { echo "No such file: $f" >&2; exit 1; }
[ -n "$WIRESHARK" ] || { echo "Wireshark GUI not found (set WIRESHARK_DIR)" >&2; exit 1; }
if [ -n "$frame" ]; then case $frame in *[!0-9]*) echo "frame must be a number" >&2; exit 64 ;; esac; fi

if [ -n "$filt" ] && [ -n "$TSHARK" ]; then
  if ! err=$("$TSHARK" -n -r "$f" -Y "$filt" 2>&1 >/dev/null); then
    echo "Display filter rejected by tshark: $err" >&2; exit 2
  fi
  n=$("$TSHARK" -n -r "$f" -Y "$filt" 2>/dev/null | wc -l | tr -d ' ')
  echo "Filter matches $n frame(s)."
fi

if [ "$WS_OS" = windows ]; then
  ps_args=(-Exe "$(ws_winpath "$WIRESHARK")" -File "$(ws_winpath "$(cd "$(dirname "$f")" && pwd)/$(basename "$f")")")
  [ -n "$filt" ]  && ps_args+=(-Filter "$filt")
  [ -n "$frame" ] && ps_args+=(-Frame "$frame")
  MSYS2_ARG_CONV_EXCL='*' powershell.exe -NoProfile -ExecutionPolicy Bypass \
    -File "$(ws_winpath "$here/open_wireshark.ps1")" "${ps_args[@]}"
else
  args=(-r "$f")
  [ -n "$filt" ]  && args+=(-Y "$filt")
  [ -n "$frame" ] && args+=(-g "$frame")
  if [ "$WS_OS" = macos ]; then open -n -a Wireshark --args "${args[@]}"
  else nohup "$WIRESHARK" "${args[@]}" >/dev/null 2>&1 & disown || true; fi
fi
echo "Opened $f in Wireshark${filt:+ with filter: $filt}${frame:+, frame $frame}."
