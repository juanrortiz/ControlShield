#!/usr/bin/env bash
# Finds the Wireshark command-line tools on Windows (Git Bash / MSYS / Cygwin / WSL), Linux or macOS.
# Source it from the Group Project folder:
#     . .claude/skills/wireshark-analyze/scripts/wstools.sh
# Sets: TSHARK CAPINFOS DUMPCAP EDITCAP MERGECAP WIRESHARK WS_OS (windows|linux|macos)
# Defines: ws_sha256 <file>   (prints only the hex digest)
#          ws_winpath <path>  (Windows path on Windows, unchanged elsewhere)
# Override the search with WIRESHARK_DIR=/path/to/Wireshark if it is installed somewhere unusual.

case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*) WS_OS=windows ;;
  Darwin)               WS_OS=macos ;;
  *)                    WS_OS=linux ;;
esac

_ws_dirs=()
[ -n "${WIRESHARK_DIR:-}" ] && _ws_dirs+=("$WIRESHARK_DIR")
_ws_dirs+=("/c/Program Files/Wireshark" "/cygdrive/c/Program Files/Wireshark" \
           "/mnt/c/Program Files/Wireshark" "/Applications/Wireshark.app/Contents/MacOS")

_ws_find() {  # $@ = candidate names; prints the first hit
  local n d
  for n in "$@"; do
    if [ -n "${WIRESHARK_DIR:-}" ]; then
      [ -x "$WIRESHARK_DIR/$n.exe" ] && { printf '%s\n' "$WIRESHARK_DIR/$n.exe"; return 0; }
      [ -x "$WIRESHARK_DIR/$n" ]     && { printf '%s\n' "$WIRESHARK_DIR/$n"; return 0; }
    fi
    command -v "$n" >/dev/null 2>&1 && { command -v "$n"; return 0; }
    for d in "${_ws_dirs[@]}"; do
      [ -x "$d/$n.exe" ] && { printf '%s\n' "$d/$n.exe"; return 0; }
      [ -x "$d/$n" ]     && { printf '%s\n' "$d/$n"; return 0; }
    done
  done
  return 1
}

TSHARK=$(_ws_find tshark)       || TSHARK=
CAPINFOS=$(_ws_find capinfos)   || CAPINFOS=
DUMPCAP=$(_ws_find dumpcap)     || DUMPCAP=
EDITCAP=$(_ws_find editcap)     || EDITCAP=
MERGECAP=$(_ws_find mergecap)   || MERGECAP=
WIRESHARK=$(_ws_find Wireshark wireshark) || WIRESHARK=
export TSHARK CAPINFOS DUMPCAP EDITCAP MERGECAP WIRESHARK WS_OS

ws_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -- "$1" | cut -d' ' -f1
  else certutil -hashfile "$(ws_winpath "$1")" SHA256 | sed -n 2p | tr -d ' \r'
  fi
}

ws_winpath() {
  if [ "$WS_OS" = windows ] && command -v cygpath >/dev/null 2>&1; then cygpath -w -- "$1"
  else printf '%s\n' "$1"
  fi
}

if [ -z "$TSHARK" ]; then
  echo "wstools: tshark NOT found. Install Wireshark (Windows: include TShark + Npcap) or set WIRESHARK_DIR." >&2
else
  echo "wstools: OS=$WS_OS"
  echo "  tshark    = $TSHARK"
  echo "  capinfos  = ${CAPINFOS:-not found}"
  echo "  dumpcap   = ${DUMPCAP:-not found}"
  echo "  editcap   = ${EDITCAP:-not found}"
  echo "  wireshark = ${WIRESHARK:-not found (GUI)}"
  "$TSHARK" --version 2>/dev/null | head -1
fi
