#!/usr/bin/env python3
"""PLC Guardian control panel: one browser window for demos, lab runs and capture analysis.

    python gui.py                    start the server and open http://127.0.0.1:8765
    python gui.py --no-browser       just serve (used by Docker and `npm run dev`)
    python gui.py --port 9000 --host 0.0.0.0

The UI is a React app built with AlignUI components (guardian/webui). `python gui.py` builds it on
first run (needs Node.js + npm); after that only Python is needed. See docs/GUARDIAN_DESIGN.md §4.12.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import threading
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

WEBUI = os.path.join(HERE, "webui")


def ensure_built(force: bool = False) -> bool:
    """Build webui/dist if it is missing. Returns False when it cannot be built."""
    index = os.path.join(os.environ.get("GUARDIAN_WEBUI_DIST") or os.path.join(WEBUI, "dist"), "index.html")
    if os.path.isfile(index) and not force:
        return True
    npm = shutil.which("npm")
    if not npm or not os.path.isdir(WEBUI):
        print("The web UI is not built and npm was not found. Install Node.js, then run in guardian/webui:\n"
              "    npm install && npm run build", file=sys.stderr)
        return False
    print("First run: building the web UI (npm install + npm run build)…")
    for cmd in (["install"], ["run", "build"]):
        if subprocess.call([npm, *cmd], cwd=WEBUI, shell=(os.name == "nt")) != 0:
            print(f"npm {' '.join(cmd)} failed", file=sys.stderr)
            return False
    return True


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="PLC Guardian control panel")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (use 0.0.0.0 inside Docker)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--rebuild", action="store_true", help="force `npm run build` before starting")
    a = ap.parse_args(argv)

    if not ensure_built(a.rebuild):
        print("Continuing without a built UI: the API runs, the page will show build instructions.", file=sys.stderr)
    from guiserver.server import make_server, serve_forever
    httpd, engine = make_server(a.host, a.port)
    url = f"http://{'127.0.0.1' if a.host in ('0.0.0.0', '') else a.host}:{a.port}"
    print(f"PLC Guardian control panel: {url}   (Ctrl+C to stop)")
    if not a.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    serve_forever(httpd, engine)


if __name__ == "__main__":
    main()
