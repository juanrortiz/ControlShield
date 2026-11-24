# PLC Guardian web control panel

React + TypeScript + Vite front end for PLC Guardian, built with [AlignUI](LICENSE-alignui) components and Tailwind CSS 3.4.
It is served by the Python backend in `guardian/guiserver/` (HTTP + server-sent events) and wraps the real Guardian commands; it adds no detection logic of its own.

## Screens
| Screen | What it does |
|---|---|
| **Live Demo** (safe) | Simulated PLC + the real proxy + HMI / laptop / attacker clients on one machine, with a guided tour. No hardware needed. |
| **Lab Mode** (real) | Start/stop the real passive `monitor` on the mirror port, set the `active_response.enabled` (D-007) and `http_watch.enabled` (D-009) flags, and use the one-press **Quick clear** buttons for `%M7` (Control Shield lockout) and `%M4` (maintenance bypass) on the real PLC. |
| **Analyze Captures** | Run `analyze`, `forensics` and `baseline` on a capture. |
| **Evidence** | Verify a log's hash chain, export CSV, tamper-with-a-copy demo. |
| **Help** | Explains what each concept on screen means. |

The live feed / process console (shared component in `src/ui.tsx`) has a text-size control and a full-screen mode.

Lab Mode talks to real lab hardware; use it only on the isolated lab network. Original `.pcapng` files are only ever read.

## Run
From `guardian/` (not this folder):

```text
python gui.py                 # builds the UI on first run (needs Node.js + npm), then serves http://127.0.0.1:8765
python gui.py --no-browser    # serve only (used by Docker and UI development)
```

After the first build only Python is needed. Docker usage is in [`guardian/README.md`](../README.md).

## UI development
Run `python gui.py --no-browser` in one terminal and the Vite dev server in another (Vite proxies `/api` to the backend):

```text
cd guardian/webui
npm install
npm run dev       # dev server with HMR
npm run build     # type-check (tsc -b) and production build into dist/
npm run lint      # oxlint
```

## Layout
- `src/screens/`: one file per screen (`Demo`, `Lab`, `Analyze`, `Evidence`, `Help`)
- `src/ui.tsx`, `src/components/ui/`: shared UI pieces and AlignUI components
- `src/api.ts`, `src/store.tsx`: backend client and shared state
- `guardian-gui-styles.css` / `.preview.html`: standalone style reference and preview page (not imported by the app)

See `docs/GUARDIAN_DESIGN.md` §4.12 for the design.
