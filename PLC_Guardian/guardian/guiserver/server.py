"""HTTP + Server-Sent-Events server for the PLC Guardian control panel (standard library only).

    GET  /api/...      JSON queries, /api/stream = live event stream (SSE)
    POST /api/...      actions (JSON body)
    GET  anything else static files from webui/dist (the built AlignUI / React app)

Safety: every request must carry a localhost Host header (blocks DNS-rebinding), POSTs must be
application/json and, when an Origin header is present, it must be a localhost origin (blocks
cross-site requests from other web pages). File paths are confined to the project / data folders.
"""
from __future__ import annotations

import json
import mimetypes
import os
import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .engine import ApiError, Engine, HERE

DIST = os.environ.get("GUARDIAN_WEBUI_DIST") or os.path.join(HERE, "webui", "dist")
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}
EXTRA_HOSTS = {h.strip().lower() for h in os.environ.get("GUARDIAN_ALLOWED_HOSTS", "").split(",") if h.strip()}
NO_BUILD_PAGE = """<!doctype html><meta charset=utf-8><title>PLC Guardian</title>
<body style="font:16px system-ui;background:#0e121b;color:#e6e8ee;padding:40px;max-width:640px">
<h2>The web UI has not been built yet</h2>
<p>Run once, from the <code>guardian/webui</code> folder (Node.js required):</p>
<pre style="background:#181b25;padding:14px;border-radius:8px">npm install
npm run build</pre><p>Then reload this page (or just run <code>python gui.py</code>, which builds it automatically).</p>"""


def _host_only(value: str) -> str:
    value = (value or "").strip().lower()
    if value.startswith("["):
        return value.split("]")[0] + "]"
    return value.split(":")[0]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "GuardianUI/1"
    engine: Engine

    def log_message(self, fmt, *args):      # keep the console quiet
        pass

    # ---------------------------------------------------------------- plumbing
    def _allowed(self, host: str) -> bool:
        return _host_only(host) in LOCAL_HOSTS or (host or "").strip().lower() in EXTRA_HOSTS \
            or _host_only(host) in EXTRA_HOSTS

    def _guard(self, post: bool) -> bool:
        if not self._allowed(self.headers.get("Host", "")):
            self._json({"error": "forbidden host"}, 403)
            return False
        origin = self.headers.get("Origin")
        if post:
            if "application/json" not in (self.headers.get("Content-Type") or ""):
                self._json({"error": "POST requires Content-Type: application/json"}, 415)
                return False
            if origin and not self._allowed(urlparse(origin).netloc):
                self._json({"error": "forbidden origin"}, 403)
                return False
        return True

    def _json(self, obj, status: int = 200):
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            data = json.loads(self.rfile.read(n).decode("utf-8"))
        except ValueError:
            raise ApiError("invalid JSON body") from None
        return data if isinstance(data, dict) else {}

    def _run(self, fn):
        try:
            self._json(fn() or {"ok": True})
        except ApiError as e:
            self._json({"error": str(e)}, e.status)
        except Exception as e:      # noqa: BLE001
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    # --------------------------------------------------------------------- GET
    def do_GET(self):
        if not self._guard(False):
            return
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        E = self.engine
        routes = {
            "/api/meta": E.meta,
            "/api/state": E.state,
            "/api/captures": E.captures,
            "/api/evidence/logs": E.evidence_logs,
            "/api/lab/config": E.lab_config,
            "/api/lab/ifaces": E.lab_ifaces,
            "/api/analyze/hash": lambda: E.capture_hash(q.get("path", "")),
            "/api/evidence/records": lambda: E.evidence_records(q.get("path", "")),
            "/api/analyze/result": lambda: E.an_result or {},
        }
        if u.path == "/api/stream":
            return self._stream()
        if u.path == "/api/evidence/export":
            try:
                data = E.evidence_csv(q.get("path", ""))
            except ApiError as e:
                return self._json({"error": str(e)}, e.status)
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="evidence.csv"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if u.path in routes:
            return self._run(routes[u.path])
        if u.path.startswith("/api/"):
            return self._json({"error": "not found"}, 404)
        self._static(u.path)

    # -------------------------------------------------------------------- POST
    def do_POST(self):
        if not self._guard(True):
            return
        path, E = urlparse(self.path).path, self.engine
        try:
            b = self._body()
        except ApiError as e:
            return self._json({"error": str(e)}, e.status)
        routes = {
            "/api/system/start": lambda: E.start_system(),
            "/api/system/stop": lambda: E.stop_system(),
            "/api/control": lambda: E.set_control(**{k: b[k] for k in ("route", "mode", "lockout", "allow_attacker") if k in b}),
            "/api/scenario": lambda: E.run_scenario(str(b.get("id", ""))),
            "/api/reset": lambda: E.reset_plc(),
            "/api/clear": lambda: E.clear(str(b.get("ch", "demo"))),
            "/api/tour/run": lambda: E.tour_run(int(b.get("step", -1))),
            "/api/lab/apply": lambda: E.lab_apply(str(b.get("mode", "")), bool(b.get("active_response")), bool(b.get("http_watch"))),
            "/api/lab/start": lambda: E.lab_start(str(b.get("key", "")), str(b.get("iface", ""))),
            "/api/lab/stop": lambda: E.lab_stop(str(b.get("key", ""))),
            "/api/analyze/run": lambda: E.analyze_run(str(b.get("mode", "")), str(b.get("pcap", "")), str(b.get("baseline", ""))),
            "/api/evidence/verify": lambda: E.evidence_verify(str(b.get("path", ""))),
            "/api/evidence/tamper": lambda: E.evidence_tamper(str(b.get("path", ""))),
        }
        if path not in routes:
            return self._json({"error": "not found"}, 404)
        self._run(routes[path])

    # --------------------------------------------------------------------- SSE
    def _stream(self):
        q = self.engine.subscribe()
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def sse(typ, data):
            self.wfile.write(f"event: {typ}\ndata: {json.dumps(data, default=str)}\n\n".encode("utf-8"))
            self.wfile.flush()
        try:
            sse("snapshot", self.engine.snapshot())
            while True:
                try:
                    typ, data = q.get(timeout=10)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                sse(typ, data)
        except OSError:
            pass
        finally:
            self.engine.unsubscribe(q)

    # ------------------------------------------------------------------ static
    def _static(self, path: str):
        index = os.path.join(DIST, "index.html")
        if not os.path.isfile(index):
            body = NO_BUILD_PAGE.encode("utf-8")
            self.send_response(503)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        rel = os.path.normpath(path.lstrip("/"))
        full = os.path.realpath(os.path.join(DIST, rel))
        if not full.startswith(os.path.realpath(DIST)) or not os.path.isfile(full):
            full = index                                    # SPA fallback
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text/") or "javascript" in ctype else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache" if full == index else "public, max-age=3600")
        self.end_headers()
        self.wfile.write(data)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return                       # browser closed an SSE stream / tab: not an error
        super().handle_error(request, client_address)


def make_server(host: str, port: int):
    engine = Engine()
    handler = type("BoundHandler", (Handler,), {"engine": engine})
    return Server((host, port), handler), engine


def serve_forever(httpd: Server, engine: Engine) -> None:
    try:
        httpd.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nStopping child processes…", file=sys.stderr)
        engine.shutdown()
        httpd.server_close()
