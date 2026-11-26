"""Minimal real-network plumbing: JSON-over-HTTP for every process.

Uses the Python standard library only: http.server (threaded) on the server
side and urllib on the client side. Every service in the networked
deployment is a separate OS process talking over real TCP sockets.
"""

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def request(url, payload=None, method=None, timeout=5.0, retries=2,
            backoff=0.2):
    """One JSON request over real HTTP. Returns (status_code, parsed_json)."""
    data = json.dumps(payload).encode() if payload is not None else None
    last_err = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                url, data=data, method=method or ("POST" if data else "GET"))
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode())
            except Exception:
                last_err = e
        except Exception as e:      # connection refused etc: retry briefly
            last_err = e
            time.sleep(backoff * (attempt + 1))
    raise ConnectionError("%s: %s" % (url, last_err))


def wait_healthy(url, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            code, body = request(url + "/health", timeout=1.0, retries=0)
            if code == 200 and body.get("status") == "ok":
                return True
        except Exception:
            time.sleep(0.1)
    return False


def serve(routes, port, state=None):
    """Start a threaded JSON/HTTP server on 127.0.0.1:port (real sockets).

    routes: {(method, path): handler(dict) -> dict}
    `state` is an optional shared dict passed to every handler as its
    second element (handlers are (body, state) -> resp) when it is not None.
    """
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self):
            body = {}
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                try:
                    body = json.loads(self.rfile.read(n))
                except json.JSONDecodeError:
                    return self._respond(400, {"status": "error",
                                               "message": "invalid_json"})
            path = self.path.split("?")[0]
            fn = routes.get((self.command, path))
            if fn is None:
                return self._respond(404, {"status": "error",
                                           "message": "not_found",
                                           "path": path})
            try:
                resp = fn(body, state) if state is not None else fn(body)
            except Exception as exc:    # diagnostics to stderr only
                import sys as _sys
                import traceback as _tb
                _sys.stderr.write(_tb.format_exc())
                resp = {"status": "error", "message": "handler_failed",
                        "error_class": type(exc).__name__}
                return self._respond(500, resp)
            self._respond(200, resp)

        def _respond(self, code, resp):
            data = json.dumps(resp).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = _handle

        def log_message(self, *args):   # silence default stderr chatter
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
