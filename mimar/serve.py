"""Serve the browser version of Mimar locally, with the usual safety headers."""
from __future__ import annotations

import os
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_DOCS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
          ".js": "text/javascript; charset=utf-8", ".json": "application/json",
          ".svg": "image/svg+xml", ".png": "image/png", ".txt": "text/plain; charset=utf-8"}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _resolve(self, path):
        path = path.split("?", 1)[0].split("#", 1)[0]
        if path in ("/", ""):
            path = "/index.html"
        full = os.path.normpath(os.path.join(_DOCS, path.lstrip("/")))
        return full if full.startswith(_DOCS) else None

    def do_GET(self):
        full = self._resolve(self.path)
        if not full or not os.path.isfile(full):
            self.send_error(404, "not found")
            return
        ext = os.path.splitext(full)[1].lower()
        with open(full, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", _TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)


def run_server(host, port, open_browser=False):
    if not os.path.isdir(_DOCS):
        print("mimar: the docs folder was not found")
        return 1
    server = ThreadingHTTPServer((host, port), _Handler)
    url = "http://" + host + ":" + str(port) + "/"
    print("Mimar at " + url + "  (Ctrl+C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    return 0
