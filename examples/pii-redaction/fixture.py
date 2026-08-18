#!/usr/bin/env python3
"""Local body-echoing upstream for the pii-redaction example.

The shared test.sbproxy.dev fixture's /anything route stopped echoing
the request body (it now returns only method, url, headers, query, and
timestamp), so `jq .json` against it is always null. This fixture
stands in for it: httpbin-shaped, JSON body echoed back verbatim under
"json" so the redaction demo shows the exact (already-redacted) request
body the upstream provider received.

Stdlib only, no dependencies:

    python3 fixture.py [port]

Defaults to port 8098, matching the example's sb.yml.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MAX_BODY_BYTES = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    def _respond(self):
        body = json.dumps(
            {
                "method": self.command,
                "url": self.path,
                "headers": dict(self.headers.items()),
                "json": self._read_json(),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # httpbin's /anything route answers every method and every sub-path
    # the same way; this fixture only needs to match that for POST.
    def do_POST(self):
        self._respond()

    def do_GET(self):
        self._respond()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8098
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
