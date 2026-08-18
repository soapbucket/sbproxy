#!/usr/bin/env python3
"""Local GraphQL-shaped upstream for the graphql-gateway example.

No live public GraphQL endpoint ships with this repo, so this fixture
stands in for one. It answers every request with a fixed response
shaped like a real GraphQL server's, so the "passing query" walkthrough
step has something real to show. It does not parse or execute the
query itself; the gateway's own validation (this example's actual
subject) has already run by the time a request reaches here.

Stdlib only, no dependencies:

    python3 fixture.py [port]

Defaults to port 8099, matching the example's sb.yml.
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
        payload = self._read_json() if self.command == "POST" else None
        query = payload.get("query", "") if isinstance(payload, dict) else ""
        body = json.dumps(
            {
                "data": {
                    "viewer": {
                        "login": "octoproxy",
                        "receivedQueryBytes": len(query.encode()),
                    }
                }
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self._respond()

    def do_GET(self):
        self._respond()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    print(f"graphql fixture listening on 127.0.0.1:{port}", file=sys.stderr)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
