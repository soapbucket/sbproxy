#!/usr/bin/env python3
"""Demo upstream for the metering-verify example.

Serves a deterministic ~2 KiB article body on every path, so metered
requests have real egress bytes to bill. Stdlib only; no dependencies.

    python3 bin/upstream.py [port]

Defaults to port 8099, matching the example's sb.yml.
"""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ARTICLE = (
    "sbproxy metering demo article\n"
    + "=" * 30
    + "\n\n"
    + "\n".join(
        f"Paragraph {n}: metered content served by the demo upstream, "
        "billed by the receipt chain in front of it." for n in range(1, 25)
    )
    + "\n"
).encode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(ARTICLE)))
        self.end_headers()
        self.wfile.write(ARTICLE)

    def log_message(self, fmt, *args):
        sys.stderr.write("upstream: %s\n" % (fmt % args))


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
