#!/usr/bin/env python3
"""Local HTML upstream for the sri example.

The `sri` policy hooks into Pingora's upstream `response_filter`, which
only runs for a genuinely proxied (`type: proxy`) origin -- a `static`
action body never reaches it, so the policy silently never fires. The
shared test.sbproxy.dev fixture's HTML pages carry no `<script src>` or
`<link rel="stylesheet" href>` tags at all, so they cannot demonstrate a
violation either. This fixture stands in: it serves the same
one-violation, one-compliant HTML the example used to embed as a
`static` body, over a real HTTP response, so `sri.local`'s `type: proxy`
origin has something to scan.

Stdlib only, no dependencies:

    python3 fixture.py [port]

Defaults to port 8097, matching the example's sb.yml.
"""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

HTML = b"""<!doctype html>
<html>
  <head>
    <!-- This stylesheet has no integrity attribute. SRI logs a violation. -->
    <link rel="stylesheet" href="https://cdn.example.com/theme.css">
    <!-- This script has integrity. SRI is happy. -->
    <script src="https://cdn.example.com/lib.js"
            integrity="sha384-OLBgp1GsljhM2TJ-sbHjaiH9txEUvgdDTAzHv2P24donTt6_529l+9Ua0vFImLlb"
            crossorigin="anonymous"></script>
  </head>
  <body>
    <h1>SRI demo</h1>
  </body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(HTML)))
        self.end_headers()
        self.wfile.write(HTML)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8097
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
