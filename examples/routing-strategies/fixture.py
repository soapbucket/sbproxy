#!/usr/bin/env python3
"""Two named upstreams for the routing-strategies example.

A load balancer's target choice is invisible when every target is the
same address. This serves two replicas that say which one they are, on
127.0.0.1:18091 and 127.0.0.1:18092, so a strategy's selection shows up
in the response body.

Stdlib only, no dependencies:

    python3 fixture.py
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

REPLICAS = {18091: "replica-a", 18092: "replica-b"}
SAFE_LOG_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-"
)


def safe_log_value(value, max_length):
    """Return one bounded log field with no control or separator characters."""
    text = str(value)
    return "".join(
        character if character in SAFE_LOG_CHARACTERS else "_" for character in text
    )[:max_length]


def handler_for(replica):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format, *_args):
            return

        def send_json(self, status, value):
            body = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/health", "/healthz"):
                self.send_json(200, {"status": "ok", "target": replica})
                return
            adapter = safe_log_value(self.headers.get("X-LoRA-Adapter", ""), 80)
            print(f"{replica} served path={safe_log_value(self.path, 120)}", flush=True)
            self.send_json(
                200,
                {
                    "target": replica,
                    "path": safe_log_value(self.path, 120),
                    "adapter_requested": adapter,
                },
            )

    return Handler


def serve():
    servers = []
    for port, replica in REPLICAS.items():
        server = HTTPServer(("127.0.0.1", port), handler_for(replica))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    return servers


def self_test():
    assert safe_log_value("alice-tone", 80) == "alice-tone"
    assert safe_log_value("safe\nforged\tline\x1b", 80) == "safe_forged_line_"
    assert safe_log_value("x" * 81, 80) == "x" * 80
    assert set(REPLICAS.values()) == {"replica-a", "replica-b"}
    print("fixture self-test: passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        serve()
        threading.Event().wait()
