#!/usr/bin/env python3
"""Counting upstream for the cache-reserve example.

Serves JSON on 127.0.0.1:18090 and counts how many times each path has
actually reached it. The count is the evidence: when the proxy replays a
response out of the hot tier or the reserve, the number in the body does
not move, so a reader can see that the upstream was not contacted rather
than take the cache header's word for it.

Stdlib only, no dependencies:

    python3 fixture.py
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 18090
MAX_PATH_KEYS = 64
SAFE_LOG_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-"
)

_lock = threading.Lock()
_hits = {}


def safe_log_value(value, max_length):
    """Return one bounded log field with no control or separator characters."""
    text = str(value)
    return "".join(
        character if character in SAFE_LOG_CHARACTERS else "_" for character in text
    )[:max_length]


def record_hit(path):
    """Count one real upstream hit for `path` and return the new total.

    The map is bounded so a caller sweeping distinct paths cannot grow it
    without limit; past the cap every further path shares one bucket.
    """
    key = safe_log_value(path, 120)
    with _lock:
        if key not in _hits and len(_hits) >= MAX_PATH_KEYS:
            key = "__other__"
        _hits[key] = _hits.get(key, 0) + 1
        return key, _hits[key]


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
            self.send_json(200, {"status": "ok"})
            return
        key, count = record_hit(self.path)
        print(f"upstream hit path={key} count={count}", flush=True)
        self.send_json(
            200,
            {
                "path": key,
                "upstream_hits": count,
                "note": "this number only moves when the request really reached the upstream",
            },
        )


def serve(port):
    server = HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def self_test():
    assert safe_log_value("/a", 120) == "/a"
    assert safe_log_value("/a\nforged\tline\x1b", 120) == "/a_forged_line_"
    assert safe_log_value("x" * 121, 120) == "x" * 120
    assert record_hit("/self-test")[1] == 1
    assert record_hit("/self-test")[1] == 2
    print("fixture self-test: passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        serve(PORT)
        threading.Event().wait()
