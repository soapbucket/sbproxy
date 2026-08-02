#!/usr/bin/env python3
"""Bounded local OpenAI-shaped fixture for the vercel-ai-sdk example.

Serves POST /v1/chat/completions on 127.0.0.1:18080 and always answers
with the fixed sentence "fixture response", echoing the requested model
back. Deterministic on purpose: the example demonstrates the gateway
wiring (virtual key, allow list, attribution), not model quality.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 18080
MAX_BODY_BYTES = 64 * 1024
SAFE_LOG_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-"
)


def safe_log_value(value, max_length):
    """Return one bounded log field with no control or separator characters."""
    text = str(value)
    return "".join(
        character if character in SAFE_LOG_CHARACTERS else "_" for character in text
    )[:max_length]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

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
        self.send_json(404, {"error": "not found"})

    def do_POST(self):
        request = self.read_json()
        if request is None:
            self.send_json(400, {"error": "invalid JSON"})
            return

        if self.path == "/v1/chat/completions":
            model = safe_log_value(request.get("model", ""), 80)
            print(
                f"method=POST path=/v1/chat/completions model={model} verdict=allow",
                flush=True,
            )
            self.send_json(
                200,
                {
                    "id": "chatcmpl-fixture",
                    "object": "chat.completion",
                    "created": 0,
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "fixture response"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                },
            )
            return

        self.send_json(404, {"error": "not found"})


def serve(port):
    server = HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def self_test():
    assert safe_log_value("gpt-4o-mini", 80) == "gpt-4o-mini"
    assert safe_log_value("safe\nforged\tline\x1b", 80) == "safe_forged_line_"
    assert safe_log_value("x" * 81, 80) == "x" * 80
    print("fixture sanitization self-test: passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        serve(PORT)
        threading.Event().wait()
