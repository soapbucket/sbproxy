#!/usr/bin/env python3
"""Bounded local OpenAI-shaped fixture for the usage-bridge-queue example.

Serves POST /v1/chat/completions on 127.0.0.1:18080 and answers with a
fixed completion carrying fixed token counts. The counts are the point:
the meter event's quantity comes from the completed call's own `usage`
object, so a deterministic upstream makes the queued row deterministic
too.

    prompt_tokens      900
    completion_tokens  120
    total_tokens      1020

Deterministic on purpose. The example demonstrates that a served request
lands one durable row on the settlement queue, not model quality.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 18080
MAX_BODY_BYTES = 64 * 1024
PROMPT_TOKENS = 900
COMPLETION_TOKENS = 120
SAFE_LOG_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-"
)


def safe_log_value(value, max_length):
    """Return one bounded log field with no control or separator characters."""
    text = str(value)
    return "".join(
        character if character in SAFE_LOG_CHARACTERS else "_" for character in text
    )[:max_length]


def completion(model):
    """One completion whose token counts the meter turns into a quantity."""
    return {
        "id": "chatcmpl-usage-bridge",
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
        "usage": {
            "prompt_tokens": PROMPT_TOKENS,
            "completion_tokens": COMPLETION_TOKENS,
            "total_tokens": PROMPT_TOKENS + COMPLETION_TOKENS,
        },
    }


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
                f"method=POST path=/v1/chat/completions model={model} "
                f"prompt_tokens={PROMPT_TOKENS} completion_tokens={COMPLETION_TOKENS}",
                flush=True,
            )
            self.send_json(200, completion(model))
            return
        self.send_json(404, {"error": "not found"})


def serve(port):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def self_test():
    assert safe_log_value("gpt-4o-mini", 80) == "gpt-4o-mini"
    assert safe_log_value("safe\nforged\tline\x1b", 80) == "safe_forged_line_"
    assert safe_log_value("x" * 81, 80) == "x" * 80
    reply = completion("gpt-4o-mini")
    assert reply["model"] == "gpt-4o-mini"
    assert reply["usage"]["total_tokens"] == 1020
    assert reply["usage"]["prompt_tokens"] == PROMPT_TOKENS
    print("fixture self-test: passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        serve(PORT)
        threading.Event().wait()
