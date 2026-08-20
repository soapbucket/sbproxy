#!/usr/bin/env python3
"""Bounded local OpenAI-shaped fixture for the temp-budget-override example.

Serves POST /v1/chat/completions on 127.0.0.1:18080, echoes back whichever
model was dispatched, and reports exactly the prompt-token count the
request asked for.

The example's subject is the per-key token budget and the temporary raise
on top of it, and spend comes from each completed call's own `usage`
object. Waiting for real traffic to exhaust a 200-token cap is not a
demo, so the request names the tokens it wants billed:

    {"messages": [{"role": "user", "content": "spend=150"}]}

reports 150 prompt tokens and 0 completion tokens. Anything without a
`spend=` marker reports 1. The number is a demo dial, not a measurement:
nothing here tokenizes anything.

Same shape as examples/ai-predictive-budget/fixture.py, kept per-example
so each walkthrough stays self-contained.
"""

import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 18080
MAX_BODY_BYTES = 256 * 1024
# Bounds the dial. Large enough to blow past any demo cap in one call,
# small enough that a typo cannot overflow the arithmetic downstream.
MAX_SPEND_TOKENS = 100_000_000
SPEND_PATTERN = re.compile(r"spend=(\d+)")
SAFE_LOG_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-"
)


def safe_log_value(value, max_length):
    """Return one bounded log field with no control or separator characters."""
    text = str(value)
    return "".join(
        character if character in SAFE_LOG_CHARACTERS else "_" for character in text
    )[:max_length]


def requested_spend(request):
    """Read the `spend=<int>` dial out of the messages. Defaults to 1."""
    for message in request.get("messages") or []:
        content = message.get("content")
        if not isinstance(content, str):
            continue
        match = SPEND_PATTERN.search(content)
        if match:
            return min(int(match.group(1)), MAX_SPEND_TOKENS)
    return 1


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
        if self.path != "/v1/chat/completions":
            self.send_json(404, {"error": "not found"})
            return

        model = safe_log_value(request.get("model", ""), 80)
        spend = requested_spend(request)
        print(
            f"method=POST path=/v1/chat/completions model={model} prompt_tokens={spend}",
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
                "usage": {
                    "prompt_tokens": spend,
                    "completion_tokens": 0,
                    "total_tokens": spend,
                },
            },
        )


def serve(port):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def self_test():
    assert safe_log_value("gpt-4o-mini", 80) == "gpt-4o-mini"
    assert safe_log_value("safe\nforged\tline\x1b", 80) == "safe_forged_line_"
    assert safe_log_value("x" * 81, 80) == "x" * 80

    assert requested_spend({"messages": [{"role": "user", "content": "spend=150"}]}) == 150
    assert requested_spend({"messages": [{"role": "user", "content": "hello"}]}) == 1
    assert requested_spend({}) == 1
    assert requested_spend({"messages": [{"role": "user", "content": None}]}) == 1
    assert (
        requested_spend({"messages": [{"role": "user", "content": "spend=999999999999"}]})
        == MAX_SPEND_TOKENS
    )
    print("fixture self-test: passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        serve(PORT)
        threading.Event().wait()
