#!/usr/bin/env python3
"""Two bounded local fixtures for the health-and-budget-gauges example.

Serves both upstreams the config points at, from one process:

* 127.0.0.1:19601 answers 200 to everything. It is the load balancer's
  live target, and its `/up` responses keep the active health probe
  green. (Port 19602, the dead target, is deliberately not served:
  refused connections are the scenario.)

* 127.0.0.1:19603 is an OpenAI-shaped `POST /v1/chat/completions` stub
  that bills exactly the prompt tokens the request asks for:

      {"messages": [{"role": "user", "content": "spend=100"}]}

  reports 100 prompt tokens and 0 completion tokens. Anything without a
  `spend=` marker reports 1. The number is a demo dial, not a
  measurement: nothing here tokenizes anything. The dial is what makes
  the budget walk in the README reproducible; waiting for real traffic
  to consume a workspace cap is not a demo.
"""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LB_PORT = 19601
AI_PORT = 19603
MAX_BODY_BYTES = 256 * 1024
# Bounds the dial: large enough to blow past the demo cap in one call,
# small enough that a typo cannot overflow arithmetic downstream.
MAX_SPEND_TOKENS = 100_000_000
SPEND_PATTERN = re.compile(r"spend=(\d+)")


def requested_spend(request):
    """Read the `spend=<int>` dial out of the messages. Defaults to 1."""
    for message in request.get("messages") or []:
        content = message.get("content")
        if isinstance(content, str):
            match = SPEND_PATTERN.search(content)
            if match:
                return min(int(match.group(1)), MAX_SPEND_TOKENS)
    return 1


class LbTarget(BaseHTTPRequestHandler):
    """The healthy load-balancer target: 200 to probes and traffic alike."""

    def do_GET(self):
        body = b'{"target": "19601", "ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # probes every 2s; keep the terminal for the proxy's log


class OpenAiStub(BaseHTTPRequestHandler):
    """OpenAI-shaped completions endpoint with a `spend=` billing dial."""

    def do_POST(self):
        length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY_BYTES)
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            request = {}
        spend = requested_spend(request)
        response = {
            "id": "chatcmpl-fixture",
            "object": "chat.completion",
            "model": request.get("model") or "gpt-4o",
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
        }
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main():
    lb = ThreadingHTTPServer(("127.0.0.1", LB_PORT), LbTarget)
    ai = ThreadingHTTPServer(("127.0.0.1", AI_PORT), OpenAiStub)
    threading.Thread(target=lb.serve_forever, daemon=True).start()
    print(f"fixture: LB target on :{LB_PORT}, OpenAI stub on :{AI_PORT}")
    ai.serve_forever()


if __name__ == "__main__":
    main()
