#!/usr/bin/env python3
"""Deterministic RAG fixture for examples/ai-rag-local.

One stdlib HTTP server stands in for all three upstreams the gateway
talks to in this walkthrough:

  POST /v1/embeddings
      OpenAI-compatible embeddings. Always returns the same
      three-element vector, so retrieval is reproducible.

  POST /collections/support-docs/points/query
      Qdrant-compatible query. Returns one point whose payload
      carries the refund policy sentence, but only when the request
      filter pins tenant_id == "docs". Any other tenant (or a
      missing filter) gets an empty result, which is how the smoke
      test proves tenant filtering is enforced.

  POST /v1/chat/completions
      OpenAI-compatible chat. Succeeds only when the incoming
      request body already contains the refund policy sentence,
      which proves the gateway injected the retrieved context
      before dispatching to the model. Otherwise it returns 500.

No third-party dependencies, no randomness, no clocks: every
response byte is fixed so the smoke assertion is exact.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8090
SENTENCE = "Refunds take five business days."
EMBEDDING = [0.1, 0.2, 0.3]


def filter_pins_docs_tenant(node):
    """Walk a Qdrant filter tree looking for tenant_id == "docs".

    Accepts both the canonical Qdrant condition shape
    {"key": "tenant_id", "match": {"value": "docs"}} and a plain
    {"tenant_id": "docs"} mapping, anywhere in the tree.
    """
    if isinstance(node, dict):
        if node.get("key") == "tenant_id":
            match = node.get("match")
            if isinstance(match, dict) and match.get("value") == "docs":
                return True
        if node.get("tenant_id") == "docs":
            return True
        return any(filter_pins_docs_tenant(value) for value in node.values())
    if isinstance(node, list):
        return any(filter_pins_docs_tenant(item) for item in node)
    return False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep the container log quiet
        pass

    def _send_json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": {"message": "not found"}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": {"message": "invalid JSON body"}})
            return

        if self.path == "/v1/embeddings":
            inputs = body.get("input", "")
            count = len(inputs) if isinstance(inputs, list) else 1
            self._send_json(
                200,
                {
                    "object": "list",
                    "data": [
                        {
                            "object": "embedding",
                            "index": index,
                            "embedding": EMBEDDING,
                        }
                        for index in range(max(count, 1))
                    ],
                    "model": "fixture-embedding",
                    "usage": {"prompt_tokens": 4, "total_tokens": 4},
                },
            )
            return

        if self.path == "/collections/support-docs/points/query":
            if filter_pins_docs_tenant(body.get("filter")):
                points = [
                    {
                        "id": 1,
                        "version": 0,
                        "score": 0.95,
                        "payload": {
                            "content": SENTENCE,
                            "tenant_id": "docs",
                            "kind": "policy",
                        },
                    }
                ]
            else:
                points = []
            self._send_json(
                200,
                {"result": {"points": points}, "status": "ok", "time": 0.0},
            )
            return

        if self.path == "/v1/chat/completions":
            if SENTENCE in raw.decode("utf-8", errors="replace"):
                self._send_json(
                    200,
                    {
                        "id": "chatcmpl-fixture-0001",
                        "object": "chat.completion",
                        "created": 0,
                        "model": "fixture-chat",
                        "choices": [
                            {
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": SENTENCE,
                                },
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {
                            "prompt_tokens": 42,
                            "completion_tokens": 8,
                            "total_tokens": 50,
                        },
                    },
                )
            else:
                self._send_json(
                    500,
                    {
                        "error": {
                            "message": "retrieved context missing from request",
                            "type": "fixture_assertion_failed",
                        }
                    },
                )
            return

        self._send_json(404, {"error": {"message": "not found"}})


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"rag fixture listening on :{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
