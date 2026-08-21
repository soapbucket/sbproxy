#!/usr/bin/env python3
"""Stand-ins for the three upstreams examples/semantic-routing/sb.yml calls.

Three loopback listeners, so the example runs end to end with no keys and
no network:

  127.0.0.1:18091  the embedding provider (`/v1/embeddings`)
  127.0.0.1:18092  code-pool     (`/v1/chat/completions`)
  127.0.0.1:18093  chat-pool     (`/v1/chat/completions`)

The embedder is a three-axis topic projection, not a language model. A
small keyword table gives each recognized word a weight on `code`,
`chat`, and `other`; a text's vector is the sum of its words' weights,
scaled to unit length. Words that genuinely belong to both topics
("explain", "write", "short") carry weight on both axes, which is why
the scores below are ordinary-looking numbers rather than a clean 1.0.
It is deliberately transparent rather than accurate: the scores this
example prints are a property of this toy projection, and a real
embedding model gives different numbers for the same prompts.

Usage:
    python3 examples/semantic-routing/fixture.py
    python3 examples/semantic-routing/fixture.py --no-embedder

`--no-embedder` starts the two pools and leaves the embedding port
unbound, which is how the README shows an embedding outage falling open
to the declared `fallback` rather than failing the request.
"""

from __future__ import annotations

import json
import math
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EMBED_PORT = 18091
CODE_PORT = 18092
CHAT_PORT = 18093

# Three axes: code, chat, and a third for everything the two pools were
# not built for. The third axis is what makes the below-floor case
# reachable at a realistic floor rather than only at a contrived one.
# Each entry is that word's weight on (code, chat, other).
KEYWORDS: dict[str, tuple[float, float, float]] = {
    # Squarely about code.
    "function": (1.0, 0.0, 0.0),
    "functions": (1.0, 0.0, 0.0),
    "parses": (1.0, 0.0, 0.0),
    "parse": (1.0, 0.0, 0.0),
    "json": (1.0, 0.0, 0.0),
    "review": (1.0, 0.0, 0.0),
    "pull": (1.0, 0.0, 0.0),
    "bug": (1.0, 0.0, 0.0),
    "bugs": (1.0, 0.0, 0.0),
    "stack": (1.0, 0.0, 0.0),
    "trace": (1.0, 0.0, 0.0),
    "compiler": (1.0, 0.0, 0.0),
    "borrow": (1.0, 0.0, 0.0),
    "checker": (1.0, 0.0, 0.0),
    "rust": (1.0, 0.0, 0.0),
    "code": (1.0, 0.0, 0.0),
    "refactor": (1.0, 0.0, 0.0),
    "error": (0.9, 0.1, 0.0),
    "errors": (0.9, 0.1, 0.0),
    "fix": (0.8, 0.1, 0.1),
    # Squarely conversational.
    "friendly": (0.0, 1.0, 0.0),
    "conversation": (0.0, 1.0, 0.0),
    "everyday": (0.0, 1.0, 0.0),
    "colleague": (0.0, 1.0, 0.0),
    "email": (0.0, 1.0, 0.0),
    "note": (0.0, 1.0, 0.0),
    "thank": (0.0, 1.0, 0.0),
    "polite": (0.0, 1.0, 0.0),
    "topics": (0.0, 0.9, 0.1),
    "draft": (0.1, 0.9, 0.0),
    "plain": (0.1, 0.8, 0.1),
    # Genuinely both. These are the words that keep a real request off
    # the pure axis its pool's exemplars sit on.
    "write": (0.4, 0.6, 0.0),
    "short": (0.2, 0.6, 0.2),
    "explain": (0.4, 0.4, 0.2),
    "language": (0.4, 0.5, 0.1),
    "help": (0.3, 0.5, 0.2),
    # Neither pool's specialty.
    "mountain": (0.0, 0.0, 1.0),
    "mountains": (0.0, 0.0, 1.0),
    "tallest": (0.0, 0.0, 1.0),
    "elevation": (0.0, 0.0, 1.0),
    "america": (0.0, 0.0, 1.0),
    "south": (0.0, 0.0, 1.0),
    "continent": (0.0, 0.0, 1.0),
    "which": (0.2, 0.2, 0.6),
    "each": (0.2, 0.2, 0.6),
}

WORD = re.compile(r"[a-z]+")


def embed(text: str) -> list[float]:
    """Project a text onto the three topic axes and scale to unit length."""
    vector = [0.0, 0.0, 0.0]
    for token in WORD.findall(text.lower()):
        weights = KEYWORDS.get(token)
        if weights is None:
            continue
        for axis, weight in enumerate(weights):
            vector[axis] += weight
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0.0:
        # A text with no recognized word still has to produce a scoreable
        # vector, or the strategy reads it as an embedder failure rather
        # than as the below-floor case this example wants to show. Put it
        # on the third axis, which no pool claims.
        return [0.0, 0.0, 1.0]
    return [value / norm for value in vector]


def make_handler(role: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args) -> None:  # noqa: D102 - quiet by design
            pass

        def _send(self, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            length = int(self.headers.get("content-length") or 0)
            request = json.loads(self.rfile.read(length) or b"{}")
            if role == "embed":
                inputs = request.get("input")
                if isinstance(inputs, str):
                    inputs = [inputs]
                self._send(
                    {
                        "object": "list",
                        "model": request.get("model", "bag-of-words"),
                        "data": [
                            {"object": "embedding", "index": i, "embedding": embed(text)}
                            for i, text in enumerate(inputs or [])
                        ],
                        "usage": {"prompt_tokens": 0, "total_tokens": 0},
                    }
                )
                return
            self._send(
                {
                    "id": f"chatcmpl-{role}",
                    "object": "chat.completion",
                    "created": 0,
                    "model": request.get("model", role),
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": f"answered by {role}",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                }
            )

    return Handler


def main() -> int:
    with_embedder = "--no-embedder" not in sys.argv[1:]
    servers = [
        ThreadingHTTPServer(("127.0.0.1", CODE_PORT), make_handler("code-pool")),
        ThreadingHTTPServer(("127.0.0.1", CHAT_PORT), make_handler("chat-pool")),
    ]
    if with_embedder:
        servers.insert(
            0, ThreadingHTTPServer(("127.0.0.1", EMBED_PORT), make_handler("embed"))
        )
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    embedder = f"embedder on {EMBED_PORT}" if with_embedder else "embedder DOWN"
    print(
        f"{embedder}, code-pool on {CODE_PORT}, chat-pool on {CHAT_PORT}",
        flush=True,
    )
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
