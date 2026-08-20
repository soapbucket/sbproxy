#!/usr/bin/env python3
"""Trivial MCP stdio server for the mcp-stdio example.

Speaks newline-delimited JSON-RPC 2.0 on stdin/stdout, the framing the
gateway's supervised stdio transport uses. One tool, `session_info`,
returns this process's PID and a per-process count of the `tools/call`
exchanges it has answered. Both values exist to make the supervision
model observable: under the persistent session (WOR-2453) two calls
come back with the same PID and an increasing counter, because the
gateway launches ONE child and keeps it, rather than spawning a fresh
process per exchange.

Stdlib only, no dependencies. The gateway launches this itself; there
is no reason to run it by hand except curiosity:

    python3 server.py
"""

import json
import os
import sys

CALLS_ANSWERED = 0

SESSION_INFO_TOOL = {
    "name": "session_info",
    "description": (
        "Returns this server process's PID and how many tools/call "
        "exchanges it has answered since it started. Two calls with "
        "the same PID and an increasing count prove the gateway is "
        "reusing one persistent child."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
}


def respond(request_id, result):
    line = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "result": result},
        separators=(",", ":"),
    )
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def respond_error(request_id, code, message):
    line = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        separators=(",", ":"),
    )
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def handle(message):
    global CALLS_ANSWERED
    method = message.get("method")
    request_id = message.get("id")

    if method == "initialize":
        respond(
            request_id,
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "session-info", "version": "1.0.0"},
            },
        )
    elif method == "notifications/initialized":
        pass  # notification: no response
    elif method == "ping":
        # The supervisor's idle health probe.
        respond(request_id, {})
    elif method == "tools/list":
        respond(request_id, {"tools": [SESSION_INFO_TOOL]})
    elif method == "tools/call":
        CALLS_ANSWERED += 1
        payload = {"pid": os.getpid(), "calls_answered": CALLS_ANSWERED}
        respond(
            request_id,
            {
                "content": [{"type": "text", "text": json.dumps(payload)}],
                "isError": False,
            },
        )
    elif request_id is not None:
        respond_error(request_id, -32601, f"method not found: {method}")
    # Unknown notifications are ignored, per JSON-RPC 2.0.


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        handle(message)


if __name__ == "__main__":
    main()
