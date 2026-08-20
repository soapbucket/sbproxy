# MCP federation over stdio

A local MCP server does not speak HTTP; it reads JSON-RPC on stdin and writes it on stdout. The gateway federates one by launching it as a child process (`transport: stdio`). This example wires up a trivial stdlib-Python server and shows the part that matters: the child is a persistent session, launched once and reused, not a fresh process per call.

The child's one tool, `session_info`, returns its own PID and a per-process count of the calls it has answered. Call it twice and the PID stays the same while the count goes up, which is the persistent session made visible.

## Run

The child's script path in `sb.yml` is relative, so run from this directory:

```bash
cd examples/mcp-stdio
sbproxy serve -f sb.yml
```

The gateway launches `server.py` itself; there is no second process to start.

## Try it

MCP requires an `initialize` handshake once per connection, then a `notifications/initialized` before normal traffic. The gateway holds one child across all of it.

```bash
$ curl -s -X POST http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl-demo","version":"1.0.0"}}}'
{"jsonrpc":"2.0","result":{"capabilities":{"tools":{"listChanged":true}},"protocolVersion":"2025-06-18","serverInfo":{"name":"stdio-demo","version":"1.0.0"}},"id":1}
```

Complete the handshake. Sessions are disabled here, so no `Mcp-Session-Id` is needed; it returns `202`:

```bash
$ curl -sS -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
202
```

Now call the tool twice. Same PID, and `calls_answered` climbs:

```bash
$ curl -s -X POST http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' \
    -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"local.session_info","arguments":{}}}'
{"jsonrpc":"2.0","result":{"content":[{"text":"{\"pid\": 6233, \"calls_answered\": 1}","type":"text"}],"isError":false},"id":3}

$ curl -s -X POST http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' \
    -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"local.session_info","arguments":{}}}'
{"jsonrpc":"2.0","result":{"content":[{"text":"{\"pid\": 6233, \"calls_answered\": 2}","type":"text"}],"isError":false},"id":4}
```

Same PID `6233` both times, `calls_answered` going `1` then `2`. One child answered both. A spawn-per-exchange transport would show a different PID and a count stuck at `1` each time.

## What this shows

- A `transport: stdio` federated server the gateway launches itself
- One supervised persistent child reused across calls, so server-side state survives between them
- The per-call process startup cost paid once per child rather than once per exchange

## The supervision

The child is spawned lazily on the first call that needs it and held for the life of the compiled config. While it is idle the gateway probes it with an MCP `ping`. A child that crashes is respawned under bounded exponential backoff, the gateway replays the `initialize` handshake on the replacement, and any in-flight calls on the dead child fail closed with a typed error rather than hanging. Dropping the config (or a hot reload rebuilding this action) kills the child.

A crash is not free: tool-side state the child held in memory is gone, only the protocol handshake is replayed. That is the honest tradeoff of a local process, and it is why the `session_info` counter resets to `1` if you kill `server.py` by hand between calls.

stdio servers never dial the network, so they do not consult an `egress` policy, and they refuse `run_as_user_auth` because there are no HTTP headers to mint a credential into.

## See also

- [docs/mcp.md](../../docs/mcp.md) documents the `transport`, `command`, and `args` fields and the full federation surface.
- [examples/mcp-federation](../mcp-federation/) federates over HTTP instead, with a bundled OpenAPI upstream.
- [examples/mcp-local-tools](../mcp-local-tools/) serves tools from the gateway itself with no child process at all.
