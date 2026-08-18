# MCP local tools

*Last modified: 2026-08-18*

A `type: local` MCP server: tools the gateway serves itself, with no
upstream MCP server or REST spec behind them. This is the beginner
shape: two tools, no step DAG. See
[`examples/mcp-compose`](../mcp-compose/) for the composed, multi-step
version once this one makes sense.

## Config

`federated_servers[]` gets a third `type` alongside `mcp` and
`openapi`: `local`. Its `tools[]` each declare exactly one handler:

- **`status`** is a `static` handler: it always returns the same JSON
  value. No HTTP call is made, so on its own it would need no
  `egress:`.
- **`lookup`** is a single `http` handler: one GET against
  `test.sbproxy.dev`, the project's public HTTP echo service (like
  httpbin), splicing the caller's `id` argument into the URL with
  `${args.id}`.

Because `lookup` can make an HTTP call, the *server* needs an
`egress:` policy, even though `status` alone would not: the check runs
once per server, the moment any of its tools can dial out.

```yaml
federated_servers:
  - origin: local-tools
    type: local
    prefix: local
    namespace: always
    egress:
      mode: deny_by_default
      hosts: [test.sbproxy.dev]
    tools:
      - name: status
        description: Fixed status blob. Makes no HTTP call.
        input_schema:
          type: object
          properties: {}
          additionalProperties: false
        static:
          service: mcp-local-tools-demo
          ok: true
          version: "1.0.0"
      - name: lookup
        description: Looks an id up against the test service.
        input_schema:
          type: object
          required: [id]
          properties:
            id: { type: string }
        http:
          method: GET
          url: "https://test.sbproxy.dev/get?id=${args.id}"
```

The full file is [`sb.yml`](sb.yml). See
[docs/mcp-compose.md](../../docs/mcp-compose.md) for the field-by-field
reference (`static` / `http` / `steps`, the interpolation vocabulary,
and how these tools inherit governance) and
[docs/mcp.md](../../docs/mcp.md) for the rest of the `mcp` action.

## Run

```bash
sbproxy serve -f examples/mcp-local-tools/sb.yml
```

Run from the repository root, like every other example here.

## Call

Both tools are advertised bare-prefixed, so `local.status` and
`local.lookup` (this server's `prefix: local`, `namespace: always`).

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq .
```

## Outcome

`tools/list` shows both, no upstream contacted to build this catalog
(a local server's tools come straight from config):

```json
{"jsonrpc":"2.0","id":1,"result":{"tools":[
  {"name":"local.status","description":"Fixed status blob for this gateway. Always returns the same value; makes no HTTP call.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
  {"name":"local.lookup","description":"Looks an id up against the project's public echo/test service and returns what it saw (a real HTTP round trip, egress-gated to test.sbproxy.dev).","inputSchema":{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Value to look up."}},"additionalProperties":false}}
]}}
```

`local.status` never leaves the process:

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"local.status","arguments":{}}}' | jq .
```

```json
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"ok\":true,\"service\":\"mcp-local-tools-demo\",\"version\":\"1.0.0\"}"}],"isError":false}}
```

`local.lookup` makes a real GET, egress-checked against `hosts:
[test.sbproxy.dev]` before the connection opens:

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"local.lookup","arguments":{"id":"widget-42"}}}' | jq .
```

```json
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"status\":200,\"headers\":{\"content-type\":\"application/json\"},\"body\":{\"method\":\"GET\",\"url\":\"/get\",\"query\":{\"id\":\"widget-42\"},\"headers\":{\"host\":\"test.sbproxy.dev\"},\"timestamp\":\"2026-08-18T00:00:00Z\"}}"}],"isError":false}}
```

`${args.id}` is the whole value of the `id` query parameter, so it
splices in as `widget-42` verbatim; embedded in a longer string it
would stringify the same way. A host outside `egress.hosts` is refused
before any connection, the same way an `openapi`-backed server's REST
egress works; see
[mcp-gateway-guardrails.md](../../docs/mcp-gateway-guardrails.md#deterministic-egress).

## What this exercises

- `federated_servers[].type: local`
- `tools[].static`: a fixed-value handler needing no egress
- `tools[].http`: a single-call handler, egress-gated
- `${args.<path>}` interpolation in a request URL
- Per-server `egress` required the moment any tool can dial out

## See also

- [`examples/mcp-compose`](../mcp-compose/) - the same `type: local`
  server composing two calls into one tool via a step DAG, condition,
  and Lua response shaping
- [`docs/mcp-compose.md`](../../docs/mcp-compose.md) - the field
  reference and full interpolation vocabulary
- [`docs/mcp.md`](../../docs/mcp.md) - the `mcp` action and
  `federated_servers[]` in full
- [`examples/mcp-governance`](../mcp-governance/) - every governance
  surface a `type: local` tool inherits, turned on at once
