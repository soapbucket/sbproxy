# MCP tool composition

*Last modified: 2026-08-18*

The headline `type: local` shape: one tool built from a two-step DAG
against two other tools, shaped into a single response, governed the
same way any federated tool is. See
[`examples/mcp-local-tools`](../mcp-local-tools/) first if you have
not seen `type: local` before; this example builds on it. See
[`examples/mcp-compose-js`](../mcp-compose-js/) for the identical
composition shaped with JavaScript instead of Lua.

## What it does

`compose.greet_and_echo` takes a `name` and a `verbose` flag and runs:

- **`hello`**: a raw JSON-RPC `tools/call` POST to
  `test.sbproxy.dev/mcp`'s own `hello` tool (the project's public test
  service, the same one [`examples/mcp-governance`](../mcp-governance/)
  and [`examples/mcp-tool-versioning`](../mcp-tool-versioning/) already
  federate to), with the caller's `name`.
- **`echo`**: `depends_on: [hello]`, and only runs when `verbose:
  true` (its `condition`). Its message is built from `hello`'s own
  outcome: `"Echo after hello returned HTTP ${steps.hello.status}"`,
  demonstrating `${steps.<name>.status}` interpolation against a real
  prior step. `hello`'s actual greeting text is *not* reachable this
  way (it sits inside an array, and `${}` has no array indexing); see
  [docs/mcp-compose.md](../../docs/mcp-compose.md#interpolation-vocabulary).
- **`response.lua`** shapes whatever ran into one JSON object,
  reading `hello`'s greeting text out of its result array with real
  Lua indexing: `{"greeting": "...", "echoed": "..."}` when `echo`
  ran, just `{"greeting": "..."}` when it did not.

A second tool, `compose.ping`, is a plain `static` handler present in
the catalog but left off the RBAC allowed list on purpose (see
[Call: an RBAC-denied call](#an-rbac-denied-call) below).

Every field this example sets is in [`sb.yml`](sb.yml); the field
reference for all of it is
[docs/mcp-compose.md](../../docs/mcp-compose.md).

## Run

```bash
sbproxy serve -f examples/mcp-compose/sb.yml
```

Run it from the repository root: `events.path` below is written
relative to that working directory.

## Call

### An allowed composed call, `verbose: true`

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"compose.greet_and_echo","arguments":{"name":"Ada","verbose":true}}}' | jq .
```

`caller`'s RBAC policy allows `compose.greet_and_echo`, so the call
reaches the DAG. `hello` runs first (no `depends_on`, no `condition`);
`echo`'s `condition` (`mcp.arguments.verbose == true`) evaluates true,
so it runs too, reading `hello`'s already-completed result. Both step
calls are real HTTP round trips to `test.sbproxy.dev`, egress-checked
first:

```json
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"greeting\":\"Hello, Ada!\",\"echoed\":\"Echo after hello returned HTTP 200\"}"}],"isError":false}}
```

### `verbose: false`: the echo step is skipped, not run

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"compose.greet_and_echo","arguments":{"name":"Grace","verbose":false}}}' | jq .
```

`hello` still runs (its own `condition` is unset, so it always does).
`echo`'s `condition` evaluates false, so it is skipped: not attempted,
not an error, and `response.lua` finds nothing at `steps.echo` to add:

```json
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"greeting\":\"Hello, Grace!\"}"}],"isError":false}}
```

### An RBAC-denied call

```bash
curl -s -X POST http://127.0.0.1:8080 \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"compose.ping","arguments":{}}}' | jq .
```

`compose.ping` is real and would resolve (it is a plain `static`
handler, no DAG, no egress needed), but `caller`'s `tool_access` never
named it. RBAC refuses it before the step DAG, `condition`, or
anything else about the tool is ever consulted, the same ordering
[`examples/mcp-governance`](../mcp-governance/) demonstrates for a
federated tool:

```json
{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"tool 'compose.ping' is denied by RBAC policy for caller"}}
```

### The evidence sink

```bash
tail -n 3 mcp-compose-events.ndjson | jq -c '{event_type, data: {tool: .data["gen_ai.tool.name"], verdict: .data["sbproxy.decision.verdict"], reason: .data["sbproxy.decision.reason"], seq: .data["sbproxy.evidence.seq"]}}'
```

Every call above, dispatched or refused, is a line here:
`mcp_governance_decision` records for the two `greet_and_echo` calls
and the RBAC-denied `ping` call, each carrying
`sbproxy.evidence.seq`, a per-tenant gapless counter.
`events.fail_closed` covers the same type, so a sink outage would have
refused the call rather than serving it with no evidence behind it.

## What this exercises

- `federated_servers[].type: local` with `tools[].steps`
- `steps[].depends_on` (dependency ordering) and `steps[].condition`
  (CEL, per-call skip)
- `${steps.<name>.status}` interpolation reading a prior step's
  outcome
- `response.lua`, run over `input = {args, steps}`, indexing into a
  step's result array natively where `${}` cannot
- `rbac_policies` default-deny gating a `type: local` tool the same
  way it gates a federated one
- `events.sink: file`, `events.types`, `events.fail_closed` on MCP
  governance decisions from a `type: local` server

## See also

- [`examples/mcp-local-tools`](../mcp-local-tools/) - the beginner
  shape: one static tool, one single-call http tool, no DAG
- [`examples/mcp-compose-js`](../mcp-compose-js/) - the same
  composition, shaped with JavaScript
- [`docs/mcp-compose.md`](../../docs/mcp-compose.md) - handler kinds,
  the full interpolation vocabulary, DAG semantics, and shaping
  reference for all three engines
- [`docs/mcp.md`](../../docs/mcp.md) - the `mcp` action in full
- [`examples/mcp-governance`](../mcp-governance/) - every governance
  surface a composed tool inherits, turned on at once
