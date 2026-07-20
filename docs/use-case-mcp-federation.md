# Internal MCP servers multiplying without an owner: federate them behind one gateway

*Last modified: 2026-07-19*

Every team that wires an agent up to a tool ends up standing up its own MCP server: one for the GitHub org, one for the internal database, one for the ticket tracker. Six months later there are a dozen of them, each with its own auth story, its own idea of who is allowed to call `delete_repo`, and no shared record of what any agent actually did. SBproxy's MCP gateway collapses that sprawl into one endpoint: it aggregates the tool catalogues of every upstream server behind a single virtual MCP server, gates every `tools/call` with default-deny RBAC keyed on the caller's identity, and can turn a REST API with no MCP support at all into governed tools with nothing but an OpenAPI spec. This guide builds that gateway end to end, with real curls against a real (if intentionally tiny) upstream.

## What you will build

One MCP endpoint on port 8080 that speaks JSON-RPC 2.0 and aggregates two upstreams under namespace prefixes, `gh.*` and `db.*`, so an agent calling `gh.search_repos` never needs to know it isn't talking to GitHub directly. `gh` is backed by `type: openapi`: a tiny REST mock stands in for a real internal API, and the gateway derives its one tool from an inline OpenAPI spec with no server-side code. `db` is left pointed at an unreachable placeholder host, on purpose, so this walkthrough is honest about what a broken federated server looks like from the outside (quietly absent, not a crash) as well as what a working one looks like. Two RBAC policies gate `tools/call` per upstream by caller, and a `tool_allowlist` guardrail sits on top of both as a second, coarser check.

## Prerequisites

- `curl` for requests and `jq` for reading JSON.
- No Rust toolchain and no external MCP server account. Everything below runs from two local `sbproxy` processes.

## Install

```bash
# Linux / macOS, single static binary:
curl -fsSL https://download.sbproxy.dev | sh

# macOS via Homebrew:
brew install soapbucket/tap/sbproxy
```

The full install matrix is in the [manual](manual.md).

## Config

The assembled files live in [`examples/mcp-federation/`](../examples/mcp-federation/): [`upstream.yml`](../examples/mcp-federation/upstream.yml) is the mock REST API, [`sb.yml`](../examples/mcp-federation/sb.yml) is the gateway. It reads in three parts.

First, the real federated server. `type: openapi` skips MCP entirely on the wire to the upstream: the gateway reads an inline spec, derives one tool per operation, and dispatches `tools/call` as a plain REST request. `namespace: always` guarantees the `gh.` prefix on every tool from this server regardless of name collisions, which is what makes `gh.search_repos` the name to rely on in RBAC policies and guardrails below.

```yaml
federated_servers:
  - type: openapi
    origin: http://127.0.0.1:8091
    prefix: gh
    namespace: always
    rbac: read_only
    timeout: 10s
    spec:
      openapi: "3.0.0"
      info:
        title: Mock repository search
        version: "1.0"
      paths:
        "/search/repositories":
          get:
            operationId: search_repos
            summary: Search repositories by query.
            parameters:
              - name: q
                in: query
                required: true
                schema:
                  type: string
```

Second, the RBAC allowlist. `rbac_policies` are named, default-deny ACLs: a caller matching no rule is refused before the upstream is ever contacted, so a tool is reachable only when a rule explicitly allows it. `read_only` allows `gh.search_repos` to any caller (`principals: []` matches everyone); a real deployment scopes `principals` to a virtual key, team, or role instead. `db_writer` does the same for `db.query`, kept separate so a caller cleared for read-only GitHub search is not automatically cleared to write to the database upstream.

```yaml
rbac_policies:
  read_only:
    default_allow: false
    tool_access:
      - principals: []
        allowed: ["gh.search_repos"]
  db_writer:
    default_allow: false
    tool_access:
      - principals: []
        allowed: ["db.query"]
```

Third, the honest placeholder and the allowlist guardrail. `db` is a plain `type: mcp` server pointed at `postgres.example.com`, an RFC 2606 reserved hostname that resolves nowhere — this is what an unfinished federation entry looks like before you point it at a real server. The `tool_allowlist` guardrail is a second, coarser gate on top of RBAC: even an RBAC-allowed tool must also appear here to be forwarded, which is useful as a single audited list independent of the per-caller policy detail above.

```yaml
  - origin: postgres.example.com
    prefix: db
    namespace: always
    rbac: db_writer
    timeout: 5s

guardrails:
  - type: tool_allowlist
    allow:
      - gh.search_repos
      - db.query
```

## Run it

Start the mock upstream, then the gateway that federates it:

```bash
sbproxy serve -f examples/mcp-federation/upstream.yml &
sbproxy serve -f examples/mcp-federation/sb.yml
```

Initialize an MCP session. This is answered locally by the gateway — no upstream is contacted, so it works even before the mock is up:

```console
$ curl -s -X POST http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | jq -c '.result.serverInfo'
{"name":"my-mcp","version":"1.0.0"}
```

List the federated catalogue. Only `gh.search_repos` shows up: the `db` upstream's `tools/list` fetch fails against the unreachable placeholder, and federation drops the failed server rather than failing the whole call.

```console
$ curl -s -X POST http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq -c '.result.tools[].name'
"gh.search_repos"
```

Call the real tool. The gateway resolves the OpenAPI route for `search_repos`, puts `q` on the query string, and sends an actual GET to the mock upstream — the response below is that upstream's real body, wrapped as MCP tool-result content:

```console
$ curl -s -X POST http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gh.search_repos","arguments":{"q":"sbproxy"}}}' \
  | jq -r '.result.content[0].text'
[{"full_name":"soapbucket/sbproxy","name":"sbproxy","stars":4200},{"full_name":"soapbucket/docs","name":"docs","stars":12}]
```

Call a tool that is not on the allowlist. The `tool_allowlist` guardrail refuses it before the gateway even checks whether the tool exists, let alone contacts an upstream:

```console
$ curl -s -X POST http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gh.delete_repo","arguments":{"owner":"foo","repo":"bar"}}}' \
  | jq -c '.error'
{"code":-32602,"message":"tool 'gh.delete_repo' is blocked by tool_allowlist guardrail"}
```

Now call `db.query`, the tool behind the placeholder upstream. This is the honest failure mode this guide promised: the tool never entered the registry because `db`'s `tools/list` never succeeded, so the gateway reports it unknown rather than pretending to reach a database that is not there.

```console
$ curl -s -X POST http://127.0.0.1:8080 \
    -H 'Host: mcp.example.com' -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"db.query","arguments":{"sql":"select 1"}}}' \
  | jq -c '.error'
{"code":-32603,"message":"tool call failed: unknown tool: db.query"}
```

To make `db` real, point its `origin` at a running MCP server — a bare hostname normalises to `https://<host>/mcp`, or give a full URL (including `http://127.0.0.1:<port>/mcp` for something running locally) — or convert it to a second `type: openapi` server the way `gh` is done here, pointed at any REST API you own with a `spec` or `spec_path`. Neither change touches `rbac_policies` or the `tool_allowlist` guardrail; both keep applying.

## You are done when

- `tools/list` returns exactly one tool, `gh.search_repos`, and does not error even though `db`'s upstream is unreachable.
- `tools/call gh.search_repos` returns `"isError":false` with the mock upstream's repository list in `.result.content[0].text`.
- `tools/call gh.delete_repo` (not on the allowlist) returns a JSON-RPC error naming the blocked tool, code `-32602`.
- `tools/call db.query` returns a JSON-RPC error naming it an unknown tool, code `-32603` — proof that a federated server failing does not silently forward calls to a tool that was never really there.

## Next steps

- [tool-versioning.md](tool-versioning.md) - once `db` is real, add the rollout plane and compatibility oracle so a breaking change to `search_repos` fails a version-bump check instead of breaking every agent that calls it at once.
- [`examples/mcp-progressive-discovery`](../examples/mcp-progressive-discovery) - once the federated catalogue grows past a handful of tools, advertise `search` / `execute` meta-tools instead of the full list so it does not eat the model's context window.
- [`examples/mcp-rbac-quotas`](../examples/mcp-rbac-quotas) - per-tool sliding-window quotas on top of the same default-deny RBAC used here.
- [mcp.md](mcp.md) - the full wire format: sessions, OAuth discovery, resources, and the session ledger for behavioral eval.
- [mcp-archestra-guardrails.md](mcp-archestra-guardrails.md) - egress policy, session risk, and quarantine for tool output, including the OpenAPI-backed REST egress this guide left at its allow-all default.
- [configuration.md](configuration.md) - the full configuration schema.
