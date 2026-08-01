# Getting started

*Last modified: 2026-07-31*

This walkthrough runs one local upstream through three gateway configurations. It needs SBproxy, `curl`, and `jq`. It makes no network request to an AI provider and needs no API key.

On Windows, run the commands in Git Bash, or replace `curl` with `curl.exe` in PowerShell: the bare name is an alias for `Invoke-WebRequest` there and rejects flags like `-H`.

SBproxy currently binds its data listener to all host interfaces. Run this
walkthrough on a trusted development machine or behind a host firewall. The
commands connect through `127.0.0.1`, and the cleanup section stops both
listeners when you finish.

Install SBproxy first if `sbproxy --version` does not print a version:

```bash
curl -fsSL https://download.sbproxy.dev | sh
export PATH="$HOME/.local/bin:$PATH"
sbproxy --version
```

Add the `export` to your shell profile if `~/.local/bin` was not already on
`PATH`.

Clone the repository so the example files are available:

```bash
git clone https://github.com/soapbucket/sbproxy
cd sbproxy
```

The example has four configurations. `upstream.yml` starts a fixed local service on port 8091. The other files use port 8080 and add one traffic type at a time: HTTP API, MCP, then AI.

```bash
for config in upstream.yml api.yml mcp.yml sb.yml; do
  sbproxy validate "examples/enterprise-ai-gateway/$config"
done
```

`sbproxy validate` parses and compiles the configuration without opening a listener. Fix a validation error before starting the process.

## Start the local upstream

In the first terminal, run the fixture and leave it running:

```bash
sbproxy serve -f examples/enterprise-ai-gateway/upstream.yml
```

`upstream.yml` sets `proxy.http_bind_port` to `8091`. Its `127.0.0.1` origin uses a mock action that returns a fixed OpenAI-compatible JSON response on every path. The fields used later are `gateway`, `object`, `model`, and `choices[0].message.content`.

## Stage 1: proxy an HTTP API

In a second terminal, start the API configuration:

```bash
sbproxy serve -f examples/enterprise-ai-gateway/api.yml
```

`api.yml` binds the gateway to port `8080`. Its `api.example.com` origin has a `proxy` action whose upstream URL is `http://127.0.0.1:8091`. The `Host` header selects that origin, so the client can reach a local listener while still exercising hostname routing.

SBproxy blocks proxy upstreams that resolve to private IP addresses by
default. This local example opts into only the IPv4 loopback range with
`proxy.extensions.upstream.allow_private_cidrs: [127.0.0.0/8]`. Keep that
allowlist as narrow as possible; a production service on a public address
does not need it. The AI provider in stage 3 has a separate
`allow_private_base_url: true` switch because model-provider egress is
configured independently from a conventional proxy action.

Send a request from a third terminal:

```bash
curl -sS \
  -H 'Host: api.example.com' \
  http://127.0.0.1:8080/status | jq '{gateway, object, model}'
```

The response includes `"gateway": "sbproxy"`. That value comes from the local upstream and proves the request passed through the gateway.

Stop the stage-1 gateway with `Ctrl-C` in the second terminal. Keep the upstream terminal running.

## Stage 2: add an MCP tool

Start the next configuration in the second terminal:

```bash
sbproxy serve -f examples/enterprise-ai-gateway/mcp.yml
```

`mcp.yml` keeps the API origin and adds `mcp.example.com`. Its `mcp` action derives a tool from the local upstream's OpenAPI description. The server is given the `local` prefix and uses an always-on namespace, so its `GET /status` operation appears as `local.gateway_status`.

An MCP client initializes the connection before it lists or calls tools. This
example leaves sessions disabled, so the gateway does not return a session ID
that you need to save.

Initialize the client:

```bash
curl -sS \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl-demo","version":"1.0.0"}}}' \
  http://127.0.0.1:8080/ | jq .
```

Then tell the gateway initialization is complete:

```bash
curl -sS -o /dev/null -w 'initialized: HTTP %{http_code}\n' \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  http://127.0.0.1:8080/
```

List the tool catalogue:

```bash
curl -sS \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  http://127.0.0.1:8080/ | jq '.result.tools[] | select(.name == "local.gateway_status")'
```

The command prints the `local.gateway_status` tool. Call it with another JSON-RPC request:

```bash
curl -sS \
  -H 'Host: mcp.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"local.gateway_status","arguments":{}}}' \
  http://127.0.0.1:8080/ | jq '.result.content'
```

The returned content contains `sbproxy`. Stop this gateway with `Ctrl-C` before the next stage.

## Stage 3: add an AI endpoint

Start the complete configuration:

```bash
sbproxy serve -f examples/enterprise-ai-gateway/sb.yml
```

`sb.yml` keeps the API and MCP origins, then adds `ai.example.com`. Its `ai_proxy` action uses `local-demo` as the default model. The `local-openai` provider speaks the OpenAI protocol at `http://127.0.0.1:8091/v1`; `allow_private_base_url: true` permits this loopback provider. The fixture answers the request, so no model weights or provider credentials are involved.

Send a chat completion:

```bash
curl -sS \
  -H 'Host: ai.example.com' \
  -H 'Content-Type: application/json' \
  -d '{"model":"local-demo","messages":[{"role":"user","content":"Say hello."}]}' \
  http://127.0.0.1:8080/v1/chat/completions \
  | jq '{object, model, content: .choices[0].message.content}'
```

The response has `"object": "chat.completion"` and a nonempty `content` value.

## Stop and clean up

Press `Ctrl-C` in the gateway terminal, then press `Ctrl-C` in the upstream terminal. The walkthrough starts no background process, writes no credentials, and leaves no model cache. Keep the checked-out example files for later runs.

## Continue

Read [core concepts](core-concepts.md) for the shared request pipeline, then use [configuration.md](configuration.md) to change the example. [MCP](mcp.md) and [AI gateway](ai-gateway.md) explain the two actions in depth. To connect a LangChain application, model calls and tools both, follow [langchain.md](langchain.md). To run actual local model weights, use [Run your first managed model](quickstart-serve.md).
