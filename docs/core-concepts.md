# Core concepts

*Last modified: 2026-07-28*

SBproxy has one request pipeline. The client chooses a hostname, SBproxy finds that hostname in `origins:`, runs the configured policy and action, then returns the upstream response. The upstream can be an ordinary HTTP service, an MCP tool collection, or an AI provider. The request is still handled by the same gateway.

## The request pipeline

1. A client connects to an SBproxy listener and sends a request with a `Host` header.
2. SBproxy selects the matching origin in `origins:`.
3. The origin's authentication, policies, and transforms run around its action.
4. The action proxies HTTP, dispatches an MCP method, or sends an AI request to a provider.
5. SBproxy applies response work, records observability data, and sends the result to the client.

An origin is the unit of configuration that owns this work. It has a client-facing hostname and an action. An action describes what happens after SBproxy accepts the request. A provider is an upstream AI service or local model endpoint used by an `ai_proxy` action.

The detailed order and extension points are in [architecture.md](architecture.md#3-request-pipeline). [configuration.md](configuration.md) is the field-by-field source of truth.

## APIs, MCP, and AI traffic

| Traffic type | What the client sends | What SBproxy routes | Typical result |
|---|---|---|---|
| HTTP API | An HTTP method, path, headers, and body | An HTTP request to an upstream service | The upstream HTTP response |
| MCP | A JSON-RPC method such as `tools/list` or `tools/call` | A tool call to a configured MCP or OpenAPI-backed server | A JSON-RPC tool catalog or tool result |
| AI | An OpenAI- or Anthropic-shaped completion request | A request to a hosted provider or local model | A completion, possibly streamed |

MCP is a protocol for discovering and calling tools. It does not supply model inference. An AI provider generates model output. An HTTP API is the general case: it can be an application backend, a service used by an MCP tool, or an OpenAI-compatible local inference server.

The [MCP guide](mcp.md) explains the MCP action and tool routing. The [AI gateway guide](ai-gateway.md) covers providers, routing, guardrails, budgets, and streaming.

## Data plane and admin plane

The data plane serves application traffic. It is the listener your clients call, usually on port 8080 in local examples. Origins, policies, actions, and providers define its behavior.

The admin plane changes or inspects a running proxy. It includes authenticated configuration and reload endpoints, key management, health, metrics, and the built-in UI when enabled. Keep it on a protected network and use the [admin guide](admin.md) and [admin API guide](admin-api-guide.md) before exposing it. A successful data-plane request does not require an admin-plane request.

## Configuration, compilation, and reload

`sb.yml` is source input, not a set of instructions interpreted one line at a time for every request. At startup, `sbproxy validate` and `sbproxy serve -f` parse and compile it into an origin pipeline. Compilation catches schema and semantic errors before a listener starts.

While SBproxy is running, the file watcher, `SIGHUP`, `sbproxy apply`, and authenticated `POST /admin/reload` use the same reload primitive. SBproxy compiles a candidate configuration first. If it succeeds, the new pipeline is swapped in and new requests use it. If it fails, the prior pipeline continues serving. Some process state, including rate-limit and budget accumulators, survives a compatible reload.

For the exact reload contract and its limits, see [the manual's hot-reload section](manual.md#9-hot-reload). For a production change preview, see [`sbproxy plan`](manual.md#plan---diff-a-proposed-config-against-a-baseline).
