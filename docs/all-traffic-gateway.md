# All-traffic gateway

*Last modified: 2026-08-28*

One binary, one config, three kinds of traffic: the HTTP APIs you already run, the MCP tools your agents call, and the models your apps call. This page is the hub for that walkthrough. The commands live in [getting-started.md](getting-started.md), which boots [`examples/enterprise-ai-gateway/`](../examples/enterprise-ai-gateway/) in three stages against a local mock (no provider key).

## The four walkthroughs

| You want | Page |
|---|---|
| API + MCP + AI on one listener | This page, then [getting-started.md](getting-started.md) |
| Apps calling models | [getting-started-ai-estate.md](getting-started-ai-estate.md) |
| Agents and crawlers calling you | [getting-started-inbound.md](getting-started-inbound.md) |
| A model you run locally | [quickstart-serve.md](quickstart-serve.md) |

## What the example actually runs

`examples/enterprise-ai-gateway/upstream.yml` is a mock on port 8091. The other files bind the gateway on 8080 and add one traffic type at a time:

1. `api.yml` - hostname routing to that mock (`type: proxy`).
2. `mcp.yml` - an MCP gateway in front of the same origin.
3. `sb.yml` - an `ai_proxy` origin that talks to the mock as if it were a model provider.

You will not hit OpenAI, Anthropic, or a public MCP server. When you are ready for those, [getting-started-ai-estate.md](getting-started-ai-estate.md) and [use-case-mcp-federation.md](use-case-mcp-federation.md) are the next pages.

Field-level reference stays in [configuration.md](configuration.md). Domain hubs: [api-gateway.md](api-gateway.md), [mcp-and-agents.md](mcp-and-agents.md), [ai-gateway.md](ai-gateway.md).
