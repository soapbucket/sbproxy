# SBproxy documentation
*Last modified: 2026-05-08*

The AI gateway built like a real proxy. One binary, built on Pingora.

## Where to start

New here? Read [manual.md](manual.md) for install and CLI, then [configuration.md](configuration.md) for the schema. The [examples](../examples/) folder has runnable configs you can point the binary at right away.

## Documentation index

### Getting started
- [manual.md](manual.md) - install, CLI, runtime, TLS, deployment patterns.
- [configuration.md](configuration.md) - every `sb.yml` field with examples.
- [features.md](features.md) - tour of every feature with copy-paste configs.
- [troubleshooting.md](troubleshooting.md) - common failure modes and fixes.

### AI gateway
- [ai-gateway.md](ai-gateway.md) - providers, routing strategies, guardrails, budgets, streaming.
- [providers.md](providers.md) - the catalog of supported LLM providers.
- [scripting.md](scripting.md) - CEL, Lua, JavaScript, and WASM scripting reference.
- [mcp.md](mcp.md) - the MCP gateway: wire shape, capabilities, and `experimental.agentSkillsUrl` advertising.
- [agent-skills.md](agent-skills.md) - Agent Skills v0.2.0 well-known projection: schema, integrity, archive safety, no-script-execution contract.
- [cloudflare-code-mode.md](cloudflare-code-mode.md) - typed TypeScript module emission for Cloudflare Code Mode agents over the MCP federation registry.

### Operations
- [access-log.md](access-log.md) - structured JSON access log: filters, sampling, header capture, redaction.
- [audit-log.md](audit-log.md) - tamper-evident audit log of admin actions.
- [observability.md](observability.md) - metrics, logs, traces, and the bundled dashboards.
- [operator-runbook.md](operator-runbook.md) - dashboard triage and rollback actions.
- [threat-model.md](threat-model.md) - OSS trust boundaries and per-wave review checklist.
- [events.md](events.md) - the event bus, callback hooks, and emitted event types.
- [openapi-emission.md](openapi-emission.md) - publishing an OpenAPI 3.0 document from the live config.
- [policy.md](policy.md) - the policy engine: `semantic_constraint`, the NL linter L001-L009, and the OSS / enterprise capability boundary.
- [performance.md](performance.md) - tuning guide, benchmark methodology, profiling.
- [degradation.md](degradation.md) - failure modes and graceful degradation behavior.
- [upgrade.md](upgrade.md) - migration notes between releases.
- [quickstart-operator.md](quickstart-operator.md) - first 24 hours running the Kubernetes operator.
- [kubernetes.md](kubernetes.md) - the OSS Kubernetes operator and its CRDs.

### Reference
- [402-challenge.md](402-challenge.md) - wire-format contract for the `402 Payment Required` body, including the OSS-advertises / enterprise-settles split.
- [outbound-peer-pricing.md](outbound-peer-pricing.md) - the `peer_pricing_preflight` policy: parse a peer's `llms.txt`, gate egress on budget, return a structured 402 to the agent on overflow.
- [admin-api-reference.md](admin-api-reference.md) - per-route schema for the embedded admin server (`/api/*`, `/admin/*`, and the unauthenticated probe routes).
- [config-stability.md](config-stability.md) - field stability guarantees and versioning.
- [listings.md](listings.md) - the repo-native `Listing` primitive: schema, loader, three pinning modes, plan-validation rules.
- [enterprise.md](enterprise.md) - what the enterprise tier adds on top of the OSS data plane and how to request access.
- [glossary.md](glossary.md) - vocabulary used in this documentation set.
- [headers-reference.md](headers-reference.md) - every response header the proxy can emit, with the config that triggers it.
- [metrics-stability.md](metrics-stability.md) - Prometheus metric naming and stability.
- [model-pinning.md](model-pinning.md) - how SHA-256 hashes get computed and pinned for the classifier known-model registry.
- [adr-ai-hub-format.md](adr-ai-hub-format.md) - hub `ChatFormat` trait and the canonical `ChatRequest` / `ChatResponse` shape that backs `/v1/chat/completions`, `/v1/messages`, and `/v1/responses`.
- [adr-classifier-supply-chain-oss.md](adr-classifier-supply-chain-oss.md) - operator-trusted model supply-chain decisions for the OSS classifier path.
- [adr-config-plan-apply.md](adr-config-plan-apply.md) - audit + design for the proposed `sbproxy plan` and `sbproxy apply` subcommands.
- [adr-config-source-modes.md](adr-config-source-modes.md) - audit + design for the `file`, `git`, `git+overlay`, and `db` config source modes.
- [adr-fast-track-amendment.md](adr-fast-track-amendment.md) - template for additive closed-enum ADR changes.
- [comparison.md](comparison.md) - how SBproxy compares to other proxies and AI gateways.

### Contributing
- [architecture.md](architecture.md) - internals: pipeline, hot reload, plugin system.
- [codebase.md](codebase.md) - plain-English walkthrough of every crate.
- [build.md](build.md) - building from source, supported platforms, optional features.
- [CONTRIBUTING.md](../CONTRIBUTING.md) - how to set up a dev environment and submit changes.

## Quick start

```bash
# Build
make build-release

# Run with a config
make run CONFIG=examples/basic-proxy/sb.yml
```

Minimal `sb.yml`:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "api.example.com":
    action:
      type: proxy
      url: http://backend:3000
```

## What's in the box

- Reverse proxy: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, connection pooling, hot reload.
- AI gateway: 200+ LLM models, 10 routing strategies, OpenAI-compatible API, guardrails, budgets, virtual keys, MCP server.
- Authentication: API key, basic, bearer, JWT, digest, forward auth, noop.
- Policies: rate limiting, IP filter, CEL expressions, WAF, DDoS, CSRF, security headers.
- Transforms: 18 request and response transforms (JSON, HTML, Markdown, CSS, Lua, JavaScript, encoding, and more).
- Scripting: CEL via cel-rust, Lua via mlua/Luau, JavaScript via QuickJS, WebAssembly via wasmtime.
- Caching: response cache with pluggable backends (memory, file, Redis).
- Load balancing: 7 algorithms with sticky sessions and health checks.
- Observability: Prometheus metrics, structured logging, typed event bus, OpenTelemetry tracing.
- Hot reload: config changes apply with no dropped connections.
