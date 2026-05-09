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

### Operations
- [access-log.md](access-log.md) - structured JSON access log: filters, sampling, header capture, redaction.
- [audit-log.md](audit-log.md) - tamper-evident audit log of admin actions.
- [observability.md](observability.md) - metrics, logs, traces, and the bundled dashboards.
- [operator-runbook.md](operator-runbook.md) - dashboard triage and rollback actions.
- [threat-model.md](threat-model.md) - OSS trust boundaries and per-wave review checklist.
- [events.md](events.md) - the event bus, callback hooks, and emitted event types.
- [openapi-emission.md](openapi-emission.md) - publishing an OpenAPI 3.0 document from the live config.
- [performance.md](performance.md) - tuning guide, benchmark methodology, profiling.
- [degradation.md](degradation.md) - failure modes and graceful degradation behavior.
- [upgrade.md](upgrade.md) - migration notes between releases.
- [quickstart-operator.md](quickstart-operator.md) - first 24 hours running the Kubernetes operator.
- [kubernetes.md](kubernetes.md) - the OSS Kubernetes operator and its CRDs.

### Reference
- [402-challenge.md](402-challenge.md) - wire-format contract for the `402 Payment Required` body, including the OSS-advertises / enterprise-settles split.
- [config-stability.md](config-stability.md) - field stability guarantees and versioning.
- [enterprise.md](enterprise.md) - what the enterprise tier adds on top of the OSS data plane and how to request access.
- [glossary.md](glossary.md) - vocabulary used in this documentation set.
- [headers-reference.md](headers-reference.md) - every response header the proxy can emit, with the config that triggers it.
- [metrics-stability.md](metrics-stability.md) - Prometheus metric naming and stability.
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
make run CONFIG=examples/00-basic-proxy/sb.yml
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
- AI gateway: 200+ LLM models, 9 routing strategies, OpenAI-compatible API, guardrails, budgets, virtual keys, MCP server.
- Authentication: API key, basic, bearer, JWT, digest, forward auth, noop.
- Policies: rate limiting, IP filter, CEL expressions, WAF, DDoS, CSRF, security headers.
- Transforms: 18 request and response transforms (JSON, HTML, Markdown, CSS, Lua, JavaScript, encoding, and more).
- Scripting: CEL via cel-rust, Lua via mlua/Luau, JavaScript via QuickJS, WebAssembly via wasmtime.
- Caching: response cache with pluggable backends (memory, file, Redis).
- Load balancing: 7 algorithms with sticky sessions and health checks.
- Observability: Prometheus metrics, structured logging, typed event bus, OpenTelemetry tracing.
- Hot reload: config changes apply with no dropped connections.
