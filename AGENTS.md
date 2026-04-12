# AGENTS.md - AI Agent Instructions for SBproxy

## Project Overview

SBproxy is a reverse proxy and AI gateway written in Go. Single binary, Caddy-style plugin architecture, 18-layer compiled handler chain.

- **Source:** https://github.com/soapbucket/sbproxy
- **Docs:** https://sbproxy.dev/docs
- **License:** Apache 2.0

## Repository Structure

```
cmd/sbproxy/       Binary entry point
pkg/               Public API (plugin interfaces, config types, events)
internal/          Private implementation
  config/          Config loading, validation, compilation (compiler.go is key)
  engine/          HTTP pipeline (middleware, handlers, transport)
  modules/         Plugin modules (action/, auth/, policy/, transform/)
  middleware/      Per-origin middleware (callback, cors, waf, modifier, etc.)
  ai/              AI gateway (providers, routing, guardrails)
  extension/       Scripting (CEL, Lua, MCP)
  observe/         Logging, metrics, telemetry, events
  loader/          Config lifecycle, feature flags
  platform/        Infrastructure (circuit breaker, DNS, health, messenger)
  request/         Request context (reqctx, session, rate limit)
  security/        Crypto, cert pinning, PII, signatures
  cache/           Response and object caching
  service/         Server lifecycle
examples/          16 working config examples (all use test.sbproxy.dev)
docs/              Architecture, configuration, scripting docs
```

## Build and Test

```bash
go build ./...                                    # build
go test ./...                                     # test all
go test ./internal/config/ -count=1 -timeout 120s # config tests
go test ./internal/modules/... -v                 # module tests
go vet ./...                                      # lint
go test -race ./... -count=1 -timeout 180s        # race detector
```

## Key Architectural Concepts

### Plugin System
Modules register via `init()` into `pkg/plugin` registry. Five interfaces:
- `ActionHandler` - what to do with a request (proxy, redirect, static, AI, etc.)
- `AuthProvider` - who can access (api_key, jwt, basic_auth, etc.)
- `PolicyEnforcer` - rules and limits (rate_limit, waf, cel expression, etc.)
- `TransformHandler` - modify response body (json_projection, html, lua, etc.)
- `RequestEnricher` - enrich request context (GeoIP, UA parsing - enterprise only)

### Compiled Handler Chain
`internal/config/compiler.go: CompileOrigin()` builds an 18-layer handler chain per origin. Built inside-out, executes outside-in. Zero per-request allocation.

### Config Format
YAML config (sb.yml) with `proxy:` (global) and `origins:` (per-hostname) top-level keys. Each origin has sibling fields: `action`, `authentication`, `policies`, `transforms`, `request_modifiers`, `response_modifiers`, `forward_rules`, `response_cache`, `on_request`, `on_response`, `compression`, `cors`, `error_pages`.

**Critical rule:** `authentication`, `policies`, `transforms`, etc. are SIBLINGS of `action`, never nested inside it.

### Header Normalization
Two systems with different rules:
- **CEL expressions:** lowercase, hyphens preserved, bracket notation: `request.headers["x-api-key"]`
- **Mustache templates:** lowercase, hyphens to underscores, dot notation: `{{ request.headers.x_api_key }}`

### Enterprise Boundary
- OSS code must NEVER import enterprise packages
- Enterprise code imports only `sbproxy/pkg/*` (never `sbproxy/internal/*`)
- Enterprise features: canary, shadow, geo-blocking, OAuth, WASM, guardrails, semantic cache
- Enterprise modules register via the same `plugin.Register*()` pattern

## Code Style

- Standard `gofmt`
- Explicit `if err != nil` error handling, no panics in production
- All exported types and functions must have Go doc comments
- Add logical section comments at decision points, not on every line
- Use `// --- Section Name ---` dividers in larger files
- Do NOT use em dashes in any content
- Do NOT expose internal implementation details in marketing content
- All documentation files must have `*Last modified: YYYY-MM-DD*` after the title

## When Making Changes

1. Read the existing code before modifying
2. Follow existing patterns in the package
3. Run `go build ./...` after every change
4. Run `go vet ./...` before committing
5. Run `go test` for affected packages
6. All examples use test.sbproxy.dev as the backend
7. Do NOT include enterprise features in OSS code

## Adding a New Module

1. Create package under `internal/modules/{type}/{name}/`
2. Implement the appropriate `pkg/plugin` interface
3. Register via `plugin.Register*()` in `init()`
4. Add blank import to `internal/modules/imports.go`
5. Write tests
6. Run full build and test suite

## Important Files

| File | Purpose |
|---|---|
| `internal/config/compiler.go` | Origin compilation (18-layer handler chain) |
| `pkg/plugin/registry.go` | Plugin registration |
| `pkg/plugin/services.go` | ServiceProvider interface |
| `pkg/plugin/enricher.go` | RequestEnricher interface |
| `internal/engine/middleware/middleware.go` | Global middleware chain and origin routing |
| `internal/modules/imports.go` | Module activation via blank imports |
| `internal/service/service.go` | Server startup sequence |
| `internal/request/reqctx/types.go` | RequestData struct |
| `internal/template/resolver.go` | Template resolution (9-namespace model) |
