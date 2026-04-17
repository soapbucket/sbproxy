# sbproxy

## Build & Test
- **Build:** `go build ./cmd/sbproxy/`
- **Full build:** `go build ./...`
- **Test:** `go test ./...`
- **Config tests:** `go test ./internal/config/ -count=1 -timeout 120s`
- **Module tests:** `go test ./internal/modules/... -v`
- **Lint:** `golangci-lint run ./...`
- **Validate config:** `go run ./cmd/sbproxy/ validate -c sb.yml`

## Pre-Commit Requirements
Before committing ANY change, you MUST verify:
1. `go build ./...` - zero errors
2. `go test ./internal/config/ -count=1 -timeout 120s` - all tests pass
3. `go test ./internal/modules/... -v` - all module tests pass
4. `go vet ./...` - zero warnings

Do NOT commit if any of these fail. Fix the issue first.

## Package Structure
- `pkg/plugin/` - Public plugin interfaces (ActionHandler, PolicyEnforcer, AuthProvider, TransformHandler, RequestEnricher) and registry
- `pkg/config/` - Public config types (zero internal imports)
- `pkg/httpkit/` - Public HTTP utilities (ClientIP, SplitHostPort)
- `pkg/events/` - Public EventBus interface (no-op default)
- `pkg/proxy/` - Public lifecycle API: New(), Run(), Shutdown()
- `internal/modules/` - Self-contained modules registered via pkg/plugin
  - `internal/modules/action/` - Action handlers: proxy, redirect, static, echo, loadbalancer, aiproxy, mcp, a2a, websocket, grpc, graphql, mock, beacon, noop, storage
  - `internal/modules/auth/` - Auth providers: apikey, basicauth, bearer, jwt, forwardauth, digest, grpcauth, noop
  - `internal/modules/policy/` - Policy enforcers: ratelimit, ipfilter, expression (CEL), waf, ddos, csrf, secheaders, requestlimit, assertion, sri
  - `internal/modules/transform/` - Response transforms: json, jsonprojection, jsonschema, html, markdown, css, template, luajson, encoding, formatconvert, normalize, replacestrings, ssechunking, payloadlimit, discard, optimizehtml, javascript, htmltomarkdown, noop
- `internal/config/` - Config loading, validation, compilation, and the 18-layer handler chain
- `internal/engine/` - HTTP request pipeline (chi router, middleware, streaming, transport)
- `internal/ai/` - AI gateway handler (providers, routing, guardrails, streaming)
- `internal/extension/` - Scripting runtimes (CEL, Lua, MCP)
- `internal/cache/` - Response and object caching (memory, file, pebble, redis backends)
- `internal/loader/` - Config lifecycle (configloader, featureflags, manager, settings)
- `internal/observe/` - Observability (events, logging, metrics, telemetry)
- `internal/platform/` - Infrastructure (circuitbreaker, dns, health, messenger, storage)
- `internal/request/` - Per-request context (classifier, ratelimit, session)
- `internal/security/` - Security primitives (certpin, crypto, hostfilter)
- `internal/service/` - Server lifecycle (server, signals, hotreload)
- `internal/transformer/` - Response body transformation (css, html, json)
- `cmd/sbproxy/` - Binary entry point
- `examples/` - Working config examples (all use test.sbproxy.dev)
- `docs/` - Documentation

## Module System
sbproxy uses a Caddy-style module architecture:
- Each module registers itself via `init()` into `pkg/plugin` registry
- Modules are imported via blank imports in `internal/modules/imports.go`
- The config compiler (`internal/config/compiler.go`) discovers modules from the `pkg/plugin` registry
- New modules implement one of: `plugin.ActionHandler`, `plugin.PolicyEnforcer`, `plugin.AuthProvider`, `plugin.TransformHandler`, or `plugin.RequestEnricher`
- Optional lifecycle: `plugin.Provisioner`, `plugin.Validator`, `plugin.Cleanup`
- Additional registrations: `plugin.RegisterMiddleware`, `plugin.RegisterHealthChecker`, `plugin.RegisterTransport`, `plugin.RegisterEnricher`

## RequestEnricher Pattern
The `plugin.RequestEnricher` interface enables extensible per-request context enrichment without hardcoding features like GeoIP or user-agent parsing into the core:
- Enterprise/third-party packages implement `RequestEnricher` (Name + Enrich methods)
- Register via `plugin.RegisterEnricher()` in `init()`
- The enricher middleware (`internal/engine/middleware/enricher.go`) calls all registered enrichers on every request
- Enrichers store results via `plugin.SetEnrichmentData()`, and the middleware applies them to `RequestData`
- Errors are logged but never block request processing

## Compiled Handler Chain (18 Layers)
The compiler (`internal/config/compiler.go`) builds each origin's handler chain inside-out:
1. Action handler (innermost)
2. Response cache
3. Transforms
4. on_response callbacks
5. Response modifiers
6. Request modifiers
7. Auth
8. on_request callbacks
9. Compression
10. CORS
11. HSTS
12. Policies (outermost of per-origin middleware)
13. Rate limit headers
14. Bot detection
15. Threat protection
16. Session
17. Message signatures (RFC 9421)
18. Traffic capture, error pages, force_ssl, allowed_methods (outermost)

The chain is compiled once per origin and cached. Requests execute the pre-compiled chain with zero per-request allocation.

## Adding a New Module
1. Create package under `internal/modules/{type}/{name}/`
2. Define config struct and implement the appropriate `pkg/plugin` interface
3. Register via `plugin.Register{Action|Policy|Auth|Transform|Enricher}()` in `init()`
4. Add blank import to `internal/modules/imports.go`
5. Run full build and test suite before committing

## Rules
- `pkg/` packages must NEVER import from `internal/`
- Modules should NOT import `internal/config` - use `pkg/plugin` interfaces
- Run `go build ./...` after every change
- All examples use test.sbproxy.dev as the backend
- Do NOT use em dashes in any content
- Do NOT include enterprise features in OSS code
- Enterprise features are available via sbproxy Cloud (cloud.sbproxy.dev)
- GeoIP and UA parser enrichers are enterprise-only (registered via `plugin.RegisterEnricher` in sbproxy-enterprise)

## License & Attribution
- This project is licensed under Apache 2.0 (see `LICENSE`)
- **NOTICE file maintenance:** When adding or upgrading a dependency that is licensed under Apache 2.0 (not dual MIT/Apache-2.0), update the `NOTICE` file with the dependency's copyright notice and license. Apache 2.0 Section 4 requires this.
- To check: run `go-licenses csv ./...` or inspect `go.mod` for Apache-only deps
- Copyright holder: Soap Bucket LLC
- Do NOT expose internal implementation details (language, libraries, algorithms) in user-facing content per the root CLAUDE.md anti-patterns
