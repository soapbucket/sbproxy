# Changelog

All notable changes are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.2] - 2026-04-12

### Added
- 200+ AI provider support with native provider registry.
- Comparison documentation (LiteLLM, Portkey, Kong, Caddy, Traefik, Nginx, Envoy).
- Provider documentation with full provider list.

### Fixed
- Go version badge updated to match go.mod (1.25).
- Install script now uses user's bin directory instead of system path.
- Race condition in test suite.
- Flaky test stabilized.
- CI no longer triggers on docs-only PRs.
- Cloud hosting link updated to sbproxy.dev.
- Version number corrected in binary output.

## [0.1.1] - 2026-04-12

### Fixed
- Goreleaser retry failures resolved by replacing existing release assets.

## [0.1.0] - 2026-04-12

### Added
- Initial release. Single-binary reverse proxy and AI gateway.
- 18-layer compiled handler chain with sub-millisecond overhead.
- Reverse proxy with path-based routing, load balancing (10 algorithms), and health checks.
- AI gateway with OpenAI-compatible API, model fallback chains, and provider routing.
- Authentication: API key, basic auth, bearer token, JWT (HS256/RS256/ES256), forward auth, digest.
- Security: WAF (OWASP CRS), DDoS protection, IP filtering, CORS, CSRF, HTTP signatures, bot detection.
- Response caching with TTL, stale-while-revalidate, and stale-if-error.
- CEL expressions and Lua scripting for custom logic.
- Protocol support: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, SSE, MCP, A2A.
- Structured logging, Prometheus metrics, and OpenTelemetry tracing.
- Hot reload without restarts or dropped connections.
- 17 working example configurations.
- Apache 2.0 license.

[Unreleased]: https://github.com/soapbucket/sbproxy/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/soapbucket/sbproxy/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/soapbucket/sbproxy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/soapbucket/sbproxy/releases/tag/v0.1.0
