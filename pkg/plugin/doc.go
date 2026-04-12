// Package plugin defines interfaces for extensible proxy components.
//
// sbproxy uses a Caddy-style plugin architecture where every extensible
// component type registers a factory function during init(). The proxy engine
// looks up plugins by name when building request pipelines from configuration.
//
// # Registration Types
//
// Six component types can be registered:
//
//   - ActionHandler: handles the core request (proxy, redirect, static, AI proxy, etc.).
//     Register with [RegisterAction].
//   - AuthProvider: authenticates incoming requests (API key, JWT, basic auth, etc.).
//     Register with [RegisterAuth].
//   - PolicyEnforcer: enforces traffic policies (rate limiting, WAF, IP filter, etc.).
//     Register with [RegisterPolicy].
//   - TransformHandler: transforms response bodies (JSON projection, HTML, template, etc.).
//     Register with [RegisterTransform].
//   - RequestEnricher: populates request context with enrichment data (GeoIP, user-agent, etc.).
//     Register with [RegisterEnricher].
//   - MiddlewareRegistration: global middleware applied to every request.
//     Register with [RegisterMiddleware].
//
// Additional registrations are available for health checkers ([RegisterHealthChecker])
// and custom transports ([RegisterTransport]).
//
// # Lifecycle
//
// Plugins may optionally implement [Provisioner] (called once after creation with
// origin context), [Validator] (called after provisioning to check config), and
// [Cleanup] (called on shutdown to release resources).
//
// # Thread Safety
//
// All Register and Get functions are safe for concurrent use. In practice,
// registration happens exclusively during init() before main() runs, so
// lock contention during request handling is negligible.
package plugin
