// Package engine implements the HTTP request processing pipeline.
//
// The engine wires together the chi router, global middleware stack,
// config loader, and compiled origin handler chains. Incoming requests
// flow through global middleware (recovery, compression, real IP, fast-path
// context population, correlation ID, logging, shutdown drain) before host
// resolution selects the compiled origin chain. The origin chain then
// applies per-origin layers (session, bot detection, policies, auth,
// modifiers, transforms, caching) before the action handler proxies,
// redirects, or serves content.
//
// Sub-packages:
//   - handler: proxy, echo, SSE, and WebSocket request handlers
//   - middleware: global and per-origin HTTP middleware
//   - streaming: SSE and chunked response streaming
//   - transport: HTTP transport with circuit breaker and connection pooling
package engine
