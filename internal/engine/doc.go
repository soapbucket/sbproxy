// Package engine implements the HTTP request processing pipeline.
//
// The engine wires together the chi router, middleware stack, config
// loader, and action handlers. Incoming requests flow through middleware
// (correlation ID, logging, auth, rate limiting, transforms) before
// reaching the action handler that proxies, redirects, or serves content.
package engine
