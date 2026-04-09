package plugin

import "net/http"

// MiddlewareRegistration describes a global middleware plugin with priority-based
// ordering constraints. Middlewares registered here run on every request before the
// per-origin pipeline (authentication, policies, action). They are used for
// cross-cutting concerns like request logging, tracing, CORS, and DDoS protection.
//
// The proxy engine sorts registered middlewares by Priority (lower values run first)
// and then applies After/Before constraints for fine-grained ordering between
// specific middlewares. For example, a tracing middleware might specify
// After: ["logging"] to ensure it runs after the request ID is assigned.
type MiddlewareRegistration struct {
	// Name is a unique identifier for this middleware, used in After/Before references.
	Name string

	// Priority determines the base execution order. Lower values run earlier in the
	// chain (closer to the client). Suggested ranges: 0-99 for infrastructure (TLS,
	// compression), 100-199 for observability (logging, tracing), 200+ for security
	// (CORS, DDoS).
	Priority int

	// After lists middleware names that must run before this one. The engine will
	// reorder middlewares to satisfy these constraints even if Priority alone would
	// not produce the correct order.
	After []string

	// Before lists middleware names that must run after this one.
	Before []string

	// Factory returns a new middleware function. The outer function is called once at
	// startup; the inner function wraps the next handler in the chain. This two-level
	// factory allows the middleware to perform one-time initialization before returning
	// the per-request wrapper.
	Factory func() func(http.Handler) http.Handler
}
