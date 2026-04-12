// action.go defines the ActionHandler interface for origin action plugins.
package plugin

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
)

// ActionHandler is the core interface for origin actions. An action defines what
// the proxy does with a request after authentication and policies have passed.
// Built-in action types include reverse proxy, redirect, static response, and
// load balancer.
//
// Actions are the terminal step in the request pipeline: they produce the response
// that is eventually sent back to the client (possibly after response transforms).
//
// Implementations must be safe for concurrent use.
type ActionHandler interface {
	// Type returns the action type name as it appears in configuration (e.g.,
	// "proxy", "redirect", "static", "load_balancer").
	Type() string

	// ServeHTTP handles the request and writes the response. For simple actions
	// like static responses or redirects, this is the only method needed.
	ServeHTTP(http.ResponseWriter, *http.Request)
}

// ReverseProxyAction extends ActionHandler with methods that integrate with Go's
// [httputil.ReverseProxy]. Implement this interface instead of ActionHandler when
// the action needs fine-grained control over the proxy lifecycle: rewriting the
// outbound request, providing a custom transport, modifying the upstream response,
// or handling proxy errors.
//
// The proxy engine detects this interface and wires the methods into a
// [httputil.ReverseProxy] instance rather than calling ServeHTTP directly.
type ReverseProxyAction interface {
	ActionHandler

	// Rewrite modifies the outbound request before it is sent to the upstream.
	// This is where URL rewriting, header injection, and host changes happen.
	Rewrite(*httputil.ProxyRequest)

	// Transport returns the [http.RoundTripper] used to send requests upstream.
	// Return nil to use the default transport. Custom transports are useful for
	// TLS configuration, connection pooling, or request coalescing.
	Transport() http.RoundTripper

	// ModifyResponse is called after a successful upstream response is received
	// but before it is copied to the client. Return a non-nil error to trigger
	// ErrorHandler instead of forwarding the response.
	ModifyResponse(*http.Response) error

	// ErrorHandler is called when the upstream request fails or ModifyResponse
	// returns an error. It should write an appropriate error response to the client.
	ErrorHandler(http.ResponseWriter, *http.Request, error)
}

// ActionFactory is a constructor function that creates an ActionHandler from raw
// JSON configuration. Each action plugin registers a factory via [RegisterAction]
// during init(). The factory is called once per origin configuration load, not
// per request, so expensive setup (parsing config, compiling templates) happens here.
type ActionFactory func(cfg json.RawMessage) (ActionHandler, error)
