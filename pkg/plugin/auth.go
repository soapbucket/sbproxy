// auth.go defines the AuthProvider interface for authentication plugins.
package plugin

import (
	"encoding/json"
	"net/http"
)

// AuthProvider is the interface for authentication plugins. Authentication is
// step 4 in the request lifecycle, running after global middleware but before
// policy enforcement. If authentication fails, the request is rejected with a
// 401 or 403 response and never reaches policies or the action handler.
//
// Built-in auth types include basic_auth, api_keys, and OAuth.
type AuthProvider interface {
	// Type returns the auth type name as it appears in configuration (e.g.,
	// "basic_auth", "api_keys", "oauth").
	Type() string

	// Wrap returns a new [http.Handler] that checks authentication before calling
	// next. If the request is authenticated, the handler calls next.ServeHTTP to
	// continue the pipeline. If not, it writes an error response (typically 401)
	// and does not call next. This wrapping pattern allows auth to be composed
	// into the handler chain without modifying other components.
	Wrap(next http.Handler) http.Handler
}

// AuthFactory is a constructor function that creates an AuthProvider from raw
// JSON configuration. Registered via [RegisterAuth] during init().
type AuthFactory func(cfg json.RawMessage) (AuthProvider, error)
