// policy.go defines the PolicyEnforcer interface for request policy plugins.
package plugin

import (
	"encoding/json"
	"net/http"
)

// PolicyEnforcer is the interface for policy plugins that gate access to the
// action handler. Policies run after authentication has succeeded, forming the
// second layer of request validation. Common policies include rate limiting,
// IP filtering, WAF rules, and CEL expression evaluation.
//
// Multiple policies can be stacked on a single origin. They are applied in the
// order they appear in the configuration, and each must pass for the request
// to reach the action handler.
type PolicyEnforcer interface {
	// Type returns the policy type name as it appears in configuration (e.g.,
	// "rate_limit", "ip_filter", "waf", "cel").
	Type() string

	// Enforce returns a new [http.Handler] that evaluates the policy before calling
	// next. If the policy allows the request, next.ServeHTTP is called to continue
	// the pipeline. If not, the handler writes an appropriate error response (e.g.,
	// 429 Too Many Requests, 403 Forbidden) and does not call next. This uses the
	// same wrapping pattern as [AuthProvider.Wrap].
	Enforce(next http.Handler) http.Handler
}

// PolicyFactory is a constructor function that creates a PolicyEnforcer from raw
// JSON configuration. Registered via [RegisterPolicy] during init().
type PolicyFactory func(cfg json.RawMessage) (PolicyEnforcer, error)

// CSPReportURIProvider is an optional interface that a [PolicyEnforcer] may
// implement to expose the Content-Security-Policy violation report URI. The
// CSP report handler in internal/config uses this to match incoming report
// requests against the configured URI.
type CSPReportURIProvider interface {
	// CSPReportURI returns the report-uri value from the CSP configuration, or
	// an empty string if CSP reporting is not enabled.
	CSPReportURI() string
}
