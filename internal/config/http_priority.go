// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"net/http"
)

// forwardHTTPPriority forwards the Priority header to upstream per RFC 9218.
// The Priority header uses structured fields: urgency (0-7) and incremental (boolean).
// Example: Priority: u=3, i
func forwardHTTPPriority(outReq *http.Request, clientReq *http.Request, cfg *HTTPPriorityConfig) {
	if cfg == nil || !cfg.ForwardPriority {
		return
	}

	priority := clientReq.Header.Get("Priority")
	if priority != "" {
		outReq.Header.Set("Priority", priority)
	}
}
