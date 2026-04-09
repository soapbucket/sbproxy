// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"net/http"
)

// isEarlyDataRequest checks if the request was received via TLS 0-RTT early data.
// Go's net/http does not directly expose this, but some TLS implementations
// and load balancers set the Early-Data header.
func isEarlyDataRequest(r *http.Request) bool {
	return r.Header.Get("Early-Data") == "1"
}

// handleEarlyData checks early data safety per RFC 8470.
// Returns true if the request was rejected (caller should stop processing).
func handleEarlyData(w http.ResponseWriter, r *http.Request, cfg *EarlyDataConfig, pdCfg *ProblemDetailsConfig) bool {
	if cfg == nil {
		return false
	}

	if !isEarlyDataRequest(r) {
		return false
	}

	// Check if the method is safe for early data
	if cfg.RejectNonIdempotent && !isEarlyDataSafe(r.Method, cfg) {
		writeProblemDetail(w, r, 425, "Request received via TLS early data is not safe to process", pdCfg)
		return true
	}

	return false
}

// isEarlyDataSafe checks if a method is safe to process from early data.
func isEarlyDataSafe(method string, cfg *EarlyDataConfig) bool {
	safeMethods := cfg.SafeMethods
	if len(safeMethods) == 0 {
		safeMethods = []string{"GET", "HEAD", "OPTIONS"}
	}

	for _, m := range safeMethods {
		if m == method {
			return true
		}
	}
	return false
}

// addEarlyDataHeader adds the Early-Data: 1 header to the outgoing request
// when the original request was received in early data.
func addEarlyDataHeader(outReq *http.Request, clientReq *http.Request, cfg *EarlyDataConfig) {
	if cfg == nil || !cfg.ForwardHeader {
		return
	}

	if isEarlyDataRequest(clientReq) {
		outReq.Header.Set("Early-Data", "1")
	}
}
