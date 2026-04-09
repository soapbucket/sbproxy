// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// generateRequestID creates a unique request identifier with the "req-" prefix
// followed by 16 random hex characters (8 bytes of entropy from crypto/rand).
func generateRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "req-" + hex.EncodeToString(b)
}

// resolveRequestID reads X-Request-ID from the client request headers.
// If the header is missing or empty, it generates a new request ID.
// It returns the resolved request ID.
func resolveRequestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-ID"); id != "" {
		return id
	}
	return generateRequestID()
}
