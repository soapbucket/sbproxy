// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// applyCORSHeaders applies CORS headers to a response based on the request origin.
// Implements the Fetch Standard CORS protocol.
func applyCORSHeaders(w http.ResponseWriter, r *http.Request, cfg *CORSConfig) {
	if cfg == nil || !cfg.Enable {
		return
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}

	// Check if origin is allowed
	allowed := false
	allowedOrigin := ""
	for _, o := range cfg.AllowOrigins {
		if o == "*" {
			if cfg.AllowCredentials {
				// When credentials are allowed, reflect the origin instead of "*"
				allowedOrigin = origin
			} else {
				allowedOrigin = "*"
			}
			allowed = true
			break
		}
		if strings.EqualFold(o, origin) {
			allowedOrigin = origin
			allowed = true
			break
		}
	}

	if !allowed {
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)

	if cfg.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if len(cfg.ExposeHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(cfg.ExposeHeaders, ", "))
	}

	// Vary by Origin when not using wildcard
	if allowedOrigin != "*" {
		w.Header().Add("Vary", "Origin")
	}
}

// handleCORSPreflight handles CORS preflight OPTIONS requests.
// Returns true if the request was a preflight and was handled.
func handleCORSPreflight(w http.ResponseWriter, r *http.Request, cfg *CORSConfig) bool {
	if cfg == nil || !cfg.Enable {
		return false
	}

	if r.Method != http.MethodOptions {
		return false
	}

	origin := r.Header.Get("Origin")
	requestMethod := r.Header.Get("Access-Control-Request-Method")
	if origin == "" || requestMethod == "" {
		return false
	}

	// Check origin
	allowed := false
	allowedOrigin := ""
	for _, o := range cfg.AllowOrigins {
		if o == "*" {
			if cfg.AllowCredentials {
				allowedOrigin = origin
			} else {
				allowedOrigin = "*"
			}
			allowed = true
			break
		}
		if strings.EqualFold(o, origin) {
			allowedOrigin = origin
			allowed = true
			break
		}
	}

	if !allowed {
		reqctx.RecordPolicyViolation(r.Context(), "cors", "Invalid CORS origin")
		w.WriteHeader(http.StatusForbidden)
		return true
	}

	w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)

	// Allow methods
	methods := cfg.AllowMethods
	if len(methods) == 0 {
		methods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	}
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))

	// Allow headers
	if requestHeaders := r.Header.Get("Access-Control-Request-Headers"); requestHeaders != "" {
		headers := cfg.AllowHeaders
		if len(headers) == 0 {
			headers = []string{"Content-Type", "Authorization", "X-Requested-With"}
		}
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(headers, ", "))
	}

	if cfg.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	maxAge := cfg.MaxAge
	if maxAge <= 0 {
		maxAge = 86400
	}
	w.Header().Set("Access-Control-Max-Age", strconv.Itoa(maxAge))

	if allowedOrigin != "*" {
		w.Header().Add("Vary", "Origin")
	}
	w.Header().Add("Vary", "Access-Control-Request-Method")
	w.Header().Add("Vary", "Access-Control-Request-Headers")

	w.WriteHeader(http.StatusNoContent)
	return true
}
