// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

func init() {
	authLoaderFuns[AuthTypeForward] = NewForwardAuthConfig
}

// ForwardAuthImpl implements AuthConfig for forward auth by delegating
// authentication to an external service via a subrequest.
type ForwardAuthImpl struct {
	ForwardAuthConfig

	client       *http.Client
	successCodes map[int]bool
}

// NewForwardAuthConfig creates and initializes a new ForwardAuthConfig.
func NewForwardAuthConfig(data []byte) (AuthConfig, error) {
	cfg := &ForwardAuthImpl{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("forward auth: url is required")
	}

	if cfg.Method == "" {
		cfg.Method = http.MethodGet
	} else {
		cfg.Method = strings.ToUpper(cfg.Method)
	}

	// Build success status code set
	cfg.successCodes = make(map[int]bool)
	if len(cfg.SuccessStatus) == 0 {
		cfg.successCodes[http.StatusOK] = true
	} else {
		for _, code := range cfg.SuccessStatus {
			cfg.successCodes[code] = true
		}
	}

	// Set up HTTP client with timeout
	timeout := 5 * time.Second
	if cfg.Timeout.Duration > 0 {
		timeout = cfg.Timeout.Duration
	}
	cfg.client = &http.Client{Timeout: timeout}

	return cfg, nil
}

// Authenticate performs the authenticate operation on the ForwardAuthImpl.
func (c *ForwardAuthImpl) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Build the auth subrequest
		var body io.Reader
		if c.ForwardBody && r.Body != nil {
			body = r.Body
		}

		authReq, err := http.NewRequestWithContext(r.Context(), c.Method, c.URL, body)
		if err != nil {
			slog.Error("forward auth: failed to create request", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Forward configured headers from original request
		if len(c.ForwardHeaders) > 0 {
			for _, header := range c.ForwardHeaders {
				if val := r.Header.Get(header); val != "" {
					authReq.Header.Set(header, val)
				}
			}
		} else {
			// Default: forward Authorization and Cookie headers
			if auth := r.Header.Get("Authorization"); auth != "" {
				authReq.Header.Set("Authorization", auth)
			}
			if cookie := r.Header.Get("Cookie"); cookie != "" {
				authReq.Header.Set("Cookie", cookie)
			}
		}

		// Forward useful request metadata as X-Forwarded-* headers
		authReq.Header.Set("X-Forwarded-Method", r.Method)
		authReq.Header.Set("X-Forwarded-Proto", forwardAuthScheme(r))
		authReq.Header.Set("X-Forwarded-Host", r.Host)
		authReq.Header.Set("X-Forwarded-Uri", r.RequestURI)
		if r.RemoteAddr != "" {
			authReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
		}

		// Make the auth subrequest
		resp, err := c.client.Do(authReq)
		if err != nil {
			ipAddress := forwardAuthExtractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), false, "forward", "", ipAddress, "auth_server_error")
			origin := forwardAuthOrigin(c.cfg)
			metric.AuthFailure(origin, "forward", "auth_server_error", ipAddress)
			emitSecurityAuthFailure(r.Context(), c.cfg, r, "forward", "auth_server_error")

			slog.Error("forward auth: request failed", "error", err, "url", c.URL)
			http.Error(w, "Authentication Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		// Check if auth succeeded
		if c.successCodes[resp.StatusCode] {
			// Copy trust headers from auth response to the downstream request
			for _, header := range c.TrustHeaders {
				if val := resp.Header.Get(header); val != "" {
					r.Header.Set(header, val)
				}
			}

			ipAddress := forwardAuthExtractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), true, "forward", "", ipAddress, "")

			next.ServeHTTP(w, r)
			return
		}

		// Auth failed - forward the auth server's response
		ipAddress := forwardAuthExtractIP(r)
		logging.LogAuthenticationAttempt(r.Context(), false, "forward", "", ipAddress, "denied")
		origin := forwardAuthOrigin(c.cfg)
		metric.AuthFailure(origin, "forward", "denied", ipAddress)
		emitSecurityAuthFailure(r.Context(), c.cfg, r, "forward", "denied")

		// Copy response headers from auth server
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		// Forward the auth server's status code and body
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func forwardAuthScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

func forwardAuthExtractIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return r.RemoteAddr
}

func forwardAuthOrigin(cfg *Config) string {
	if cfg != nil {
		return cfg.ID
	}
	return "unknown"
}
