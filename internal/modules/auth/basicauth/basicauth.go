// Package basicauth registers the basic_auth authentication provider.
package basicauth

import (
	"crypto/subtle"
	"encoding/json"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
	"log/slog"
	"net/http"
	"strings"
)

func init() {
	plugin.RegisterAuth("basic_auth", New)
}

// User represents a username/password pair for basic auth.
type User struct {
	Username string `json:"username"`
	Password string `json:"password" secret:"true"`
}

// Config holds configuration for the basic_auth provider.
type Config struct {
	Type     string `json:"type"`
	Disabled bool   `json:"disabled,omitempty"`
	Users    []User `json:"users"`

	// Runtime fields (not from JSON).
	userMap map[string]string // username -> password, O(1) lookup
}

// provider is the runtime auth provider.
type provider struct {
	cfg *Config
}

// New creates a new basic_auth provider from raw JSON configuration.
func New(data json.RawMessage) (plugin.AuthProvider, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.userMap = make(map[string]string, len(cfg.Users))
	for _, u := range cfg.Users {
		cfg.userMap[u.Username] = u.Password
	}

	return &provider{cfg: cfg}, nil
}

func (p *provider) Type() string { return "basic_auth" }

func (p *provider) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			ipAddress := extractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), false, "basic", "", ipAddress, "credentials_missing")
			metric.AuthFailure("unknown", "basic", "credentials_missing", ipAddress)
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Fast O(1) lookup for static users.
		if expectedPassword, exists := p.cfg.userMap[username]; exists {
			if subtle.ConstantTimeCompare([]byte(expectedPassword), []byte(password)) == 1 {
				slog.Info("user authenticated via basic auth",
					"username", username,
					"auth_method", "basic",
					"source", "static")
				ipAddress := extractIP(r)
				logging.LogAuthenticationAttempt(r.Context(), true, "basic", username, ipAddress, "")
				next.ServeHTTP(w, r)
				return
			}
		} else {
			// Fallback linear search (e.g., when userMap was not built).
			for _, u := range p.cfg.Users {
				if subtle.ConstantTimeCompare([]byte(u.Username), []byte(username)) == 1 &&
					subtle.ConstantTimeCompare([]byte(u.Password), []byte(password)) == 1 {
					slog.Info("user authenticated via basic auth",
						"username", username,
						"auth_method", "basic",
						"source", "static_linear")
					ipAddress := extractIP(r)
					logging.LogAuthenticationAttempt(r.Context(), true, "basic", username, ipAddress, "")
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		slog.Warn("basic auth authentication failed",
			"username", username,
			"reason", "invalid_credentials")

		ipAddress := extractIP(r)
		logging.LogAuthenticationAttempt(r.Context(), false, "basic", username, ipAddress, "invalid_credentials")
		metric.AuthFailure("unknown", "basic", "invalid_credentials", ipAddress)
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func extractIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return r.RemoteAddr
}
