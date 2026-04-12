// Package bearer registers the bearer_token authentication provider.
package bearer

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAuth("bearer_token", New)
}

const (
	// DefaultHeaderName is the default header for bearer tokens.
	DefaultHeaderName = "Authorization"
	// DefaultHeaderPrefix is the default prefix to strip from the header value.
	DefaultHeaderPrefix = "Bearer "

	// openAIInsecureAPIKeySubprotocolPrefix is the WebSocket subprotocol prefix.
	openAIInsecureAPIKeySubprotocolPrefix = "openai-insecure-api-key."
)

// Config holds configuration for the bearer_token auth provider.
type Config struct {
	Type         string   `json:"type"`
	Disabled     bool     `json:"disabled,omitempty"`
	Tokens       []string `json:"tokens" secret:"true"`
	HeaderName   string   `json:"header_name,omitempty"`
	HeaderPrefix string   `json:"header_prefix,omitempty"`
	CookieName   string   `json:"cookie_name,omitempty"`
	QueryParam   string   `json:"query_param,omitempty"`

	// Runtime fields.
	tokenMap map[string]bool
}

// provider is the runtime auth provider.
type provider struct {
	cfg *Config
}

// New creates a new bearer_token auth provider from raw JSON configuration.
func New(data json.RawMessage) (plugin.AuthProvider, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.tokenMap = make(map[string]bool, len(cfg.Tokens))
	for _, t := range cfg.Tokens {
		cfg.tokenMap[t] = true
	}

	if cfg.HeaderName == "" {
		cfg.HeaderName = DefaultHeaderName
	}
	if cfg.HeaderPrefix == "" {
		cfg.HeaderPrefix = DefaultHeaderPrefix
	}

	return &provider{cfg: cfg}, nil
}

func (p *provider) Type() string { return "bearer_token" }

func (p *provider) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := p.extractToken(r)
		if token == "" {
			slog.Debug("bearer token: no token provided")
			ipAddress := extractIP(r)
			metric.AuthFailure("unknown", "bearer", "token_missing", ipAddress)
			reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Bearer token required")
			http.Error(w, "Unauthorized: Bearer token required", http.StatusUnauthorized)
			return
		}

		// Check all tokens with constant-time comparison (no early exit for timing safety).
		tokenValid := false
		for _, t := range p.cfg.Tokens {
			if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
				tokenValid = true
			}
		}

		if tokenValid {
			slog.Debug("bearer token: authentication successful")
			next.ServeHTTP(w, r)
			return
		}

		slog.Debug("bearer token: invalid token")
		ipAddress := extractIP(r)
		metric.AuthFailure("unknown", "bearer", "token_invalid", ipAddress)
		reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Invalid bearer token")
		http.Error(w, "Unauthorized: Invalid bearer token", http.StatusUnauthorized)
	})
}

func (p *provider) extractToken(r *http.Request) string {
	headerName := p.cfg.HeaderName
	if headerName == "" {
		headerName = DefaultHeaderName
	}

	if header := r.Header.Get(headerName); header != "" {
		prefix := p.cfg.HeaderPrefix
		if prefix == "" {
			prefix = DefaultHeaderPrefix
		}
		if strings.HasPrefix(header, prefix) {
			return strings.TrimPrefix(header, prefix)
		}
		return header
	}

	if p.cfg.CookieName != "" {
		if cookie, err := r.Cookie(p.cfg.CookieName); err == nil && cookie.Value != "" {
			return cookie.Value
		}
	}

	if p.cfg.QueryParam != "" {
		if token := r.URL.Query().Get(p.cfg.QueryParam); token != "" {
			return token
		}
	}

	// WebSocket browser clients may carry credentials in subprotocols.
	if token := extractOpenAIKeyFromSubprotocols(r); token != "" {
		return token
	}

	return ""
}

func extractOpenAIKeyFromSubprotocols(r *http.Request) string {
	raw := r.Header.Values("Sec-WebSocket-Protocol")
	if len(raw) == 0 {
		if h := r.Header.Get("Sec-WebSocket-Protocol"); h != "" {
			raw = []string{h}
		}
	}
	for _, value := range raw {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, openAIInsecureAPIKeySubprotocolPrefix) {
				return strings.TrimPrefix(part, openAIInsecureAPIKeySubprotocolPrefix)
			}
		}
	}
	return ""
}

func extractIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return r.RemoteAddr
}
