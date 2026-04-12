// Package apikey registers the api_key authentication provider.
package apikey

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAuth("api_key", New)
}

const (
	// DefaultHeaderName is the default header to extract the API key from.
	DefaultHeaderName = "X-API-Key"

	// openAIInsecureAPIKeySubprotocolPrefix is the WebSocket subprotocol prefix used by some clients.
	openAIInsecureAPIKeySubprotocolPrefix = "openai-insecure-api-key."
)

// Config holds configuration for the api_key auth provider.
type Config struct {
	Type       string   `json:"type"`
	Disabled   bool     `json:"disabled,omitempty"`
	APIKeys    []string `json:"api_keys" secret:"true"`
	HeaderName string   `json:"header_name,omitempty"`
	QueryParam string   `json:"query_param,omitempty"`

	// Runtime fields (not from JSON).
	apiKeyMap map[string]bool
}

// provider is the runtime auth provider.
type provider struct {
	cfg *Config
}

// New creates a new api_key auth provider from raw JSON configuration.
func New(data json.RawMessage) (plugin.AuthProvider, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.apiKeyMap = make(map[string]bool, len(cfg.APIKeys))
	for _, key := range cfg.APIKeys {
		cfg.apiKeyMap[key] = true
	}
	if cfg.HeaderName == "" {
		cfg.HeaderName = DefaultHeaderName
	}

	return &provider{cfg: cfg}, nil
}

func (p *provider) Type() string { return "api_key" }

func (p *provider) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := p.extractAPIKey(r)
		if apiKey == "" {
			slog.Debug("api key: no api key provided")
			ipAddress := extractIP(r)
			metric.AuthFailure("unknown", "apikey", "key_missing", ipAddress)
			reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: API key required")
			http.Error(w, "Unauthorized: API key required", http.StatusUnauthorized)
			return
		}

		// Check static keys via O(1) map lookup.
		if p.cfg.apiKeyMap[apiKey] {
			slog.Debug("api key: authentication successful")
			trackUniqueUser("apikey", apiKey)
			next.ServeHTTP(w, r)
			return
		}

		// Check dynamic keys with constant-time comparison.
		dynamicKeys := p.cfg.APIKeys
		dynamicKeyValid := false
		for _, key := range dynamicKeys {
			if subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) == 1 {
				dynamicKeyValid = true
			}
		}

		if dynamicKeyValid {
			slog.Debug("api key: authentication successful (dynamic)")
			trackUniqueUser("apikey", apiKey)
			next.ServeHTTP(w, r)
			return
		}

		slog.Debug("api key: invalid api key")
		ipAddress := extractIP(r)
		metric.AuthFailure("unknown", "apikey", "key_invalid", ipAddress)
		reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Invalid API key")
		http.Error(w, "Unauthorized: Invalid API key", http.StatusUnauthorized)
	})
}

func (p *provider) extractAPIKey(r *http.Request) string {
	headerName := p.cfg.HeaderName
	if headerName == "" {
		headerName = DefaultHeaderName
	}

	if apiKey := r.Header.Get(headerName); apiKey != "" {
		return apiKey
	}

	if p.cfg.QueryParam != "" {
		if apiKey := r.URL.Query().Get(p.cfg.QueryParam); apiKey != "" {
			return apiKey
		}
	}

	// WebSocket browser clients may carry API keys in subprotocols.
	if apiKey := extractOpenAIKeyFromSubprotocols(r); apiKey != "" {
		return apiKey
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

// uniqueUsers tracks unique authenticated identifiers per auth type.
var (
	uniqueUsersMap = make(map[string]map[string]bool)
	uniqueUsersMu  sync.RWMutex
)

func trackUniqueUser(userType, identifier string) {
	if identifier == "" {
		return
	}
	uniqueUsersMu.Lock()
	if uniqueUsersMap[userType] == nil {
		uniqueUsersMap[userType] = make(map[string]bool)
	}
	uniqueUsersMap[userType][identifier] = true
	count := int64(len(uniqueUsersMap[userType]))
	uniqueUsersMu.Unlock()
	metric.UniqueUsersSet("unknown", userType, count)
}
