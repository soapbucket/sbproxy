// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

const (
	// Default bearer token settings
	DefaultBearerTokenHeaderName   = "Authorization"
	// DefaultBearerTokenHeaderPrefix is the default value for bearer token header prefix.
	DefaultBearerTokenHeaderPrefix = "Bearer "
)

type bearerTokens struct {
	tokens  []string
	expires time.Time
}

// IsExpired reports whether the bearerTokens is expired.
func (b bearerTokens) IsExpired() bool {
	return b.expires.Before(time.Now())
}

func init() {
	authLoaderFuns[AuthTypeBearerToken] = NewBearerTokenAuthConfig
}

// BearerTokenAuthConfig holds configuration for bearer token auth.
type BearerTokenAuthConfig struct {
	BearerTokenConfig

	HeaderName   string `json:"header_name,omitempty"`   // Header to extract token from (default: Authorization)
	HeaderPrefix string `json:"header_prefix,omitempty"` // Prefix to strip (default: "Bearer ")
	CookieName   string `json:"cookie_name,omitempty"`   // Alternative: extract from cookie
	QueryParam   string `json:"query_param,omitempty"`   // Alternative: extract from query param

	tokenMap  map[string]bool // Fast O(1) lookup for static tokens
	mapTokens map[string]bearerTokens
	mx        sync.RWMutex
}

func (c *BearerTokenAuthConfig) getTokens(ctx context.Context) ([]string, error) {
	if c.TokensCallback == nil {
		return nil, nil
	}

	key := c.TokensCallback.GetCacheKey()

	if c.TokensCallback.CacheDuration.Duration > 0 {
		c.mx.RLock()
		tokens, ok := c.mapTokens[key]
		c.mx.RUnlock()
		if ok && !tokens.IsExpired() {
			return tokens.tokens, nil
		}
	}

	result, err := c.TokensCallback.Do(ctx, map[string]any{})
	if err != nil {
		return nil, err
	}

	rtokens, ok := result["tokens"]
	if ok {
		switch v := rtokens.(type) {
		case []string:
			if c.TokensCallback.CacheDuration.Duration > 0 {
				c.mx.Lock()
				c.mapTokens[key] = bearerTokens{
					tokens:  v,
					expires: time.Now().Add(c.TokensCallback.CacheDuration.Duration),
				}
				c.mx.Unlock()
			}
			return v, nil
		case []interface{}:
			// Handle generic array conversion
			tokens := make([]string, 0, len(v))
			for _, item := range v {
				if str, ok := item.(string); ok {
					tokens = append(tokens, str)
				}
			}
			if c.TokensCallback.CacheDuration.Duration > 0 {
				c.mx.Lock()
				c.mapTokens[key] = bearerTokens{
					tokens:  tokens,
					expires: time.Now().Add(c.TokensCallback.CacheDuration.Duration),
				}
				c.mx.Unlock()
			}
			return tokens, nil
		}
	}
	return nil, nil
}

func (c *BearerTokenAuthConfig) extractToken(r *http.Request) string {
	// Try header first
	headerName := c.HeaderName
	if headerName == "" {
		headerName = DefaultBearerTokenHeaderName
	}

	if header := r.Header.Get(headerName); header != "" {
		// Strip prefix if configured
		prefix := c.HeaderPrefix
		if prefix == "" {
			prefix = DefaultBearerTokenHeaderPrefix
		}
		if strings.HasPrefix(header, prefix) {
			return strings.TrimPrefix(header, prefix)
		}
		return header
	}

	// Try cookie
	if c.CookieName != "" {
		cookie, err := r.Cookie(c.CookieName)
		if err == nil && cookie.Value != "" {
			return cookie.Value
		}
	}

	// Try query parameter
	if c.QueryParam != "" {
		if token := r.URL.Query().Get(c.QueryParam); token != "" {
			return token
		}
	}

	// WebSocket browser clients may carry credentials in subprotocols.
	if token := extractOpenAIKeyFromSubprotocols(r); token != "" {
		return token
	}

	return ""
}

// Authenticate performs the authenticate operation on the BearerTokenAuthConfig.
func (c *BearerTokenAuthConfig) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract bearer token from request
		token := c.extractToken(r)
		if token == "" {
			slog.Debug("bearer token: no token provided")
			// Record authentication failure metric
			origin := "unknown"
			if c.cfg != nil {
				origin = c.cfg.ID
			}
			ipAddress := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ipAddress = strings.Split(forwarded, ",")[0]
			}
			metric.AuthFailure(origin, "bearer", "token_missing", ipAddress)
			reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Bearer token required")
			http.Error(w, "Unauthorized: Bearer token required", http.StatusUnauthorized)
			return
		}

		// Check static tokens with constant-time comparison to prevent timing attacks
		// Note: We iterate through all tokens instead of using map lookup for constant-time security
		tokenValid := false
		for _, t := range c.Tokens {
			// Use constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
				tokenValid = true
				// Don't break early - continue checking all tokens for constant-time
			}
		}

		if tokenValid {
			slog.Debug("bearer token: authentication successful")

			// Call authentication callback if provided
			if c.AuthenticationCallback != nil {
				params := map[string]any{
					"token": token,
				}
				result, err := c.AuthenticationCallback.Do(r.Context(), params)
				if err != nil {
					slog.Error("bearer token: authentication callback failed", "error", err)
					http.Error(w, "authentication callback failed", http.StatusInternalServerError)
					return
				}
				// Store auth callback results in RequestData.SessionData.AuthData.Data
				// This allows {{auth_data.*}} template variables to access auth callback data
				requestData := reqctx.GetRequestData(r.Context())
				if requestData != nil {
					// Ensure SessionData exists
					if requestData.SessionData == nil {
						requestData.SessionData = &reqctx.SessionData{}
					}
					// Ensure AuthData exists
					if requestData.SessionData.AuthData == nil {
						requestData.SessionData.AuthData = &reqctx.AuthData{
							Type: "bearer_token",
						}
					}
					// Store auth data in SessionData.AuthData.Data
					// Callback.Do returns map[string]any, so we can directly assign it
					requestData.SessionData.AuthData.Data = result
					// Update request context with modified RequestData
					*r = *r.WithContext(reqctx.SetRequestData(r.Context(), requestData))
				}
			}

			next.ServeHTTP(w, r)
			return
		}

		// Check dynamic tokens from callback if static lookup fails
		dynamicTokens, err := c.getTokens(r.Context())
		if err != nil {
			slog.Error("bearer token: failed to get dynamic tokens", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check dynamic tokens with constant-time comparison
		dynamicTokenValid := false
		for _, t := range dynamicTokens {
			// Use constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
				dynamicTokenValid = true
				// Don't break early - continue checking all tokens for constant-time
			}
		}

		if dynamicTokenValid {
			slog.Debug("bearer token: authentication successful (dynamic)")

			// Call authentication callback if provided
			if c.AuthenticationCallback != nil {
				params := map[string]any{
					"token": token,
				}
				result, err := c.AuthenticationCallback.Do(r.Context(), params)
				if err != nil {
					slog.Error("bearer token: authentication callback failed", "error", err)
					http.Error(w, "authentication callback failed", http.StatusInternalServerError)
					return
				}
				// Store auth callback results in RequestData.SessionData.AuthData.Data
				// This allows {{auth_data.*}} template variables to access auth callback data
				requestData := reqctx.GetRequestData(r.Context())
				if requestData != nil {
					// Ensure SessionData exists
					if requestData.SessionData == nil {
						requestData.SessionData = &reqctx.SessionData{}
					}
					// Ensure AuthData exists
					if requestData.SessionData.AuthData == nil {
						requestData.SessionData.AuthData = &reqctx.AuthData{
							Type: "bearer_token",
						}
					}
					// Store auth data in SessionData.AuthData.Data
					// Callback.Do returns map[string]any, so we can directly assign it
					requestData.SessionData.AuthData.Data = result
					// Update request context with modified RequestData
					*r = *r.WithContext(reqctx.SetRequestData(r.Context(), requestData))
				}
			}

			next.ServeHTTP(w, r)
			return
		}

		slog.Debug("bearer token: invalid token")
		// Record authentication failure metric
		origin := "unknown"
		requestData := reqctx.GetRequestData(r.Context())
		if requestData != nil && requestData.Config != nil {
			if id, ok := requestData.Config["config_id"].(string); ok {
				origin = id
			}
		}
		ipAddress := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ipAddress = strings.Split(forwarded, ",")[0]
		}
		metric.AuthFailure(origin, "bearer", "token_invalid", ipAddress)
		reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Invalid bearer token")
		http.Error(w, "Unauthorized: Invalid bearer token", http.StatusUnauthorized)
	})
}

// NewBearerTokenAuthConfig creates and initializes a new BearerTokenAuthConfig.
func NewBearerTokenAuthConfig(data []byte) (AuthConfig, error) {
	config := &BearerTokenAuthConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Build index for O(1) lookups
	config.tokenMap = make(map[string]bool, len(config.Tokens))
	for _, token := range config.Tokens {
		config.tokenMap[token] = true
	}

	config.mapTokens = make(map[string]bearerTokens)
	config.mx = sync.RWMutex{}

	// Set defaults
	if config.HeaderName == "" {
		config.HeaderName = DefaultBearerTokenHeaderName
	}
	if config.HeaderPrefix == "" {
		config.HeaderPrefix = DefaultBearerTokenHeaderPrefix
	}

	return config, nil
}

