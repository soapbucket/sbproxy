// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

const (
	// DefaultIntrospectionCacheDuration is the default cache TTL for introspection results.
	DefaultIntrospectionCacheDuration = 60 * time.Second
	// DefaultIntrospectionTimeout is the default HTTP timeout for introspection requests.
	DefaultIntrospectionTimeout = 5 * time.Second
	// DefaultIntrospectionHeaderName is the default header to extract the token from.
	DefaultIntrospectionHeaderName = "Authorization"
	// DefaultIntrospectionHeaderPrefix is the default prefix to strip from the token header.
	DefaultIntrospectionHeaderPrefix = "Bearer "
)

func init() {
	authLoaderFuns[AuthTypeOAuthIntrospection] = NewOAuthIntrospectionConfig
}

// OAuthTokenIntrospectionConfig holds configuration for OAuth 2.0 token introspection (RFC 7662).
type OAuthTokenIntrospectionConfig struct {
	BaseAuthConfig

	IntrospectionURL string          `json:"introspection_url"`
	ClientID         string          `json:"client_id" secret:"true"`
	ClientSecret     string          `json:"client_secret" secret:"true"`
	CacheDuration    reqctx.Duration `json:"cache_duration,omitempty"`
	Timeout          reqctx.Duration `json:"timeout,omitempty"`
	RequiredScopes   []string        `json:"required_scopes,omitempty"`
	RequiredAudience string          `json:"required_audience,omitempty"`
	TokenHeaderName  string          `json:"token_header_name,omitempty"`
	TokenHeaderPrefix string         `json:"token_header_prefix,omitempty"`
}

// introspectionResult holds a cached introspection response.
type introspectionResult struct {
	response  *introspectionResponse
	expiresAt time.Time
}

// introspectionResponse represents the RFC 7662 token introspection response.
type introspectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

// OAuthIntrospectionImpl implements AuthConfig for OAuth 2.0 token introspection.
type OAuthIntrospectionImpl struct {
	OAuthTokenIntrospectionConfig

	client *http.Client
	cache  map[string]*introspectionResult
	mu     sync.RWMutex
}

// NewOAuthIntrospectionConfig creates and initializes a new OAuthIntrospectionImpl.
func NewOAuthIntrospectionConfig(data []byte) (AuthConfig, error) {
	cfg := &OAuthIntrospectionImpl{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.IntrospectionURL == "" {
		return nil, fmt.Errorf("oauth_introspection: introspection_url is required")
	}

	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oauth_introspection: client_id is required")
	}

	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("oauth_introspection: client_secret is required")
	}

	// Apply defaults
	if cfg.TokenHeaderName == "" {
		cfg.TokenHeaderName = DefaultIntrospectionHeaderName
	}
	if cfg.TokenHeaderPrefix == "" {
		cfg.TokenHeaderPrefix = DefaultIntrospectionHeaderPrefix
	}

	timeout := DefaultIntrospectionTimeout
	if cfg.Timeout.Duration > 0 {
		timeout = cfg.Timeout.Duration
	}
	cfg.client = &http.Client{Timeout: timeout}
	cfg.cache = make(map[string]*introspectionResult)

	return cfg, nil
}

// Authenticate validates incoming requests by introspecting their bearer tokens
// against the configured OAuth 2.0 introspection endpoint (RFC 7662).
func (c *OAuthIntrospectionImpl) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := c.extractToken(r)
		if token == "" {
			slog.Debug("oauth_introspection: no token provided")
			c.recordFailure(r, "token_missing")
			reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Bearer token required")
			http.Error(w, "Unauthorized: Bearer token required", http.StatusUnauthorized)
			return
		}

		// Check cache first
		tokenHash := hashToken(token)
		resp, cached := c.getCachedResult(tokenHash)

		if !cached {
			var err error
			resp, err = c.introspect(r, token)
			if err != nil {
				slog.Error("oauth_introspection: introspection request failed", "error", err)
				c.recordFailure(r, "introspection_error")
				reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Token introspection failed")
				http.Error(w, "Unauthorized: Token introspection failed", http.StatusUnauthorized)
				return
			}
			c.setCachedResult(tokenHash, resp)
		}

		// Validate the introspection response
		if !resp.Active {
			slog.Debug("oauth_introspection: token is not active")
			c.recordFailure(r, "token_inactive")
			reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Token is not active")
			http.Error(w, "Unauthorized: Token is not active", http.StatusUnauthorized)
			return
		}

		// Check token expiration
		if resp.Exp > 0 && time.Now().Unix() >= resp.Exp {
			slog.Debug("oauth_introspection: token is expired")
			c.invalidateCache(tokenHash)
			c.recordFailure(r, "token_expired")
			reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Token is expired")
			http.Error(w, "Unauthorized: Token is expired", http.StatusUnauthorized)
			return
		}

		// Validate required scopes
		if len(c.RequiredScopes) > 0 {
			tokenScopes := parseScopes(resp.Scope)
			for _, required := range c.RequiredScopes {
				if !containsScope(tokenScopes, required) {
					slog.Debug("oauth_introspection: missing required scope", "required", required, "token_scopes", resp.Scope)
					c.recordFailure(r, "scope_missing")
					reqctx.RecordPolicyViolation(r.Context(), "auth", "Forbidden: Insufficient scope")
					http.Error(w, "Forbidden: Insufficient scope", http.StatusForbidden)
					return
				}
			}
		}

		// Validate required audience
		if c.RequiredAudience != "" && resp.Aud != c.RequiredAudience {
			slog.Debug("oauth_introspection: audience mismatch", "required", c.RequiredAudience, "got", resp.Aud)
			c.recordFailure(r, "audience_mismatch")
			reqctx.RecordPolicyViolation(r.Context(), "auth", "Forbidden: Invalid audience")
			http.Error(w, "Forbidden: Invalid audience", http.StatusForbidden)
			return
		}

		// Set upstream headers with token claims
		r.Header.Set("X-Auth-Subject", resp.Sub)
		r.Header.Set("X-Auth-Client-ID", resp.ClientID)
		if resp.Scope != "" {
			r.Header.Set("X-Auth-Scopes", resp.Scope)
		}
		if resp.Username != "" {
			r.Header.Set("X-Auth-Username", resp.Username)
		}

		// Store auth data in RequestData
		requestData := reqctx.GetRequestData(r.Context())
		if requestData != nil {
			if requestData.SessionData == nil {
				requestData.SessionData = &reqctx.SessionData{}
			}
			requestData.SessionData.AuthData = &reqctx.AuthData{
				Type: AuthTypeOAuthIntrospection,
				Data: map[string]any{
					"sub":       resp.Sub,
					"client_id": resp.ClientID,
					"scope":     resp.Scope,
					"username":  resp.Username,
					"aud":       resp.Aud,
					"iss":       resp.Iss,
				},
			}
			*r = *r.WithContext(reqctx.SetRequestData(r.Context(), requestData))
		}

		ipAddress := extractIntrospectionIP(r)
		logging.LogAuthenticationAttempt(r.Context(), true, "oauth_introspection", resp.Sub, ipAddress, "")

		next.ServeHTTP(w, r)
	})
}

// extractToken extracts the bearer token from the configured header.
func (c *OAuthIntrospectionImpl) extractToken(r *http.Request) string {
	header := r.Header.Get(c.TokenHeaderName)
	if header == "" {
		return ""
	}
	if c.TokenHeaderPrefix != "" && strings.HasPrefix(header, c.TokenHeaderPrefix) {
		return strings.TrimPrefix(header, c.TokenHeaderPrefix)
	}
	return header
}

// introspect calls the token introspection endpoint per RFC 7662.
func (c *OAuthIntrospectionImpl) introspect(r *http.Request, token string) (*introspectionResponse, error) {
	form := url.Values{}
	form.Set("token", token)

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, c.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ClientID, c.ClientSecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("introspection endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var result introspectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	return &result, nil
}

// getCachedResult returns a cached introspection result if it exists and has not expired.
func (c *OAuthIntrospectionImpl) getCachedResult(tokenHash string) (*introspectionResponse, bool) {
	cacheDuration := DefaultIntrospectionCacheDuration
	if c.CacheDuration.Duration > 0 {
		cacheDuration = c.CacheDuration.Duration
	}
	// If cache duration is explicitly set to a negative value, caching is disabled
	if cacheDuration <= 0 {
		return nil, false
	}

	c.mu.RLock()
	result, ok := c.cache[tokenHash]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if time.Now().After(result.expiresAt) {
		c.invalidateCache(tokenHash)
		return nil, false
	}
	return result.response, true
}

// setCachedResult stores an introspection result in the cache.
func (c *OAuthIntrospectionImpl) setCachedResult(tokenHash string, resp *introspectionResponse) {
	cacheDuration := DefaultIntrospectionCacheDuration
	if c.CacheDuration.Duration > 0 {
		cacheDuration = c.CacheDuration.Duration
	}
	if cacheDuration <= 0 {
		return
	}

	c.mu.Lock()
	c.cache[tokenHash] = &introspectionResult{
		response:  resp,
		expiresAt: time.Now().Add(cacheDuration),
	}
	c.mu.Unlock()
}

// invalidateCache removes a cached introspection result.
func (c *OAuthIntrospectionImpl) invalidateCache(tokenHash string) {
	c.mu.Lock()
	delete(c.cache, tokenHash)
	c.mu.Unlock()
}

// recordFailure records an authentication failure via metrics and logging.
func (c *OAuthIntrospectionImpl) recordFailure(r *http.Request, reason string) {
	origin := "unknown"
	if c.cfg != nil {
		origin = c.cfg.ID
	}
	ipAddress := extractIntrospectionIP(r)
	metric.AuthFailure(origin, "oauth_introspection", reason, ipAddress)
	logging.LogAuthenticationAttempt(r.Context(), false, "oauth_introspection", "", ipAddress, reason)
	emitSecurityAuthFailure(r.Context(), c.cfg, r, "oauth_introspection", reason)
}

// hashToken creates a SHA-256 hash of the token for use as a cache key.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// parseScopes splits a space-delimited scope string into individual scopes.
func parseScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

// containsScope checks if the given scope is present in the scopes list.
func containsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// extractIntrospectionIP extracts the client IP address from the request.
func extractIntrospectionIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return r.RemoteAddr
}
