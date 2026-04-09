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
	// DefaultClientCredentialsTimeout is the default HTTP timeout for token requests.
	DefaultClientCredentialsTimeout = 5 * time.Second
	// DefaultClientCredentialsHeaderName is the default header to extract credentials from.
	DefaultClientCredentialsHeaderName = "Authorization"
	// DefaultClientCredentialsHeaderPrefix is the default prefix for injected upstream token.
	DefaultClientCredentialsHeaderPrefix = "Bearer "
)

func init() {
	authLoaderFuns[AuthTypeOAuthClientCredentials] = NewOAuthClientCredentialsConfig
}

// OAuthClientCredentialsConfig holds configuration for OAuth 2.0 Client Credentials Grant authentication.
// Incoming requests provide client_id and client_secret via HTTP Basic auth. The gateway exchanges
// those credentials at the token_url for an access token, validates scopes, and injects the token
// as an upstream header.
type OAuthClientCredentialsConfig struct {
	BaseAuthConfig

	TokenURL       string          `json:"token_url"`
	ClientID       string          `json:"client_id,omitempty" secret:"true"`       // Gateway-level client_id (optional, for static credential mode)
	ClientSecret   string          `json:"client_secret,omitempty" secret:"true"`   // Gateway-level client_secret (optional, for static credential mode)
	Scopes         []string        `json:"scopes,omitempty"`                        // Scopes to request in the token exchange
	RequiredScopes []string        `json:"required_scopes,omitempty"`               // Scopes the resulting token must have
	CacheDuration  reqctx.Duration `json:"cache_duration,omitempty"`                // Cache token TTL; 0 means use expires_in from response
	Timeout        reqctx.Duration `json:"timeout,omitempty"`                       // HTTP timeout for token requests (default 5s)
	HeaderName     string          `json:"header_name,omitempty"`                   // Upstream header name (default: Authorization)
	HeaderPrefix   string          `json:"header_prefix,omitempty"`                 // Upstream header prefix (default: "Bearer ")
}

// clientCredentialsTokenResponse represents the OAuth 2.0 token endpoint response.
type clientCredentialsTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// cachedClientCredentialsToken holds a cached token with its expiry time.
type cachedClientCredentialsToken struct {
	response  *clientCredentialsTokenResponse
	expiresAt time.Time
}

// OAuthClientCredentialsImpl implements AuthConfig for OAuth 2.0 Client Credentials Grant.
type OAuthClientCredentialsImpl struct {
	OAuthClientCredentialsConfig

	client *http.Client
	cache  map[string]*cachedClientCredentialsToken
	mu     sync.RWMutex
}

// NewOAuthClientCredentialsConfig creates and initializes a new OAuthClientCredentialsImpl.
func NewOAuthClientCredentialsConfig(data []byte) (AuthConfig, error) {
	cfg := &OAuthClientCredentialsImpl{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.TokenURL == "" {
		return nil, fmt.Errorf("oauth_client_credentials: token_url is required")
	}

	// Apply defaults
	if cfg.HeaderName == "" {
		cfg.HeaderName = DefaultClientCredentialsHeaderName
	}
	if cfg.HeaderPrefix == "" {
		cfg.HeaderPrefix = DefaultClientCredentialsHeaderPrefix
	}

	timeout := DefaultClientCredentialsTimeout
	if cfg.Timeout.Duration > 0 {
		timeout = cfg.Timeout.Duration
	}
	cfg.client = &http.Client{Timeout: timeout}
	cfg.cache = make(map[string]*cachedClientCredentialsToken)

	return cfg, nil
}

// Authenticate validates incoming requests by extracting Basic auth credentials,
// exchanging them at the token_url via the client_credentials grant, validating
// the returned scopes, and injecting the access token as an upstream header.
func (c *OAuthClientCredentialsImpl) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok || clientID == "" || clientSecret == "" {
			slog.Debug("oauth_client_credentials: no Basic auth credentials provided")
			c.recordFailure(r, "credentials_missing")
			reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Basic auth credentials required")
			http.Error(w, "Unauthorized: Basic auth credentials required", http.StatusUnauthorized)
			return
		}

		// Check cache first
		cacheKey := hashClientCredentials(clientID, clientSecret)
		tokenResp, cached := c.getCachedToken(cacheKey)

		if !cached {
			var err error
			tokenResp, err = c.exchangeCredentials(r, clientID, clientSecret)
			if err != nil {
				slog.Error("oauth_client_credentials: token exchange failed", "error", err)
				c.recordFailure(r, "token_exchange_error")
				reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Token exchange failed")
				http.Error(w, "Unauthorized: Token exchange failed", http.StatusUnauthorized)
				return
			}
			c.setCachedToken(cacheKey, tokenResp)
		}

		// Validate required scopes
		if len(c.RequiredScopes) > 0 {
			tokenScopes := parseScopes(tokenResp.Scope)
			for _, required := range c.RequiredScopes {
				if !containsScope(tokenScopes, required) {
					slog.Debug("oauth_client_credentials: missing required scope", "required", required, "token_scopes", tokenResp.Scope)
					c.recordFailure(r, "scope_missing")
					reqctx.RecordPolicyViolation(r.Context(), "auth", "Forbidden: Insufficient scope")
					http.Error(w, "Forbidden: Insufficient scope", http.StatusForbidden)
					return
				}
			}
		}

		// Inject obtained access token as upstream header
		r.Header.Set(c.HeaderName, c.HeaderPrefix+tokenResp.AccessToken)

		// Set upstream metadata headers
		r.Header.Set("X-Auth-Client-ID", clientID)
		if tokenResp.Scope != "" {
			r.Header.Set("X-Auth-Scopes", tokenResp.Scope)
		}

		// Store auth data in RequestData
		requestData := reqctx.GetRequestData(r.Context())
		if requestData != nil {
			if requestData.SessionData == nil {
				requestData.SessionData = &reqctx.SessionData{}
			}
			requestData.SessionData.AuthData = &reqctx.AuthData{
				Type: AuthTypeOAuthClientCredentials,
				Data: map[string]any{
					"client_id": clientID,
					"scope":     tokenResp.Scope,
				},
			}
			*r = *r.WithContext(reqctx.SetRequestData(r.Context(), requestData))
		}

		ipAddress := clientCredentialsExtractIP(r)
		logging.LogAuthenticationAttempt(r.Context(), true, "oauth_client_credentials", clientID, ipAddress, "")

		next.ServeHTTP(w, r)
	})
}

// exchangeCredentials performs the client_credentials grant token exchange.
func (c *OAuthClientCredentialsImpl) exchangeCredentials(r *http.Request, clientID, clientSecret string) (*clientCredentialsTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if len(c.Scopes) > 0 {
		form.Set("scope", strings.Join(c.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var result clientCredentialsTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if result.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned empty access_token")
	}

	return &result, nil
}

// getCachedToken returns a cached token if it exists and has not expired.
func (c *OAuthClientCredentialsImpl) getCachedToken(cacheKey string) (*clientCredentialsTokenResponse, bool) {
	c.mu.RLock()
	entry, ok := c.cache[cacheKey]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		c.invalidateCachedToken(cacheKey)
		return nil, false
	}
	return entry.response, true
}

// setCachedToken stores a token in the cache with an appropriate TTL.
func (c *OAuthClientCredentialsImpl) setCachedToken(cacheKey string, resp *clientCredentialsTokenResponse) {
	var ttl time.Duration
	if c.CacheDuration.Duration > 0 {
		ttl = c.CacheDuration.Duration
	} else if resp.ExpiresIn > 0 {
		// Use expires_in from the response, with a 10-second safety margin
		ttl = time.Duration(resp.ExpiresIn)*time.Second - 10*time.Second
		if ttl <= 0 {
			return
		}
	} else {
		// No cache duration configured and no expires_in in response; do not cache
		return
	}

	c.mu.Lock()
	c.cache[cacheKey] = &cachedClientCredentialsToken{
		response:  resp,
		expiresAt: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}

// invalidateCachedToken removes a cached token entry.
func (c *OAuthClientCredentialsImpl) invalidateCachedToken(cacheKey string) {
	c.mu.Lock()
	delete(c.cache, cacheKey)
	c.mu.Unlock()
}

// recordFailure records an authentication failure via metrics and logging.
func (c *OAuthClientCredentialsImpl) recordFailure(r *http.Request, reason string) {
	origin := "unknown"
	if c.cfg != nil {
		origin = c.cfg.ID
	}
	ipAddress := clientCredentialsExtractIP(r)
	metric.AuthFailure(origin, "oauth_client_credentials", reason, ipAddress)
	logging.LogAuthenticationAttempt(r.Context(), false, "oauth_client_credentials", "", ipAddress, reason)
	emitSecurityAuthFailure(r.Context(), c.cfg, r, "oauth_client_credentials", reason)
}

// hashClientCredentials creates a SHA-256 hash of the client credentials for use as a cache key.
func hashClientCredentials(clientID, clientSecret string) string {
	h := sha256.Sum256([]byte(clientID + ":" + clientSecret))
	return hex.EncodeToString(h[:])
}

// clientCredentialsExtractIP extracts the client IP address from the request.
func clientCredentialsExtractIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return r.RemoteAddr
}
