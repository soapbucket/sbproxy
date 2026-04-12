// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// UpstreamOAuthConfig configures OAuth2 client credentials for upstream authentication.
type UpstreamOAuthConfig struct {
	TokenURL     string   `json:"token_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes,omitempty"`
	HeaderName   string   `json:"header_name,omitempty"`   // Default: "Authorization"
	HeaderPrefix string   `json:"header_prefix,omitempty"` // Default: "Bearer "
}

// UpstreamOAuth wraps an http.RoundTripper and injects OAuth2 bearer tokens
// acquired via client_credentials grant into upstream requests.
type UpstreamOAuth struct {
	config    UpstreamOAuthConfig
	transport http.RoundTripper
	client    *http.Client

	mu          sync.RWMutex
	cachedToken string
	tokenExpiry time.Time
}

// oauthTokenResponse represents the JSON response from an OAuth2 token endpoint.
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// tokenExpiryBuffer is how far in advance of actual expiry we refresh the token.
const tokenExpiryBuffer = 30 * time.Second

// NewUpstreamOAuth creates a new UpstreamOAuth transport wrapper.
// If transport is nil, http.DefaultTransport is used for upstream requests.
// The token endpoint is called using a separate http.Client with a 10s timeout.
func NewUpstreamOAuth(config UpstreamOAuthConfig, transport http.RoundTripper) *UpstreamOAuth {
	if transport == nil {
		transport = http.DefaultTransport
	}
	if config.HeaderName == "" {
		config.HeaderName = "Authorization"
	}
	if config.HeaderPrefix == "" {
		config.HeaderPrefix = "Bearer "
	}
	return &UpstreamOAuth{
		config:    config,
		transport: transport,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// RoundTrip implements http.RoundTripper. It acquires a valid OAuth2 token
// and injects it into the request before forwarding to the underlying transport.
func (u *UpstreamOAuth) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := u.getToken()
	if err != nil {
		return nil, fmt.Errorf("upstream oauth: %w", err)
	}

	// Clone the request to avoid mutating the caller's request.
	cloned := req.Clone(req.Context())
	cloned.Header.Set(u.config.HeaderName, u.config.HeaderPrefix+token)

	return u.transport.RoundTrip(cloned)
}

// getToken returns a cached token or fetches a new one if expired.
func (u *UpstreamOAuth) getToken() (string, error) {
	u.mu.RLock()
	if u.cachedToken != "" && time.Now().Before(u.tokenExpiry) {
		token := u.cachedToken
		u.mu.RUnlock()
		return token, nil
	}
	u.mu.RUnlock()

	u.mu.Lock()
	defer u.mu.Unlock()

	// Double-check after acquiring write lock.
	if u.cachedToken != "" && time.Now().Before(u.tokenExpiry) {
		return u.cachedToken, nil
	}

	resp, err := u.fetchToken()
	if err != nil {
		return "", err
	}

	u.cachedToken = resp.AccessToken
	u.tokenExpiry = time.Now().Add(time.Duration(resp.ExpiresIn)*time.Second - tokenExpiryBuffer)

	return u.cachedToken, nil
}

// fetchToken performs the HTTP POST to the token endpoint using the client_credentials grant.
func (u *UpstreamOAuth) fetchToken() (*oauthTokenResponse, error) {
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {u.config.ClientID},
		"client_secret": {u.config.ClientSecret},
	}
	if len(u.config.Scopes) > 0 {
		data.Set("scope", strings.Join(u.config.Scopes, " "))
	}

	resp, err := u.client.Post(u.config.TokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned empty access_token")
	}

	return &tokenResp, nil
}
