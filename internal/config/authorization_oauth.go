// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"golang.org/x/oauth2"
)

const (
	// Default OAuth paths
	DefaultOAuthCallbackPath = "/oauth/callback"
	// DefaultOAuthLoginPath is the default value for o auth login path.
	DefaultOAuthLoginPath    = "/oauth/login"
	// DefaultOAuthLogoutPath is the default value for o auth logout path.
	DefaultOAuthLogoutPath   = "/oauth/logout"

	// State parameter length in bytes (32 bytes = 256 bits)
	stateParameterLength = 32
)

var (
	// ErrNoAuthData is a sentinel error for no auth data conditions.
	ErrNoAuthData                   = errors.New("config: no auth data found")
	// ErrOAuthServiceUnavailable is a sentinel error for o auth service unavailable conditions.
	ErrOAuthServiceUnavailable      = errors.New("config: oauth service unavailable")
	// ErrInvalidStateParameter is a sentinel error for invalid state parameter conditions.
	ErrInvalidStateParameter        = errors.New("config: oauth invalid state parameter")
	// ErrTokenExchangeFailed is a sentinel error for token exchange failed conditions.
	ErrTokenExchangeFailed          = errors.New("config: oauth token exchange failed")
	// ErrUserInfoFailed is a sentinel error for user info failed conditions.
	ErrUserInfoFailed               = errors.New("config: oauth user info failed")
	// ErrAuthenticationCallbackFailed is a sentinel error for authentication callback failed conditions.
	ErrAuthenticationCallbackFailed = errors.New("config: oauth authentication callback failed")
	// ErrLogoutCallbackFailed is a sentinel error for logout callback failed conditions.
	ErrLogoutCallbackFailed         = errors.New("config: oauth logout callback failed")
	// ErrStateGenerationFailed is a sentinel error for state generation failed conditions.
	ErrStateGenerationFailed        = errors.New("config: oauth failed to generate state")
)

func init() {
	authLoaderFuns[AuthTypeOAuth] = NewOAuthConfig
}

// NewOAuthConfig creates and initializes a new OAuthConfig.
func NewOAuthConfig(data []byte) (AuthConfig, error) {
	cfg := new(OAuthAuthConfig)
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Apply provider/OIDC defaults when any discovery source is available:
	// a provider name, an explicit issuer, or a discovery URL.
	if cfg.Provider != "" || cfg.Issuer != "" || cfg.DiscoveryURL != "" {
		substitutions := cfg.TenantSubstitutions
		if substitutions == nil && cfg.Tenant != "" {
			// Convenience: if tenant is specified but no substitutions, use it as "tenant"
			substitutions = map[string]string{"tenant": cfg.Tenant}
		}
		if err := ApplyProviderDefaults(&cfg.OAuthConfig, substitutions); err != nil {
			return nil, fmt.Errorf("failed to apply provider/OIDC defaults: %w", err)
		}
	}

	oauth2Config, err := createOAuth2Config(cfg)
	if err != nil {
		return nil, err
	}
	cfg.oauth2Config = oauth2Config
	return cfg, nil
}

// OAuthAuthConfig holds configuration for o auth auth.
type OAuthAuthConfig struct {
	OAuthConfig

	oauth2Config *oauth2.Config
}

// Init performs the init operation on the OAuthAuthConfig.
func (c *OAuthAuthConfig) Init(config *Config) error {
	c.BaseAuthConfig.Init(config)
	if c.AuthenticationCallback != nil && c.AuthenticationCallback.VariableName == "" {
		c.AuthenticationCallback.VariableName = "auth"
	}
	if c.LogoutCallback != nil && c.LogoutCallback.VariableName == "" {
		c.LogoutCallback.VariableName = "auth"
	}
	return nil
}

// Authenticate performs the authenticate operation on the OAuthAuthConfig.
func (c *OAuthAuthConfig) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("authenticating request", "request", r.URL.String())

		if c.Disabled {
			httputil.HandleError(http.StatusServiceUnavailable, ErrOAuthServiceUnavailable, w, r)
			return
		}

		// Check for OAuth callback
		if r.URL.Path == c.getCallbackPath() {
			c.callback(w, r)
			return
		}

		// Check for OAuth login
		if r.URL.Path == c.getLoginPath() {
			c.login(w, r)
			return
		}

		// Check for OAuth logout
		if r.URL.Path == c.getLogoutPath() {
			c.logout(w, r)
			return
		}

		data, err := c.getAuthData(r)

		// If no valid session and authentication is required (either force or default behavior)
		// Redirect to login for unauthenticated requests
		if err != nil || data == nil {
			// For OAuth, always redirect unauthenticated requests to login
			// unless explicitly disabled
			if !c.Disabled {
				slog.Debug("no valid session, redirecting to login", "request", r.URL.String())
				c.redirectToLogin(w, r)
				return
			}
		}

		// NOTE: Role checking is now handled via request rules (CEL/Lua expressions)
		// Auth data is available in session.auth for use in rules.
		// See docs/OAUTH_ROLE_CHECKING_PROPOSAL.md for implementation examples.
		if data != nil {
			// Auth data is now stored in session and accessible via:
			// - CEL: session['auth']['roles'], session['auth']['permissions'], etc.
			// - Lua: session.auth.roles, session.auth.permissions, etc.
			// Rules can check roles, permissions, groups, workspace_id, or any custom auth data.
		}

		// Add user to context
		slog.Debug("oauth user", "data", data)
		next.ServeHTTP(w, r)
	})
}

//// private methods

func (c *OAuthAuthConfig) callAuthenticationCallback(ctx context.Context, data *reqctx.AuthData) error {
	cb := c.AuthenticationCallback
	if cb == nil {
		return nil
	}

	result, err := cb.Do(ctx, data.Data)
	if err != nil {
		return err
	}
	maps.Copy(data.Data, result)

	return nil
}

func (c *OAuthAuthConfig) callLogoutCallback(ctx context.Context, data *reqctx.AuthData) error {
	cb := c.LogoutCallback
	if cb == nil {
		return nil
	}

	_, err := cb.Do(ctx, data.Data)
	if err != nil {
		return err
	}

	return nil
}

func (c *OAuthAuthConfig) getAuthData(r *http.Request) (*reqctx.AuthData, error) {
	// Get auth data from RequestData.SessionData.AuthData
	// This is stored by the OAuth callback and saved by the session middleware
	requestData := reqctx.GetRequestData(r.Context())
	if requestData == nil || requestData.SessionData == nil || requestData.SessionData.AuthData == nil {
		return nil, ErrNoAuthData
	}
	return requestData.SessionData.AuthData, nil
}

func (c *OAuthAuthConfig) deleteAuthData(r *http.Request, data *reqctx.AuthData) error {
	// Clear auth data from RequestData.SessionData.AuthData
	// The session middleware will save the updated session (without auth data) to Redis
	requestData := reqctx.GetRequestData(r.Context())
	if requestData != nil && requestData.SessionData != nil {
		requestData.SessionData.AuthData = nil
		// Update request context with modified RequestData
		*r = *r.WithContext(reqctx.SetRequestData(r.Context(), requestData))
	}
	return nil
}

func (c *OAuthAuthConfig) getAuthDataFromToken(ctx context.Context, token *oauth2.Token) (*reqctx.AuthData, error) {
	client := c.oauth2Config.Client(ctx, token)

	data := &reqctx.AuthData{
		Type: AuthTypeOAuth,
		Data: map[string]any{
			"provider": c.Provider,
		},
	}

	results := make(map[string]any)

	// Get userinfo URL from provider config
	var userInfoURL string
	if c.Provider != "" {
		provider, ok := GetProvider(c.Provider)
		if ok && provider.UserInfoURL != "" {
			userInfoURL = provider.UserInfoURL
		}
	}

	// If we have a userinfo URL, fetch user information
	if userInfoURL != "" {
		resp, err := client.Get(userInfoURL)
		if err != nil {
			return nil, fmt.Errorf("failed to get user info: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
		}

		if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
			return nil, fmt.Errorf("failed to decode userinfo: %w", err)
		}
	}

	// Always include token information
	results["access_token"] = token.AccessToken
	if token.RefreshToken != "" {
		results["refresh_token"] = token.RefreshToken
	}
	results["token_type"] = token.TokenType
	results["expiry"] = token.Expiry

	maps.Copy(data.Data, results)

	return data, nil
}

func (c *OAuthAuthConfig) callback(w http.ResponseWriter, r *http.Request) {
	slog.Debug("handling callback", "request", r.URL.String())

	// Verify state parameter using constant-time comparison to prevent timing attacks
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie("oauth_state")
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		httputil.HandleError(http.StatusBadRequest, ErrInvalidStateParameter, w, r)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	// Build token exchange options
	var exchangeOpts []oauth2.AuthCodeOption

	// PKCE: retrieve verifier from cookie and pass to token exchange
	if c.pkceEnabled() {
		verifierCookie, verifierErr := r.Cookie("oauth_pkce_verifier")
		if verifierErr == nil && verifierCookie.Value != "" {
			exchangeOpts = append(exchangeOpts,
				oauth2.SetAuthURLParam("code_verifier", verifierCookie.Value),
			)
		}

		// Clear PKCE verifier cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_pkce_verifier",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
	}

	// Exchange code for token
	code := r.URL.Query().Get("code")
	token, err := c.oauth2Config.Exchange(r.Context(), code, exchangeOpts...)
	if err != nil {
		slog.Error("oauth authentication failed: token exchange",
			"error", err,
			"auth_method", "oauth")
		httputil.HandleError(http.StatusInternalServerError, ErrTokenExchangeFailed, w, r)
		return
	}

	// Get user info
	data, err := c.getAuthDataFromToken(r.Context(), token)
	if err != nil {
		slog.Error("oauth authentication failed: user info retrieval",
			"error", err,
			"auth_method", "oauth")
		httputil.HandleError(http.StatusInternalServerError, ErrUserInfoFailed, w, r)
		return
	}

	// Call authentication callback to get roles
	if err := c.callAuthenticationCallback(r.Context(), data); err != nil {
		slog.Error("failed to call authentication callback", "error", err)
		httputil.HandleError(http.StatusInternalServerError, ErrAuthenticationCallbackFailed, w, r)
		return
	}

	// Store auth data in RequestData.SessionData.AuthData
	// The session middleware will save it to Redis at the end of the request
	requestData := reqctx.GetRequestData(r.Context())
	if requestData != nil {
		// Ensure SessionData exists
		if requestData.SessionData == nil {
			requestData.SessionData = &reqctx.SessionData{}
		}
		// Store auth data in SessionData.AuthData
		requestData.SessionData.AuthData = data
		// Update request context with modified RequestData
		*r = *r.WithContext(reqctx.SetRequestData(r.Context(), requestData))
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)

}

func (c *OAuthAuthConfig) login(w http.ResponseWriter, r *http.Request) {
	slog.Debug("handling login", "request", r.URL.String())

	state, err := generateRandomState()
	if err != nil {
		slog.Error("failed to generate state", "error", err)
		httputil.HandleError(http.StatusInternalServerError, ErrStateGenerationFailed, w, r)
		return
	}

	// Store state in a secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	authOpts := []oauth2.AuthCodeOption{oauth2.AccessTypeOnline}

	// PKCE: generate verifier and challenge, store verifier in cookie
	if c.pkceEnabled() {
		verifier, err := generateCodeVerifier()
		if err != nil {
			slog.Error("failed to generate PKCE code verifier", "error", err)
			httputil.HandleError(http.StatusInternalServerError, ErrStateGenerationFailed, w, r)
			return
		}

		challenge := generateCodeChallenge(verifier)

		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_pkce_verifier",
			Value:    verifier,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   600, // 10 minutes
		})

		authOpts = append(authOpts,
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}

	authURL := c.oauth2Config.AuthCodeURL(state, authOpts...)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (c *OAuthAuthConfig) logout(w http.ResponseWriter, r *http.Request) {
	slog.Debug("handling logout", "request", r.URL.String())
	data, err := c.getAuthData(r)

	// Get current user to extract session ID
	if err == nil && data != nil {
		// Log authentication expired (logout)

		// Call logout callback if enabled
		if err := c.callLogoutCallback(r.Context(), data); err != nil {
			slog.Error("failed to call logout callback", "error", err)
		}

		if err := c.deleteAuthData(r, data); err != nil {
			slog.Error("failed to delete auth data", "error", err)
		}
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (c *OAuthAuthConfig) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	slog.Debug("redirecting to login", "request", r.URL.String())
	loginURL := c.getLoginPath()
	if r.URL.RawQuery != "" {
		loginURL += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (c *OAuthAuthConfig) getLoginPath() string {
	path := c.LoginPath
	if path == "" {
		path = DefaultOAuthLoginPath
	}
	return path
}

func (c *OAuthAuthConfig) getCallbackPath() string {
	path := c.CallbackPath
	if path == "" {
		path = DefaultOAuthCallbackPath
	}
	return path
}

func (c *OAuthAuthConfig) getLogoutPath() string {
	path := c.LogoutPath
	if path == "" {
		path = DefaultOAuthLogoutPath
	}
	return path
}

// generateRandomState generates a cryptographically secure random state parameter
func generateRandomState() (string, error) {
	b := make([]byte, stateParameterLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// pkceEnabled returns whether PKCE is enabled for this OAuth config.
// Defaults to true when the PKCE field is nil (not explicitly set).
func (c *OAuthAuthConfig) pkceEnabled() bool {
	if c.PKCE == nil {
		return true
	}
	return *c.PKCE
}

// generateCodeVerifier creates a cryptographically random PKCE code verifier.
// The verifier is a 43-128 character URL-safe string (RFC 7636 Section 4.1).
func generateCodeVerifier() (string, error) {
	// 32 bytes -> 43 base64url characters (without padding)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateCodeChallenge derives the S256 code challenge from a code verifier.
// The challenge is the base64url-encoded (no padding) SHA-256 hash of the verifier
// (RFC 7636 Section 4.2).
func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func createOAuth2Config(config *OAuthAuthConfig) (*oauth2.Config, error) {
	baseConfig := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
	}

	// Set default scopes if none provided
	if len(baseConfig.Scopes) == 0 {
		baseConfig.Scopes = []string{"openid", "email", "profile"}
	}

	// Check if auth_url and token_url are set (either from provider defaults or manual config)
	if config.AuthURL == "" || config.TokenURL == "" {
		return nil, fmt.Errorf("OAuth requires auth_url and token_url (set provider or configure manually)")
	}

	baseConfig.Endpoint = oauth2.Endpoint{
		AuthURL:  config.AuthURL,
		TokenURL: config.TokenURL,
	}

	return baseConfig, nil
}
