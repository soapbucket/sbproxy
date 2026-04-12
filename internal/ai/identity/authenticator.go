// authenticator.go defines the Authenticator interface and built-in credential validators.
package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	json "github.com/goccy/go-json"
)

// Authenticator validates credentials and returns a Principal.
type Authenticator interface {
	Type() CredentialType
	Authenticate(ctx context.Context, credential string) (*Principal, error)
}

// --------------------------------------------------------------------------
// APIKeyAuth
// --------------------------------------------------------------------------

// APIKeyAuth validates API keys against a static map or an external connector.
type APIKeyAuth struct {
	keys      map[string]*Principal // SHA-256(key) -> principal
	connector PermissionConnector   // optional dynamic lookup
}

// NewAPIKeyAuth creates an API key authenticator with pre-loaded static keys.
// The keys map is keyed by the raw API key; it will be stored internally by
// its SHA-256 hex digest.
func NewAPIKeyAuth(keys map[string]*Principal) *APIKeyAuth {
	hashed := make(map[string]*Principal, len(keys))
	for k, v := range keys {
		h := sha256.Sum256([]byte(k))
		hashed[fmt.Sprintf("%x", h)] = v
	}
	return &APIKeyAuth{keys: hashed}
}

// NewAPIKeyAuthWithConnector creates an API key authenticator that falls back
// to a PermissionConnector when the key is not in the static map.
func NewAPIKeyAuthWithConnector(keys map[string]*Principal, connector PermissionConnector) *APIKeyAuth {
	auth := NewAPIKeyAuth(keys)
	auth.connector = connector
	return auth
}

// Type returns CredentialAPIKey.
func (a *APIKeyAuth) Type() CredentialType { return CredentialAPIKey }

// Authenticate validates the given API key.
func (a *APIKeyAuth) Authenticate(ctx context.Context, credential string) (*Principal, error) {
	if credential == "" {
		return nil, fmt.Errorf("identity: empty API key")
	}

	h := sha256.Sum256([]byte(credential))
	digest := fmt.Sprintf("%x", h)

	if p, ok := a.keys[digest]; ok {
		cp := *p
		cp.AuthenticatedAt = time.Now()
		return &cp, nil
	}

	if a.connector != nil {
		perm, err := a.connector.Resolve(ctx, string(CredentialAPIKey), credential)
		if err != nil {
			return nil, fmt.Errorf("identity: API key connector error: %w", err)
		}
		if perm == nil {
			return nil, fmt.Errorf("identity: invalid API key")
		}
		return &Principal{
			ID:              perm.Principal,
			Type:            CredentialAPIKey,
			Groups:          perm.Groups,
			Models:          perm.Models,
			Permissions:     perm.Permissions,
			AuthenticatedAt: time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("identity: invalid API key")
}

// --------------------------------------------------------------------------
// JWTAuth
// --------------------------------------------------------------------------

// JWTClaimsMapping maps JWT claim names to Principal fields.
type JWTClaimsMapping struct {
	UserID      string // default: "sub"
	Groups      string // default: "groups"
	Permissions string // default: "permissions"
	Models      string // default: "models"
	WorkspaceID string // default: "workspace_id"
}

func (m *JWTClaimsMapping) withDefaults() JWTClaimsMapping {
	out := *m
	if out.UserID == "" {
		out.UserID = "sub"
	}
	if out.Groups == "" {
		out.Groups = "groups"
	}
	if out.Permissions == "" {
		out.Permissions = "permissions"
	}
	if out.Models == "" {
		out.Models = "models"
	}
	if out.WorkspaceID == "" {
		out.WorkspaceID = "workspace_id"
	}
	return out
}

// JWTAuthConfig configures the JWT authenticator.
type JWTAuthConfig struct {
	Issuer    string
	Audience  string
	Secret    []byte         // HMAC-SHA256 secret
	RSAKey    *rsa.PublicKey // Optional RSA public key (not used yet)
	ClaimsMap JWTClaimsMapping
}

// JWTAuth validates JWT tokens using HMAC-SHA256.
type JWTAuth struct {
	issuer    string
	audience  string
	secret    []byte
	claimsMap JWTClaimsMapping
}

// NewJWTAuth creates a JWT authenticator.
func NewJWTAuth(config JWTAuthConfig) *JWTAuth {
	cm := config.ClaimsMap.withDefaults()
	return &JWTAuth{
		issuer:    config.Issuer,
		audience:  config.Audience,
		secret:    config.Secret,
		claimsMap: cm,
	}
}

// Type returns CredentialJWT.
func (j *JWTAuth) Type() CredentialType { return CredentialJWT }

// Authenticate validates the JWT and extracts a Principal from claims.
func (j *JWTAuth) Authenticate(_ context.Context, credential string) (*Principal, error) {
	if credential == "" {
		return nil, fmt.Errorf("identity: empty JWT")
	}

	parts := strings.Split(credential, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("identity: malformed JWT, expected 3 parts")
	}

	// Verify HMAC-SHA256 signature.
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("identity: invalid JWT signature encoding: %w", err)
	}

	mac := hmac.New(sha256.New, j.secret)
	mac.Write([]byte(signingInput))
	expected := mac.Sum(nil)

	if !hmac.Equal(sig, expected) {
		return nil, fmt.Errorf("identity: invalid JWT signature")
	}

	// Decode payload.
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("identity: invalid JWT payload encoding: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("identity: invalid JWT payload JSON: %w", err)
	}

	// Check expiry.
	if exp, ok := claims["exp"]; ok {
		var expFloat float64
		switch v := exp.(type) {
		case float64:
			expFloat = v
		case int64:
			expFloat = float64(v)
		default:
			return nil, fmt.Errorf("identity: invalid exp claim type")
		}
		if time.Now().Unix() > int64(expFloat) {
			return nil, fmt.Errorf("identity: JWT expired")
		}
	}

	// Check issuer.
	if j.issuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != j.issuer {
			return nil, fmt.Errorf("identity: JWT issuer mismatch")
		}
	}

	// Check audience.
	if j.audience != "" {
		if aud, ok := claims["aud"].(string); !ok || aud != j.audience {
			return nil, fmt.Errorf("identity: JWT audience mismatch")
		}
	}

	// Build principal from claims.
	now := time.Now()
	p := &Principal{
		Type:            CredentialJWT,
		AuthenticatedAt: now,
	}

	if sub, ok := claims[j.claimsMap.UserID].(string); ok {
		p.UserID = sub
		p.ID = sub
	}
	if wid, ok := claims[j.claimsMap.WorkspaceID].(string); ok {
		p.WorkspaceID = wid
	}
	p.Groups = extractStringSlice(claims, j.claimsMap.Groups)
	p.Permissions = extractStringSlice(claims, j.claimsMap.Permissions)
	p.Models = extractStringSlice(claims, j.claimsMap.Models)

	if p.ID == "" {
		p.ID = "jwt-unknown"
	}

	// Set expiry on Principal if JWT has exp claim.
	if exp, ok := claims["exp"]; ok {
		var expFloat float64
		switch v := exp.(type) {
		case float64:
			expFloat = v
		case int64:
			expFloat = float64(v)
		}
		t := time.Unix(int64(expFloat), 0)
		p.ExpiresAt = &t
	}

	return p, nil
}

// --------------------------------------------------------------------------
// OAuthAuth
// --------------------------------------------------------------------------

// OAuthAuthConfig configures the OAuth authenticator.
type OAuthAuthConfig struct {
	IntrospectURL string
	ClientID      string
	ClientSecret  string
	HTTPClient    *http.Client
	Timeout       time.Duration
}

// OAuthAuth validates OAuth bearer tokens via token introspection (RFC 7662).
type OAuthAuth struct {
	introspectURL string
	clientID      string
	clientSecret  string
	httpClient    *http.Client
	timeout       time.Duration
}

// NewOAuthAuth creates an OAuth authenticator.
func NewOAuthAuth(config OAuthAuthConfig) *OAuthAuth {
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &OAuthAuth{
		introspectURL: config.IntrospectURL,
		clientID:      config.ClientID,
		clientSecret:  config.ClientSecret,
		httpClient:    client,
		timeout:       timeout,
	}
}

// Type returns CredentialOAuth.
func (o *OAuthAuth) Type() CredentialType { return CredentialOAuth }

// Authenticate validates the token via the introspection endpoint.
func (o *OAuthAuth) Authenticate(ctx context.Context, credential string) (*Principal, error) {
	if credential == "" {
		return nil, fmt.Errorf("identity: empty OAuth token")
	}

	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	body := "token=" + credential
	if o.clientID != "" {
		body += "&client_id=" + o.clientID
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.introspectURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("identity: failed to create introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if o.clientSecret != "" {
		req.SetBasicAuth(o.clientID, o.clientSecret)
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity: introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("identity: failed to read introspection response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity: introspection returned status %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("identity: invalid introspection response JSON: %w", err)
	}

	active, _ := result["active"].(bool)
	if !active {
		return nil, fmt.Errorf("identity: token is not active")
	}

	now := time.Now()
	p := &Principal{
		Type:            CredentialOAuth,
		AuthenticatedAt: now,
	}

	if sub, ok := result["sub"].(string); ok {
		p.UserID = sub
		p.ID = sub
	}
	if clientID, ok := result["client_id"].(string); ok && p.ID == "" {
		p.ID = clientID
	}
	if scope, ok := result["scope"].(string); ok && scope != "" {
		p.Permissions = strings.Split(scope, " ")
	}

	if exp, ok := result["exp"].(float64); ok {
		t := time.Unix(int64(exp), 0)
		p.ExpiresAt = &t
	}

	if p.ID == "" {
		p.ID = "oauth-unknown"
	}

	return p, nil
}

// --------------------------------------------------------------------------
// PersonalKeyAuth
// --------------------------------------------------------------------------

// PersonalKeyAuthConfig configures the personal key authenticator.
type PersonalKeyAuthConfig struct {
	ValidatorURL string
	HTTPClient   *http.Client
	Timeout      time.Duration
	StaticKeys   map[string]*Principal // Optional static keys for testing
}

// PersonalKeyAuth validates SoapBucket personal keys.
type PersonalKeyAuth struct {
	validatorURL string
	httpClient   *http.Client
	timeout      time.Duration
	keys         map[string]*Principal // SHA-256(key) -> principal
}

// NewPersonalKeyAuth creates a personal key authenticator.
func NewPersonalKeyAuth(config PersonalKeyAuthConfig) *PersonalKeyAuth {
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	hashed := make(map[string]*Principal, len(config.StaticKeys))
	for k, v := range config.StaticKeys {
		h := sha256.Sum256([]byte(k))
		hashed[fmt.Sprintf("%x", h)] = v
	}

	return &PersonalKeyAuth{
		validatorURL: config.ValidatorURL,
		httpClient:   client,
		timeout:      timeout,
		keys:         hashed,
	}
}

// Type returns CredentialPersonalKey.
func (p *PersonalKeyAuth) Type() CredentialType { return CredentialPersonalKey }

// Authenticate validates the personal key.
func (p *PersonalKeyAuth) Authenticate(ctx context.Context, credential string) (*Principal, error) {
	if credential == "" {
		return nil, fmt.Errorf("identity: empty personal key")
	}

	// Check static keys first.
	h := sha256.Sum256([]byte(credential))
	digest := fmt.Sprintf("%x", h)
	if pr, ok := p.keys[digest]; ok {
		cp := *pr
		cp.AuthenticatedAt = time.Now()
		return &cp, nil
	}

	// Fall back to backend validation endpoint.
	if p.validatorURL == "" {
		return nil, fmt.Errorf("identity: invalid personal key")
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	body := fmt.Sprintf(`{"key":"%s"}`, credential)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.validatorURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("identity: failed to create validation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity: personal key validation request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("identity: failed to read validation response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity: personal key validation returned status %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("identity: invalid validation response JSON: %w", err)
	}

	valid, _ := result["valid"].(bool)
	if !valid {
		return nil, fmt.Errorf("identity: invalid personal key")
	}

	now := time.Now()
	pr := &Principal{
		Type:            CredentialPersonalKey,
		AuthenticatedAt: now,
	}

	if userID, ok := result["user_id"].(string); ok {
		pr.UserID = userID
		pr.ID = userID
	}
	if wid, ok := result["workspace_id"].(string); ok {
		pr.WorkspaceID = wid
	}
	pr.Groups = extractStringSlice(result, "groups")
	pr.Models = extractStringSlice(result, "models")
	pr.Permissions = extractStringSlice(result, "permissions")

	if pr.ID == "" {
		pr.ID = "pk-unknown"
	}

	return pr, nil
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// base64URLDecode decodes a base64url-encoded string (no padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// extractStringSlice extracts a string slice from a claims map.
func extractStringSlice(claims map[string]any, key string) []string {
	raw, ok := claims[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return v
	case string:
		// Single value as comma-separated or space-separated.
		if strings.Contains(v, ",") {
			parts := strings.Split(v, ",")
			result := make([]string, 0, len(parts))
			for _, p := range parts {
				if trimmed := strings.TrimSpace(p); trimmed != "" {
					result = append(result, trimmed)
				}
			}
			return result
		}
		if strings.Contains(v, " ") {
			return strings.Fields(v)
		}
		return []string{v}
	}
	return nil
}
