// jwt_authenticator.go validates JWT tokens using JWKS with auto-refresh.
package identity

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"
)

// JWTPolicy defines the JWT verification policy for a workspace.
type JWTPolicy struct {
	WorkspaceID   string            `json:"workspace_id"`
	JWKSURL       string            `json:"jwks_url"`
	Issuer        string            `json:"issuer"`
	Audience      string            `json:"audience"`
	ClaimMapping  map[string]string `json:"claim_mapping"` // JWT claim -> principal field
	GroupsClaim   string            `json:"groups_claim"`  // claim containing groups array
	AutoProvision bool              `json:"auto_provision"`
	CacheTTL      time.Duration     `json:"cache_ttl"`
}

// JWKSEntry holds cached JWKS keys for a single URL.
type JWKSEntry struct {
	Keys      []JSONWebKey `json:"keys"`
	FetchedAt time.Time    `json:"fetched_at"`
	TTL       time.Duration
}

// JSONWebKey represents an RSA public key from a JWKS endpoint.
type JSONWebKey struct {
	KID string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// toRSAPublicKey converts the JWK to an *rsa.PublicKey.
func (k *JSONWebKey) toRSAPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(k.N)
	if err != nil {
		return nil, fmt.Errorf("identity/jwt: invalid JWK modulus: %w", err)
	}
	eBytes, err := base64URLDecode(k.E)
	if err != nil {
		return nil, fmt.Errorf("identity/jwt: invalid JWK exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("identity/jwt: exponent too large")
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// JWKSCache caches JWKS responses keyed by URL.
type JWKSCache struct {
	keys map[string]*JWKSEntry
	mu   sync.RWMutex
}

// newJWKSCache creates an empty JWKS cache.
func newJWKSCache() *JWKSCache {
	return &JWKSCache{
		keys: make(map[string]*JWKSEntry),
	}
}

// get returns cached keys if they are still fresh.
func (c *JWKSCache) get(url string) ([]JSONWebKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.keys[url]
	if !ok {
		return nil, false
	}
	if time.Since(entry.FetchedAt) > entry.TTL {
		return nil, false
	}
	return entry.Keys, true
}

// set stores a JWKS entry in the cache.
func (c *JWKSCache) set(url string, keys []JSONWebKey, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys[url] = &JWKSEntry{
		Keys:      keys,
		FetchedAt: time.Now(),
		TTL:       ttl,
	}
}

// JWTClaims holds the verified claims extracted from a JWT.
type JWTClaims struct {
	Subject   string            `json:"sub"`
	Email     string            `json:"email,omitempty"`
	Name      string            `json:"name,omitempty"`
	Groups    []string          `json:"groups,omitempty"`
	ExpiresAt time.Time         `json:"exp"`
	IssuedAt  time.Time         `json:"iat"`
	Extra     map[string]string `json:"extra,omitempty"`
}

// JWTAuthenticator verifies JWTs using JWKS-based RSA256 signature verification.
type JWTAuthenticator struct {
	policies   map[string]*JWTPolicy // workspaceID -> policy
	mu         sync.RWMutex
	jwksCache  *JWKSCache
	httpClient *http.Client
}

// NewJWTAuthenticator creates a new JWTAuthenticator.
func NewJWTAuthenticator() *JWTAuthenticator {
	return &JWTAuthenticator{
		policies:  make(map[string]*JWTPolicy),
		jwksCache: newJWKSCache(),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// AddPolicy registers a JWT verification policy for a workspace.
func (a *JWTAuthenticator) AddPolicy(policy *JWTPolicy) {
	if policy == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.policies[policy.WorkspaceID] = policy
}

// Authenticate verifies a JWT token for the given workspace and returns the
// extracted claims.
func (a *JWTAuthenticator) Authenticate(ctx context.Context, workspaceID string, tokenString string) (*JWTClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("identity/jwt: empty token")
	}

	a.mu.RLock()
	policy, ok := a.policies[workspaceID]
	a.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("identity/jwt: no policy for workspace %q", workspaceID)
	}

	// Split the JWT into header, payload, signature.
	parts := strings.SplitN(tokenString, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("identity/jwt: malformed token, expected 3 parts")
	}

	// Parse header to get kid.
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("identity/jwt: invalid header encoding: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("identity/jwt: invalid header JSON: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("identity/jwt: unsupported algorithm %q, expected RS256", header.Alg)
	}

	// Fetch JWKS and find matching key.
	jwks, err := a.FetchJWKS(ctx, policy.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("identity/jwt: failed to fetch JWKS: %w", err)
	}

	var jwk *JSONWebKey
	for i := range jwks {
		if jwks[i].KID == header.KID {
			jwk = &jwks[i]
			break
		}
	}
	if jwk == nil {
		return nil, fmt.Errorf("identity/jwt: no matching key for kid %q", header.KID)
	}

	// Convert JWK to RSA public key.
	pubKey, err := jwk.toRSAPublicKey()
	if err != nil {
		return nil, err
	}

	// Verify RSA256 signature.
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("identity/jwt: invalid signature encoding: %w", err)
	}

	hashed := crypto.SHA256.New()
	hashed.Write([]byte(signingInput))
	digest := hashed.Sum(nil)

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature); err != nil {
		return nil, fmt.Errorf("identity/jwt: invalid signature: %w", err)
	}

	// Decode payload.
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("identity/jwt: invalid payload encoding: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("identity/jwt: invalid payload JSON: %w", err)
	}

	// Validate standard claims.
	if policy.Issuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != policy.Issuer {
			return nil, fmt.Errorf("identity/jwt: issuer mismatch: got %q, want %q", iss, policy.Issuer)
		}
	}
	if policy.Audience != "" {
		aud, _ := claims["aud"].(string)
		if aud != policy.Audience {
			return nil, fmt.Errorf("identity/jwt: audience mismatch: got %q, want %q", aud, policy.Audience)
		}
	}

	now := time.Now()

	// Check exp.
	if exp, ok := claimFloat64(claims, "exp"); ok {
		if now.Unix() > int64(exp) {
			return nil, fmt.Errorf("identity/jwt: token expired")
		}
	}

	// Check nbf.
	if nbf, ok := claimFloat64(claims, "nbf"); ok {
		if now.Unix() < int64(nbf) {
			return nil, fmt.Errorf("identity/jwt: token not yet valid")
		}
	}

	// Build result.
	result := &JWTClaims{
		Extra: make(map[string]string),
	}

	// Extract standard fields.
	result.Subject, _ = claims["sub"].(string)
	result.Email, _ = claims["email"].(string)
	result.Name, _ = claims["name"].(string)

	if exp, ok := claimFloat64(claims, "exp"); ok {
		result.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if iat, ok := claimFloat64(claims, "iat"); ok {
		result.IssuedAt = time.Unix(int64(iat), 0)
	}

	// Extract groups from the configured claim.
	groupsClaim := policy.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	result.Groups = extractStringSlice(claims, groupsClaim)

	// Apply claim mapping: map JWT claims to extra fields.
	for jwtClaim, principalField := range policy.ClaimMapping {
		if val, ok := claims[jwtClaim].(string); ok {
			result.Extra[principalField] = val
		}
	}

	return result, nil
}

// FetchJWKS retrieves JSON Web Keys from the given URL, using the cache when
// available.
func (a *JWTAuthenticator) FetchJWKS(ctx context.Context, url string) ([]JSONWebKey, error) {
	// Check cache first.
	if keys, ok := a.jwksCache.get(url); ok {
		return keys, nil
	}

	// Determine TTL from any policy that references this URL.
	ttl := 5 * time.Minute
	a.mu.RLock()
	for _, p := range a.policies {
		if p.JWKSURL == url && p.CacheTTL > 0 {
			ttl = p.CacheTTL
			break
		}
	}
	a.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("identity/jwt: failed to create JWKS request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity/jwt: JWKS fetch failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("identity/jwt: failed to read JWKS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity/jwt: JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []JSONWebKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("identity/jwt: invalid JWKS JSON: %w", err)
	}

	a.jwksCache.set(url, jwks.Keys, ttl)
	return jwks.Keys, nil
}

// claimFloat64 extracts a numeric claim from the claims map, handling both
// float64 and int64 JSON representations.
func claimFloat64(claims map[string]any, key string) (float64, bool) {
	raw, ok := claims[key]
	if !ok {
		return 0, false
	}
	switch v := raw.(type) {
	case float64:
		return v, true
	case int64:
		return float64(v), true
	default:
		return 0, false
	}
}
