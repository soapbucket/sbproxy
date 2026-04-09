package identity

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CredentialDetector inspects HTTP requests and identifies credential type.
type CredentialDetector struct {
	authenticators map[CredentialType]Authenticator
	cache          *PermissionCache // optional, can be nil
	order          []CredentialType // detection order
}

// NewCredentialDetector creates a detector with given authenticators.
// The cache parameter is optional and may be nil.
func NewCredentialDetector(auths map[CredentialType]Authenticator, cache *PermissionCache) *CredentialDetector {
	return &CredentialDetector{
		authenticators: auths,
		cache:          cache,
		order: []CredentialType{
			CredentialPersonalKey,
			CredentialAPIKey,
			CredentialJWT,
			CredentialOAuth,
		},
	}
}

// Detect examines the request and returns the credential type, raw credential
// value, and whether a credential was found.
//
// Detection order:
//  1. X-SB-Personal-Key header or Bearer sbk_ prefix -> personal_key
//  2. X-API-Key header or Bearer sk- prefix (OpenAI) -> api_key
//  3. Authorization: Bearer with dots (JWT) -> jwt
//  4. Authorization: Bearer without dots -> oauth
//  5. Query param ?api_key= (fallback)
func (d *CredentialDetector) Detect(r *http.Request) (CredentialType, string, bool) {
	// 1. Personal key via dedicated header.
	if pk := r.Header.Get("X-SB-Personal-Key"); pk != "" {
		return CredentialPersonalKey, pk, true
	}

	// 2. X-API-Key header.
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return CredentialAPIKey, apiKey, true
	}

	// 3. Authorization: Bearer
	if auth := r.Header.Get("Authorization"); auth != "" {
		if token, ok := extractBearerToken(auth); ok {
			// Personal key prefix.
			if strings.HasPrefix(token, "sbk_") {
				return CredentialPersonalKey, token, true
			}
			// OpenAI-style API key prefix.
			if strings.HasPrefix(token, "sk-") {
				return CredentialAPIKey, token, true
			}
			// JWT detection: three dot-separated segments.
			if isJWTLike(token) {
				return CredentialJWT, token, true
			}
			// Fallback: treat as OAuth bearer token.
			return CredentialOAuth, token, true
		}
	}

	// 4. Query param fallback.
	if apiKey := r.URL.Query().Get("api_key"); apiKey != "" {
		return CredentialAPIKey, apiKey, true
	}

	return "", "", false
}

// Resolve detects credentials and authenticates, returning a Principal.
func (d *CredentialDetector) Resolve(ctx context.Context, r *http.Request) (*Principal, error) {
	credType, credential, found := d.Detect(r)
	if !found {
		return nil, fmt.Errorf("identity: no credentials found in request")
	}

	// Check cache first if configured.
	if d.cache != nil {
		perm, err := d.cache.Lookup(ctx, string(credType), credential)
		if err == nil && perm != nil {
			return &Principal{
				ID:              perm.Principal,
				Type:            credType,
				Groups:          perm.Groups,
				Models:          perm.Models,
				Permissions:     perm.Permissions,
				AuthenticatedAt: time.Now(),
			}, nil
		}
		// On cache miss or error, fall through to authenticator.
	}

	// Find the appropriate authenticator.
	auth, ok := d.authenticators[credType]
	if !ok {
		return nil, fmt.Errorf("identity: no authenticator for credential type %q", credType)
	}

	principal, err := auth.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}

	// Store in cache if configured.
	if d.cache != nil && principal != nil {
		// We do not store directly; the cache is populated via Lookup through
		// the L3 connector. For now, caching is a read-through concern handled
		// by callers who wire the connector. This avoids duplicating cache
		// writes in two code paths.
	}

	return principal, nil
}

// extractBearerToken extracts the token from "Bearer <token>" authorization.
func extractBearerToken(auth string) (string, bool) {
	const prefix = "Bearer "
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return auth[len(prefix):], true
	}
	return "", false
}

// isJWTLike returns true if the token looks like a JWT (three base64url segments).
func isJWTLike(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0 && len(parts[2]) > 0
}
