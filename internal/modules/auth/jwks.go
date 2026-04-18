// jwks.go provides a standalone JWKS key set fetcher and cache for
// service mesh JWT validation scenarios.
//
// Unlike the full JWT auth provider in the jwt sub-package (which handles
// the complete authentication lifecycle), this component focuses solely
// on fetching, caching, and serving RSA public keys from a JWKS endpoint.
// It is intended for use by service mesh integrations that need to verify
// JWTs issued by external identity providers without importing the full
// auth module.
//
// Keys are cached in memory and refreshed on a configurable interval.
// The Refresh method is safe for concurrent use and can be called from
// a background goroutine.
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	defaultJWKSRefreshInterval = 1 * time.Hour
	jwksFetchTimeout           = 10 * time.Second
	maxJWKSResponseBytes       = 1 << 20 // 1 MiB
)

// Sentinel errors for JWKS operations.
var (
	ErrJWKSFetch        = errors.New("jwks: failed to fetch key set")
	ErrJWKSParse        = errors.New("jwks: invalid key set format")
	ErrJWKSKeyNotFound  = errors.New("jwks: key ID not found")
	ErrJWKSInvalidKey   = errors.New("jwks: invalid RSA key parameters")
	ErrJWKSEmptyURL     = errors.New("jwks: URL is required")
)

// JWKSConfig configures JWKS-based JWT validation.
type JWKSConfig struct {
	URL             string        `json:"url" yaml:"url"`
	Issuers         []string      `json:"issuers,omitempty" yaml:"issuers"`
	Audiences       []string      `json:"audiences,omitempty" yaml:"audiences"`
	RefreshInterval time.Duration `json:"refresh_interval,omitempty" yaml:"refresh_interval"`
}

// jwksKeySetEntry represents a single key in the JWKS response.
type jwksKeySetEntry struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksResponse is the JSON structure returned by a JWKS endpoint.
type jwksResponse struct {
	Keys []jwksKeySetEntry `json:"keys"`
}

// JWKSKeySet holds cached JWKS keys and handles periodic refresh.
type JWKSKeySet struct {
	mu              sync.RWMutex
	keys            map[string]*rsa.PublicKey // kid -> key
	lastFetch       time.Time
	refreshInterval time.Duration
	url             string
	client          *http.Client
}

// NewJWKSKeySet creates a new JWKS key set fetcher. The keys are not fetched
// until the first call to GetKey or Refresh.
func NewJWKSKeySet(cfg JWKSConfig) *JWKSKeySet {
	interval := cfg.RefreshInterval
	if interval <= 0 {
		interval = defaultJWKSRefreshInterval
	}
	return &JWKSKeySet{
		keys:            make(map[string]*rsa.PublicKey),
		refreshInterval: interval,
		url:             cfg.URL,
		client: &http.Client{
			Timeout: jwksFetchTimeout,
		},
	}
}

// GetKey returns the RSA public key for a given key ID. If the key is not
// found in the cache, or the cache has expired, the JWKS endpoint is refreshed
// before returning an error.
func (ks *JWKSKeySet) GetKey(kid string) (*rsa.PublicKey, error) {
	ks.mu.RLock()
	key, ok := ks.keys[kid]
	needsRefresh := time.Since(ks.lastFetch) > ks.refreshInterval
	ks.mu.RUnlock()

	if ok && !needsRefresh {
		return key, nil
	}

	// Refresh and try again
	if err := ks.Refresh(context.Background()); err != nil {
		// If we had a cached key, return it even if refresh failed
		if ok {
			return key, nil
		}
		return nil, err
	}

	ks.mu.RLock()
	key, ok = ks.keys[kid]
	ks.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrJWKSKeyNotFound, kid)
	}
	return key, nil
}

// Refresh fetches the latest keys from the JWKS endpoint and updates the cache.
func (ks *JWKSKeySet) Refresh(ctx context.Context) error {
	if ks.url == "" {
		return ErrJWKSEmptyURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ks.url, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}

	resp, err := ks.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", ErrJWKSFetch, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseBytes))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSParse, err)
	}

	newKeys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, entry := range jwks.Keys {
		if entry.Kty != "RSA" || entry.Kid == "" {
			continue
		}
		key, err := parseRSAPublicKey(entry)
		if err != nil {
			continue // Skip invalid keys rather than failing the whole refresh
		}
		newKeys[entry.Kid] = key
	}

	ks.mu.Lock()
	ks.keys = newKeys
	ks.lastFetch = time.Now()
	ks.mu.Unlock()

	return nil
}

// parseRSAPublicKey converts a JWKS entry into an rsa.PublicKey.
func parseRSAPublicKey(entry jwksKeySetEntry) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(entry.N)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid modulus: %v", ErrJWKSInvalidKey, err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(entry.E)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid exponent: %v", ErrJWKSInvalidKey, err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if !e.IsInt64() {
		return nil, fmt.Errorf("%w: exponent too large", ErrJWKSInvalidKey)
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
