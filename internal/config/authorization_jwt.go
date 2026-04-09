// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/soapbucket/sbproxy/internal/platform/circuitbreaker"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/cache/object"
	"github.com/soapbucket/sbproxy/internal/loader/settings"
)

const (
	// Default values
	DefaultJWTHeaderName     = "Authorization"
	// DefaultJWTHeaderPrefix is the default value for jwt header prefix.
	DefaultJWTHeaderPrefix   = "Bearer "
	// DefaultJWTAlgorithm is the default value for jwt algorithm.
	DefaultJWTAlgorithm      = "RS256"
	// DefaultJWKSCacheDuration is the default value for jwks cache duration.
	DefaultJWKSCacheDuration = 1 * time.Hour
)

var (
	// ErrNoToken is a sentinel error for no token conditions.
	ErrNoToken               = errors.New("jwt: no token provided")
	// ErrInvalidToken is a sentinel error for invalid token conditions.
	ErrInvalidToken          = errors.New("jwt: invalid token")
	// ErrTokenExpired is a sentinel error for token expired conditions.
	ErrTokenExpired          = errors.New("jwt: token expired")
	// ErrInvalidIssuer is a sentinel error for invalid issuer conditions.
	ErrInvalidIssuer         = errors.New("jwt: invalid issuer")
	// ErrInvalidAudience is a sentinel error for invalid audience conditions.
	ErrInvalidAudience       = errors.New("jwt: invalid audience")
	// ErrInvalidSignature is a sentinel error for invalid signature conditions.
	ErrInvalidSignature      = errors.New("jwt: invalid signature")
	// ErrUnsupportedAlgorithm is a sentinel error for unsupported algorithm conditions.
	ErrUnsupportedAlgorithm  = errors.New("jwt: unsupported algorithm")
	// ErrPublicKeyNotFound is a sentinel error for public key not found conditions.
	ErrPublicKeyNotFound     = errors.New("jwt: public key not found")
	// ErrInvalidPublicKey is a sentinel error for invalid public key conditions.
	ErrInvalidPublicKey      = errors.New("jwt: invalid public key format")
	// ErrSubjectBlacklisted is a sentinel error for subject blacklisted conditions.
	ErrSubjectBlacklisted    = errors.New("jwt: subject is blacklisted")
	// ErrSubjectNotWhitelisted is a sentinel error for subject not whitelisted conditions.
	ErrSubjectNotWhitelisted = errors.New("jwt: subject not in whitelist")
	// ErrJWKSFetchFailed is a sentinel error for jwks fetch failed conditions.
	ErrJWKSFetchFailed       = errors.New("jwt: failed to fetch JWKS")
	// ErrJWKSInvalidFormat is a sentinel error for jwks invalid format conditions.
	ErrJWKSInvalidFormat     = errors.New("jwt: invalid JWKS format")
	// ErrKeyIDNotFound is a sentinel error for key id not found conditions.
	ErrKeyIDNotFound         = errors.New("jwt: key ID (kid) not found in JWKS")
)

func init() {
	authLoaderFuns[AuthTypeJWT] = NewJWTAuthConfig
}

// hashTokenString creates a SHA256 hash of the token for cache lookup.
// Uses sha256.New() + io.WriteString to avoid copying the token string to []byte.
func hashTokenString(token string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, token)
	return hex.EncodeToString(h.Sum(nil))
}

type publicKeyCache struct {
	key     interface{}
	expires time.Time
}

// IsExpired reports whether the publicKeyCache is expired.
func (c publicKeyCache) IsExpired() bool {
	return c.expires.Before(time.Now())
}

type jwtTokenCache struct {
	claims jwt.MapClaims
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid,omitempty"` // Key ID
	Kty string `json:"kty"`           // Key Type (RSA, EC, oct)
	Use string `json:"use,omitempty"` // Public Key Use (sig, enc)
	Alg string `json:"alg,omitempty"` // Algorithm
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	X   string `json:"x,omitempty"`   // ECDSA x coordinate
	Y   string `json:"y,omitempty"`   // ECDSA y coordinate
	Crv string `json:"crv,omitempty"` // ECDSA curve
	K   string `json:"k,omitempty"`   // Symmetric key
}

// jwksCache represents cached JWKS data
type jwksCache struct {
	jwks    *JWKS
	keys    map[string]interface{} // kid -> parsed key
	expires time.Time
}

// IsExpired reports whether the jwksCache is expired.
func (c jwksCache) IsExpired() bool {
	return c.expires.Before(time.Now())
}

const (
	// Maximum number of cached JWT tokens
	maxTokenCacheEntries = 10000
	// TTL for cached JWT tokens
	tokenCacheTTL = 30 * time.Second
)

// JWTAuthConfig holds configuration for jwt auth.
type JWTAuthConfig struct {
	JWTConfig

	keyCache   map[string]publicKeyCache
	tokenCache *objectcache.ObjectCache // tokenHash -> jwtTokenCache (bounded, LRU)
	jwksCache  *jwksCache
	mx         sync.RWMutex
	httpClient *http.Client
}

// NewJWTAuthConfig creates and initializes a new JWTAuthConfig.
func NewJWTAuthConfig(data []byte) (AuthConfig, error) {
	config := &JWTAuthConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Set defaults
	if config.HeaderName == "" {
		config.HeaderName = DefaultJWTHeaderName
	}
	if config.HeaderPrefix == "" {
		config.HeaderPrefix = DefaultJWTHeaderPrefix
	}
	if config.Algorithm == "" {
		config.Algorithm = DefaultJWTAlgorithm
	}
	if config.JWKSCacheDuration.Duration == 0 && config.JWKSURL != "" {
		config.JWKSCacheDuration = reqctx.Duration{Duration: DefaultJWKSCacheDuration}
	}

	config.keyCache = make(map[string]publicKeyCache)
	config.mx = sync.RWMutex{}
	config.httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}

	tc, err := objectcache.NewObjectCache(tokenCacheTTL, tokenCacheTTL, maxTokenCacheEntries, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create token cache: %w", err)
	}
	config.tokenCache = tc

	return config, nil
}

// Authenticate performs the authenticate operation on the JWTAuthConfig.
func (c *JWTAuthConfig) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("jwt: authenticating request")

		// Extract token from request
		tokenString, err := c.extractToken(r)
		if err != nil {
			slog.Debug("jwt: failed to extract token", "error", err)
			// Record authentication failure metric
			origin := "unknown"
			if c.cfg != nil {
				origin = c.cfg.ID
			}
			ipAddress := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ipAddress = strings.Split(forwarded, ",")[0]
			}
			metric.AuthFailure(origin, "jwt", "token_missing", ipAddress)
			emitSecurityAuthFailure(r.Context(), c.cfg, r, "jwt", "token_missing")
			slog.Debug("jwt: token missing", "error", err)
			reqctx.RecordPolicyViolation(r.Context(), "auth", "authentication failed")
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}

		// Check token cache first (ObjectCache handles TTL and LRU eviction)
		tokenHash := hashTokenString(tokenString)
		if cached, ok := c.tokenCache.Get(tokenHash); ok {
			cache, ok := cached.(jwtTokenCache)
			if !ok {
				slog.Warn("jwt: cached token has unexpected type, re-validating")
				goto validate
			}
			slog.Debug("jwt: using cached token validation")

			// Check whitelist/blacklist with cached claims
			if err := c.checkAuthList(r.Context(), cache.claims); err != nil {
				slog.Debug("jwt: auth list check failed (cached)", "error", err)
				reqctx.RecordPolicyViolation(r.Context(), "auth", err.Error())
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}

			// Create auth data from cached claims
			authData := &reqctx.AuthData{
				Type: AuthTypeJWT,
				Data: make(map[string]any, len(cache.claims)+3),
			}
			maps.Copy(authData.Data, cache.claims)

			authData.Data["token"] = tokenString
			authData.Data["valid"] = true
			authData.Data["cached"] = true

			// Call authentication callback if provided
			if c.AuthenticationCallback != nil {
				result, err := c.AuthenticationCallback.Do(r.Context(), authData.Data)
				if err != nil {
					slog.Error("jwt: authentication callback failed", "error", err)
					http.Error(w, "authentication callback failed", http.StatusInternalServerError)
					return
				}
				for key, value := range result {
					authData.Data[key] = value
				}
			}

			next.ServeHTTP(w, r)
			return
		}

	validate:
		// Parse and validate token (expensive operation)
		token, claims, err := c.parseAndValidateToken(r.Context(), tokenString)
		if err != nil {
			slog.Debug("jwt: failed to validate token", "error", err)
			// Record authentication failure metric
			origin := "unknown"
			if c.cfg != nil {
				origin = c.cfg.ID
			}
			ipAddress := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ipAddress = strings.Split(forwarded, ",")[0]
			}
			failureReason := "token_validation_failed"
			if strings.Contains(err.Error(), "expired") {
				failureReason = "token_expired"
			} else if strings.Contains(err.Error(), "invalid") {
				failureReason = "token_invalid"
			} else if strings.Contains(err.Error(), "signature") {
				failureReason = "token_signature_invalid"
			}
			metric.AuthFailure(origin, "jwt", failureReason, ipAddress)
			emitSecurityAuthFailure(r.Context(), c.cfg, r, "jwt", failureReason)
			slog.Debug("jwt: token validation failed", "reason", failureReason, "error", err)
			reqctx.RecordPolicyViolation(r.Context(), "auth", "authentication failed")
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}

		// Check whitelist/blacklist
		if err := c.checkAuthList(r.Context(), claims); err != nil {
			slog.Debug("jwt: auth list check failed", "error", err)
			// Record authorization failure metric
			origin := "unknown"
			requestData := reqctx.GetRequestData(r.Context())
			if requestData != nil {
				if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
					origin = id
				}
			}
			ipAddress := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ipAddress = strings.Split(forwarded, ",")[0]
			}
			resource := "jwt_token"
			if sub, ok := claims["sub"].(string); ok {
				resource = fmt.Sprintf("jwt_token:sub=%s", sub)
			}
			metric.AuthzFailure(origin, "jwt", resource, ipAddress)
			reqctx.RecordPolicyViolation(r.Context(), "auth", err.Error())
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		// Cache the validated token (ObjectCache handles TTL expiry)
		c.tokenCache.PutWithExpires(tokenHash, jwtTokenCache{
			claims: claims,
		}, tokenCacheTTL)

		// Create auth data
		authData := &reqctx.AuthData{
			Type: AuthTypeJWT,
			Data: make(map[string]any, len(claims)+2),
		}

		// Copy claims to auth data
		for key, value := range claims {
			authData.Data[key] = value
		}
		authData.Data["token"] = tokenString
		authData.Data["valid"] = token.Valid

		// Call authentication callback if provided
		if c.AuthenticationCallback != nil {
			result, err := c.AuthenticationCallback.Do(r.Context(), authData.Data)
			if err != nil {
				slog.Error("jwt: authentication callback failed", "error", err)
				http.Error(w, "authentication callback failed", http.StatusInternalServerError)
				return
			}
			// Merge callback results into auth data
			maps.Copy(authData.Data, result)
		}

		slog.Debug("jwt: authentication successful", "claims", claims)

		// Continue to next handler
		next.ServeHTTP(w, r)
	})
}

// extractToken extracts the JWT token from the request
func (c *JWTAuthConfig) extractToken(r *http.Request) (string, error) {
	// Try header first
	if c.HeaderName != "" {
		header := r.Header.Get(c.HeaderName)
		if header != "" {
			// Strip prefix if configured
			if c.HeaderPrefix != "" && strings.HasPrefix(header, c.HeaderPrefix) {
				return strings.TrimPrefix(header, c.HeaderPrefix), nil
			}
			return header, nil
		}
	}

	// Try cookie
	if c.CookieName != "" {
		cookie, err := r.Cookie(c.CookieName)
		if err == nil && cookie.Value != "" {
			return cookie.Value, nil
		}
	}

	// Try query parameter
	if c.QueryParam != "" {
		token := r.URL.Query().Get(c.QueryParam)
		if token != "" {
			return token, nil
		}
	}

	return "", ErrNoToken
}

// parseAndValidateToken parses and validates the JWT token
func (c *JWTAuthConfig) parseAndValidateToken(ctx context.Context, tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify algorithm
		if token.Method.Alg() != c.Algorithm {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrUnsupportedAlgorithm, c.Algorithm, token.Method.Alg())
		}

		return c.getVerificationKey(ctx, token)
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, nil, ErrTokenExpired
		}
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, nil, ErrInvalidToken
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, ErrInvalidToken
	}

	// Validate standard claims
	if err := c.validateClaims(claims); err != nil {
		return nil, nil, err
	}

	return token, claims, nil
}

// getVerificationKey returns the key for verifying the JWT signature
func (c *JWTAuthConfig) getVerificationKey(ctx context.Context, token *jwt.Token) (interface{}, error) {
	// Try JWKS first if configured
	if c.JWKSURL != "" || c.JWKSURLCallback != nil {
		kid, _ := token.Header["kid"].(string)
		key, err := c.getKeyFromJWKS(ctx, kid)
		if err != nil {
			// If kid not found and refresh is enabled, try refreshing JWKS
			if errors.Is(err, ErrKeyIDNotFound) && !c.DisableJWKSRefreshUnknownKID {
				slog.Debug("jwt: kid not found, refreshing JWKS", "kid", kid)
				c.mx.Lock()
				c.jwksCache = nil // Invalidate cache
				c.mx.Unlock()
				key, err = c.getKeyFromJWKS(ctx, kid)
			}
			if err != nil {
				return nil, err
			}
		}
		return key, nil
	}

	// Determine which key source to use
	var keyData string
	var cacheKey string

	// Try public key callback
	if c.PublicKeyCallback != nil {
		cacheKey = c.PublicKeyCallback.GetCacheKey()

		// Check cache
		if c.CacheDuration.Duration > 0 {
			c.mx.RLock()
			cached, ok := c.keyCache[cacheKey]
			c.mx.RUnlock()
			if ok && !cached.IsExpired() {
				return cached.key, nil
			}
		}

		// Call callback to get public key
		params := make(map[string]any)
		if kid, ok := token.Header["kid"].(string); ok {
			params["kid"] = kid
		}

		result, err := c.PublicKeyCallback.Do(ctx, params)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key from callback: %w", err)
		}

		// Extract public key from result
		if pk, ok := result["public_key"].(string); ok {
			keyData = pk
		} else {
			return nil, ErrPublicKeyNotFound
		}
	} else if c.PublicKey != "" {
		keyData = c.PublicKey
		cacheKey = "static"
	} else if c.Secret != "" {
		// HMAC secret
		return []byte(c.Secret), nil
	} else {
		return nil, ErrPublicKeyNotFound
	}

	// Parse the key based on algorithm
	key, err := c.parseKey(keyData, token.Method.Alg())
	if err != nil {
		return nil, err
	}

	// Cache the key
	if c.CacheDuration.Duration > 0 {
		c.mx.Lock()
		c.keyCache[cacheKey] = publicKeyCache{
			key:     key,
			expires: time.Now().Add(c.CacheDuration.Duration),
		}
		c.mx.Unlock()
	}

	return key, nil
}

// parseKey parses the key data based on the algorithm
func (c *JWTAuthConfig) parseKey(keyData string, algorithm string) (interface{}, error) {
	// Determine if this is a PEM-encoded key or base64-encoded
	var rawKey []byte
	var err error

	if strings.HasPrefix(keyData, "-----BEGIN") {
		// PEM-encoded key
		rawKey = []byte(keyData)
	} else {
		// Base64-encoded key
		rawKey, err = base64.StdEncoding.DecodeString(keyData)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode base64 key: %v", ErrInvalidPublicKey, err)
		}
	}

	// Parse based on algorithm type
	switch {
	case strings.HasPrefix(algorithm, "RS"):
		// RSA keys
		return c.parseRSAPublicKey(rawKey)
	case strings.HasPrefix(algorithm, "ES"):
		// ECDSA keys
		return c.parseECDSAPublicKey(rawKey)
	case strings.HasPrefix(algorithm, "HS"):
		// HMAC - return as bytes
		return rawKey, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}
}

// parseRSAPublicKey parses an RSA public key
func (c *JWTAuthConfig) parseRSAPublicKey(keyData []byte) (*rsa.PublicKey, error) {
	// Try PEM first
	if block, _ := pem.Decode(keyData); block != nil {
		keyData = block.Bytes
	}

	// Try PKIX format (most common)
	if pub, err := x509.ParsePKIXPublicKey(keyData); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
	}

	// Try PKCS1 format
	if rsaPub, err := x509.ParsePKCS1PublicKey(keyData); err == nil {
		return rsaPub, nil
	}

	return nil, fmt.Errorf("%w: unable to parse RSA public key", ErrInvalidPublicKey)
}

// parseECDSAPublicKey parses an ECDSA public key
func (c *JWTAuthConfig) parseECDSAPublicKey(keyData []byte) (*ecdsa.PublicKey, error) {
	// Try PEM first
	if block, _ := pem.Decode(keyData); block != nil {
		keyData = block.Bytes
	}

	// Try PKIX format
	if pub, err := x509.ParsePKIXPublicKey(keyData); err == nil {
		if ecdsaPub, ok := pub.(*ecdsa.PublicKey); ok {
			return ecdsaPub, nil
		}
	}

	return nil, fmt.Errorf("%w: unable to parse ECDSA public key", ErrInvalidPublicKey)
}

// validateClaims validates standard JWT claims
func (c *JWTAuthConfig) validateClaims(claims jwt.MapClaims) error {
	// Validate expiration (already done by jwt.Parse, but double-check)
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return ErrTokenExpired
		}
	}

	// Validate issuer
	if c.Issuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != c.Issuer {
			return fmt.Errorf("%w: expected %s, got %v", ErrInvalidIssuer, c.Issuer, claims["iss"])
		}
	}

	// Validate audience
	if c.Audience != "" || len(c.Audiences) > 0 {
		expectedAudiences := c.Audiences
		if c.Audience != "" {
			expectedAudiences = append(expectedAudiences, c.Audience)
		}

		aud, ok := claims["aud"]
		if !ok {
			return ErrInvalidAudience
		}

		// Audience can be string or []string
		var audList []string
		switch v := aud.(type) {
		case string:
			audList = []string{v}
		case []interface{}:
			for _, a := range v {
				if s, ok := a.(string); ok {
					audList = append(audList, s)
				}
			}
		default:
			return ErrInvalidAudience
		}

		// Check if any of the token audiences match expected audiences
		found := false
		for _, tokenAud := range audList {
			for _, expectedAud := range expectedAudiences {
				if tokenAud == expectedAud {
					found = true
					break
				}
			}
			if found {
				break
			}
		}

		if !found {
			return fmt.Errorf("%w: expected one of %v, got %v", ErrInvalidAudience, expectedAudiences, audList)
		}
	}

	return nil
}

// checkAuthList checks whitelist/blacklist for the subject claim
func (c *JWTAuthConfig) checkAuthList(ctx context.Context, claims jwt.MapClaims) error {
	// Get subject from claims
	sub, ok := claims["sub"].(string)
	if !ok {
		// If no subject, we can't check lists
		return nil
	}

	// Get auth list config
	authList := c.AuthListConfig

	// If callback is provided, use it to get dynamic auth list
	if c.AuthListCallback != nil {
		result, err := c.AuthListCallback.Do(ctx, map[string]any{"subject": sub})
		if err != nil {
			return fmt.Errorf("auth list callback failed: %w", err)
		}

		// Parse result
		if whitelist, ok := result["whitelist"].([]string); ok {
			if authList == nil {
				authList = &AuthListConfig{}
			}
			authList.Whitelist = whitelist
		}
		if blacklist, ok := result["blacklist"].([]string); ok {
			if authList == nil {
				authList = &AuthListConfig{}
			}
			authList.Blacklist = blacklist
		}
	}

	if authList == nil {
		return nil
	}

	// Check blacklist first
	for _, blocked := range authList.Blacklist {
		if sub == blocked {
			return fmt.Errorf("%w: %s", ErrSubjectBlacklisted, sub)
		}
	}

	// Check whitelist if configured
	if len(authList.Whitelist) > 0 {
		found := false
		for _, allowed := range authList.Whitelist {
			if sub == allowed {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: %s", ErrSubjectNotWhitelisted, sub)
		}
	}

	return nil
}

// getKeyFromJWKS fetches and parses keys from JWKS endpoint
func (c *JWTAuthConfig) getKeyFromJWKS(ctx context.Context, kid string) (interface{}, error) {
	// Check JWKS cache first
	c.mx.RLock()
	if c.jwksCache != nil && !c.jwksCache.IsExpired() {
		// Look up key by kid
		if kid != "" {
			if key, ok := c.jwksCache.keys[kid]; ok {
				c.mx.RUnlock()
				slog.Debug("jwt: using cached JWKS key", "kid", kid)
				return key, nil
			}
		} else {
			// No kid specified, return first key
			for _, key := range c.jwksCache.keys {
				c.mx.RUnlock()
				slog.Debug("jwt: using cached JWKS key (no kid specified)")
				return key, nil
			}
		}
		c.mx.RUnlock()
		return nil, ErrKeyIDNotFound
	}
	c.mx.RUnlock()

	// Fetch JWKS (protected by circuit breaker)
	jwksURL, err := c.getJWKSURL(ctx)
	if err != nil {
		return nil, err
	}

	cb := circuitbreaker.DefaultRegistry.GetOrCreate(
		"jwks:"+jwksURL, circuitbreaker.DefaultConfig,
	)

	var jwks *JWKS
	if cbErr := cb.Call(func() error {
		var fetchErr error
		jwks, fetchErr = c.fetchJWKS(ctx, jwksURL)
		return fetchErr
	}); cbErr != nil {
		return nil, cbErr
	}

	// Parse all keys in the JWKS
	keys := make(map[string]interface{}, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		parsedKey, err := c.parseJWK(&jwk)
		if err != nil {
			slog.Warn("jwt: failed to parse JWK", "kid", jwk.Kid, "error", err)
			continue
		}
		if jwk.Kid != "" {
			keys[jwk.Kid] = parsedKey
		} else {
			// If no kid, use a generated key
			keys["_default_"] = parsedKey
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no valid keys found in JWKS", ErrJWKSInvalidFormat)
	}

	// Cache the JWKS
	c.mx.Lock()
	c.jwksCache = &jwksCache{
		jwks:    jwks,
		keys:    keys,
		expires: time.Now().Add(c.JWKSCacheDuration.Duration),
	}
	c.mx.Unlock()

	slog.Debug("jwt: fetched and cached JWKS", "url", jwksURL, "keys", len(keys), "cache_duration", c.JWKSCacheDuration)

	// Look up the requested key
	if kid != "" {
		if key, ok := keys[kid]; ok {
			return key, nil
		}
		return nil, fmt.Errorf("%w: %s", ErrKeyIDNotFound, kid)
	}

	// No kid specified, return first key
	for _, key := range keys {
		return key, nil
	}

	return nil, ErrPublicKeyNotFound
}

// getJWKSURL returns the JWKS URL (static or from callback)
func (c *JWTAuthConfig) getJWKSURL(ctx context.Context) (string, error) {
	// Try callback first
	if c.JWKSURLCallback != nil {
		result, err := c.JWKSURLCallback.Do(ctx, nil)
		if err != nil {
			return "", fmt.Errorf("failed to get JWKS URL from callback: %w", err)
		}

		if url, ok := result["jwks_url"].(string); ok && url != "" {
			return url, nil
		}
		return "", fmt.Errorf("callback did not return valid jwks_url")
	}

	// Use static URL
	if c.JWKSURL != "" {
		return c.JWKSURL, nil
	}

	return "", fmt.Errorf("no JWKS URL configured")
}

// fetchJWKS fetches the JWKS from the given URL
func (c *JWTAuthConfig) fetchJWKS(ctx context.Context, jwksURL string) (*JWKS, error) {
	// Parse and validate the URL for SSRF prevention
	parsedURL, err := url.Parse(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid URL: %v", ErrJWKSFetchFailed, err)
	}

	// Only allow HTTPS
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("%w: only HTTPS scheme allowed", ErrJWKSFetchFailed)
	}

	// Extract host and validate against RFC 1918 and loopback
	host := parsedURL.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: no hostname in URL", ErrJWKSFetchFailed)
	}

	// Resolve hostname to IP and check for private/loopback ranges
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("%w: DNS lookup failed: %v", ErrJWKSFetchFailed, err)
	}

	for _, ip := range ips {
		// Reject RFC 1918 private ranges
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("%w: SSRF detected - private/loopback IP rejected: %s", ErrJWKSFetchFailed, ip)
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrJWKSFetchFailed, err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrJWKSFetchFailed, resp.StatusCode)
	}

	// Limit response body size to prevent abuse
	limitedBody := io.LimitReader(resp.Body, settings.Global.MaxJWKSBodyBytes)

	var jwks JWKS
	if err := json.NewDecoder(limitedBody).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", ErrJWKSInvalidFormat, err)
	}

	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("%w: no keys found", ErrJWKSInvalidFormat)
	}

	return &jwks, nil
}

// parseJWK parses a JWK into a crypto key
func (c *JWTAuthConfig) parseJWK(jwk *JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return c.parseRSAJWK(jwk)
	case "EC":
		return c.parseECDSAJWK(jwk)
	case "oct":
		// Symmetric key
		if jwk.K == "" {
			return nil, fmt.Errorf("missing 'k' field for symmetric key")
		}
		k, err := base64.RawURLEncoding.DecodeString(jwk.K)
		if err != nil {
			return nil, fmt.Errorf("failed to decode symmetric key: %w", err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// parseRSAJWK parses an RSA JWK
func (c *JWTAuthConfig) parseRSAJWK(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf("missing 'n' or 'e' field for RSA key")
	}

	// Decode modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
	}

	// Decode exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
	}

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}

	// Create RSA public key
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

// parseECDSAJWK parses an ECDSA JWK
func (c *JWTAuthConfig) parseECDSAJWK(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.X == "" || jwk.Y == "" {
		return nil, fmt.Errorf("missing 'x' or 'y' field for ECDSA key")
	}

	// Decode X coordinate
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ECDSA x: %w", err)
	}

	// Decode Y coordinate
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ECDSA y: %w", err)
	}

	// Determine curve
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	// Create ECDSA public key
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
