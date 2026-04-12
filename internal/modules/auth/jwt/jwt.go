// Package jwt registers the JWT authentication provider.
// It supports RS256/ES256/HS256 algorithms, JWKS endpoints, token caching,
// and subject whitelist/blacklist enforcement.
package jwt

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
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gjwt "github.com/golang-jwt/jwt/v4"
	objectcache "github.com/soapbucket/sbproxy/internal/cache/object"
	"github.com/soapbucket/sbproxy/internal/loader/settings"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/platform/circuitbreaker"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAuth("jwt", New)
}

// Sentinel errors for JWT validation failures.
var (
	ErrNoToken               = errors.New("jwt: no token provided")
	ErrInvalidToken          = errors.New("jwt: invalid token")
	ErrTokenExpired          = errors.New("jwt: token expired")
	ErrInvalidIssuer         = errors.New("jwt: invalid issuer")
	ErrInvalidAudience       = errors.New("jwt: invalid audience")
	ErrInvalidSignature      = errors.New("jwt: invalid signature")
	ErrUnsupportedAlgorithm  = errors.New("jwt: unsupported algorithm")
	ErrPublicKeyNotFound     = errors.New("jwt: public key not found")
	ErrInvalidPublicKey      = errors.New("jwt: invalid public key format")
	ErrSubjectBlacklisted    = errors.New("jwt: subject is blacklisted")
	ErrSubjectNotWhitelisted = errors.New("jwt: subject not in whitelist")
	ErrJWKSFetchFailed       = errors.New("jwt: failed to fetch JWKS")
	ErrJWKSInvalidFormat     = errors.New("jwt: invalid JWKS format")
	ErrKeyIDNotFound         = errors.New("jwt: key ID (kid) not found in JWKS")
)

const (
	DefaultHeaderName     = "Authorization"
	DefaultHeaderPrefix   = "Bearer "
	DefaultAlgorithm      = "RS256"
	DefaultJWKSCacheDur   = 1 * time.Hour

	maxTokenCacheEntries = 10000
	tokenCacheTTL        = 30 * time.Second
)

// AuthListConfig holds whitelist/blacklist for subject claims.
type AuthListConfig struct {
	Whitelist []string `json:"whitelist,omitempty"`
	Blacklist []string `json:"blacklist,omitempty"`
}

// Config holds configuration for the JWT auth provider.
type Config struct {
	Type     string `json:"type"`
	Disabled bool   `json:"disabled,omitempty"`

	// Key material.
	Secret            string `json:"secret,omitempty" secret:"true"`
	PublicKey         string `json:"public_key,omitempty"`

	// JWKS support.
	JWKSURL                     string          `json:"jwks_url,omitempty"`
	JWKSCacheDurationSeconds    float64         `json:"jwks_cache_duration,omitempty"`
	DisableJWKSRefreshUnknownKID bool           `json:"disable_jwks_refresh_unknown_kid,omitempty"`

	// Validation.
	Issuer    string   `json:"issuer,omitempty"`
	Audience  string   `json:"audience,omitempty"`
	Audiences []string `json:"audiences,omitempty"`
	Algorithm string   `json:"algorithm,omitempty"`

	// Extraction.
	HeaderName   string `json:"header_name,omitempty"`
	HeaderPrefix string `json:"header_prefix,omitempty"`
	CookieName   string `json:"cookie_name,omitempty"`
	QueryParam   string `json:"query_param,omitempty"`

	// Auth list.
	AuthListConfig *AuthListConfig `json:"auth_list,omitempty"`

	// Cache duration for public keys.
	CacheDurationSeconds float64 `json:"cache_duration,omitempty"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key.
type JWK struct {
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Crv string `json:"crv,omitempty"`
	K   string `json:"k,omitempty"`
}

type publicKeyCache struct {
	key     interface{}
	expires time.Time
}

func (c publicKeyCache) isExpired() bool { return c.expires.Before(time.Now()) }

type jwtTokenCache struct {
	claims gjwt.MapClaims
}

type jwksCache struct {
	jwks    *JWKS
	keys    map[string]interface{}
	expires time.Time
}

func (c jwksCache) isExpired() bool { return c.expires.Before(time.Now()) }

// provider is the runtime JWT auth provider.
type provider struct {
	cfg              *Config
	jwksCacheDur     time.Duration
	keyCacheDur      time.Duration
	keyCache         map[string]publicKeyCache
	tokenCache       *objectcache.ObjectCache
	jwksCacheData    *jwksCache
	mx               sync.RWMutex
	httpClient       *http.Client
}

// New creates a new JWT auth provider from raw JSON configuration.
func New(data json.RawMessage) (plugin.AuthProvider, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.HeaderName == "" {
		cfg.HeaderName = DefaultHeaderName
	}
	if cfg.HeaderPrefix == "" {
		cfg.HeaderPrefix = DefaultHeaderPrefix
	}
	if cfg.Algorithm == "" {
		cfg.Algorithm = DefaultAlgorithm
	}

	jwksCacheDur := DefaultJWKSCacheDur
	if cfg.JWKSCacheDurationSeconds > 0 {
		jwksCacheDur = time.Duration(cfg.JWKSCacheDurationSeconds * float64(time.Second))
	}

	keyCacheDur := time.Duration(0)
	if cfg.CacheDurationSeconds > 0 {
		keyCacheDur = time.Duration(cfg.CacheDurationSeconds * float64(time.Second))
	}

	tc, err := objectcache.NewObjectCache(tokenCacheTTL, tokenCacheTTL, maxTokenCacheEntries, 0)
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to create token cache: %w", err)
	}

	return &provider{
		cfg:          cfg,
		jwksCacheDur: jwksCacheDur,
		keyCacheDur:  keyCacheDur,
		keyCache:     make(map[string]publicKeyCache),
		tokenCache:   tc,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

func (p *provider) Type() string { return "jwt" }

func (p *provider) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("jwt: authenticating request")

		tokenString, err := p.extractToken(r)
		if err != nil {
			slog.Debug("jwt: failed to extract token", "error", err)
			ipAddress := extractIP(r)
			metric.AuthFailure("unknown", "jwt", "token_missing", ipAddress)
			reqctx.RecordPolicyViolation(r.Context(), "auth", "authentication failed")
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}

		// Check token cache first.
		tokenHash := hashTokenString(tokenString)
		if cached, ok := p.tokenCache.Get(tokenHash); ok {
			cache, ok := cached.(jwtTokenCache)
			if !ok {
				slog.Warn("jwt: cached token has unexpected type, re-validating")
				goto validate
			}
			slog.Debug("jwt: using cached token validation")

			if err := p.checkAuthList(r.Context(), cache.claims); err != nil {
				slog.Debug("jwt: auth list check failed (cached)", "error", err)
				reqctx.RecordPolicyViolation(r.Context(), "auth", err.Error())
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
			return
		}

	validate:
		token, claims, err := p.parseAndValidateToken(r.Context(), tokenString)
		if err != nil {
			slog.Debug("jwt: failed to validate token", "error", err)
			ipAddress := extractIP(r)
			failureReason := "token_validation_failed"
			if strings.Contains(err.Error(), "expired") {
				failureReason = "token_expired"
			} else if strings.Contains(err.Error(), "invalid") {
				failureReason = "token_invalid"
			} else if strings.Contains(err.Error(), "signature") {
				failureReason = "token_signature_invalid"
			}
			metric.AuthFailure("unknown", "jwt", failureReason, ipAddress)
			reqctx.RecordPolicyViolation(r.Context(), "auth", "authentication failed")
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}

		if err := p.checkAuthList(r.Context(), claims); err != nil {
			slog.Debug("jwt: auth list check failed", "error", err)
			ipAddress := extractIP(r)
			metric.AuthzFailure("unknown", "jwt", "jwt_token", ipAddress)
			reqctx.RecordPolicyViolation(r.Context(), "auth", err.Error())
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		// Cache the validated token.
		p.tokenCache.PutWithExpires(tokenHash, jwtTokenCache{claims: claims}, tokenCacheTTL)

		slog.Debug("jwt: authentication successful", "valid", token.Valid)

		next.ServeHTTP(w, r)
	})
}

func (p *provider) extractToken(r *http.Request) (string, error) {
	if p.cfg.HeaderName != "" {
		header := r.Header.Get(p.cfg.HeaderName)
		if header != "" {
			if p.cfg.HeaderPrefix != "" && strings.HasPrefix(header, p.cfg.HeaderPrefix) {
				return strings.TrimPrefix(header, p.cfg.HeaderPrefix), nil
			}
			return header, nil
		}
	}

	if p.cfg.CookieName != "" {
		cookie, err := r.Cookie(p.cfg.CookieName)
		if err == nil && cookie.Value != "" {
			return cookie.Value, nil
		}
	}

	if p.cfg.QueryParam != "" {
		token := r.URL.Query().Get(p.cfg.QueryParam)
		if token != "" {
			return token, nil
		}
	}

	return "", ErrNoToken
}

func (p *provider) parseAndValidateToken(ctx context.Context, tokenString string) (*gjwt.Token, gjwt.MapClaims, error) {
	token, err := gjwt.Parse(tokenString, func(token *gjwt.Token) (interface{}, error) {
		if token.Method.Alg() != p.cfg.Algorithm {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrUnsupportedAlgorithm, p.cfg.Algorithm, token.Method.Alg())
		}
		return p.getVerificationKey(ctx, token)
	})

	if err != nil {
		if errors.Is(err, gjwt.ErrTokenExpired) {
			return nil, nil, ErrTokenExpired
		}
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(gjwt.MapClaims)
	if !ok {
		return nil, nil, ErrInvalidToken
	}

	if err := p.validateClaims(claims); err != nil {
		return nil, nil, err
	}

	return token, claims, nil
}

func (p *provider) getVerificationKey(ctx context.Context, token *gjwt.Token) (interface{}, error) {
	if p.cfg.JWKSURL != "" {
		kid, _ := token.Header["kid"].(string)
		key, err := p.getKeyFromJWKS(ctx, kid)
		if err != nil {
			if errors.Is(err, ErrKeyIDNotFound) && !p.cfg.DisableJWKSRefreshUnknownKID {
				slog.Debug("jwt: kid not found, refreshing JWKS", "kid", kid)
				p.mx.Lock()
				p.jwksCacheData = nil
				p.mx.Unlock()
				key, err = p.getKeyFromJWKS(ctx, kid)
			}
			if err != nil {
				return nil, err
			}
		}
		return key, nil
	}

	var keyData string
	var cacheKey string

	if p.cfg.PublicKey != "" {
		keyData = p.cfg.PublicKey
		cacheKey = "static"
	} else if p.cfg.Secret != "" {
		return []byte(p.cfg.Secret), nil
	} else {
		return nil, ErrPublicKeyNotFound
	}

	// Check cache.
	if p.keyCacheDur > 0 {
		p.mx.RLock()
		cached, ok := p.keyCache[cacheKey]
		p.mx.RUnlock()
		if ok && !cached.isExpired() {
			return cached.key, nil
		}
	}

	key, err := p.parseKey(keyData, token.Method.Alg())
	if err != nil {
		return nil, err
	}

	if p.keyCacheDur > 0 {
		p.mx.Lock()
		p.keyCache[cacheKey] = publicKeyCache{
			key:     key,
			expires: time.Now().Add(p.keyCacheDur),
		}
		p.mx.Unlock()
	}

	return key, nil
}

func (p *provider) parseKey(keyData string, algorithm string) (interface{}, error) {
	var rawKey []byte
	var err error

	if strings.HasPrefix(keyData, "-----BEGIN") {
		rawKey = []byte(keyData)
	} else {
		rawKey, err = base64.StdEncoding.DecodeString(keyData)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode base64 key: %v", ErrInvalidPublicKey, err)
		}
	}

	switch {
	case strings.HasPrefix(algorithm, "RS"):
		return parseRSAPublicKey(rawKey)
	case strings.HasPrefix(algorithm, "ES"):
		return parseECDSAPublicKey(rawKey)
	case strings.HasPrefix(algorithm, "HS"):
		return rawKey, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}
}

func parseRSAPublicKey(keyData []byte) (*rsa.PublicKey, error) {
	if block, _ := pem.Decode(keyData); block != nil {
		keyData = block.Bytes
	}

	if pub, err := x509.ParsePKIXPublicKey(keyData); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
	}

	if rsaPub, err := x509.ParsePKCS1PublicKey(keyData); err == nil {
		return rsaPub, nil
	}

	return nil, fmt.Errorf("%w: unable to parse RSA public key", ErrInvalidPublicKey)
}

func parseECDSAPublicKey(keyData []byte) (*ecdsa.PublicKey, error) {
	if block, _ := pem.Decode(keyData); block != nil {
		keyData = block.Bytes
	}

	if pub, err := x509.ParsePKIXPublicKey(keyData); err == nil {
		if ecdsaPub, ok := pub.(*ecdsa.PublicKey); ok {
			return ecdsaPub, nil
		}
	}

	return nil, fmt.Errorf("%w: unable to parse ECDSA public key", ErrInvalidPublicKey)
}

func (p *provider) validateClaims(claims gjwt.MapClaims) error {
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return ErrTokenExpired
		}
	}

	if p.cfg.Issuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != p.cfg.Issuer {
			return fmt.Errorf("%w: expected %s, got %v", ErrInvalidIssuer, p.cfg.Issuer, claims["iss"])
		}
	}

	if p.cfg.Audience != "" || len(p.cfg.Audiences) > 0 {
		expectedAudiences := append([]string{}, p.cfg.Audiences...)
		if p.cfg.Audience != "" {
			expectedAudiences = append(expectedAudiences, p.cfg.Audience)
		}

		aud, ok := claims["aud"]
		if !ok {
			return ErrInvalidAudience
		}

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

func (p *provider) checkAuthList(_ context.Context, claims gjwt.MapClaims) error {
	sub, ok := claims["sub"].(string)
	if !ok {
		return nil
	}

	authList := p.cfg.AuthListConfig
	if authList == nil {
		return nil
	}

	for _, blocked := range authList.Blacklist {
		if sub == blocked {
			return fmt.Errorf("%w: %s", ErrSubjectBlacklisted, sub)
		}
	}

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

func (p *provider) getKeyFromJWKS(ctx context.Context, kid string) (interface{}, error) {
	p.mx.RLock()
	if p.jwksCacheData != nil && !p.jwksCacheData.isExpired() {
		if kid != "" {
			if key, ok := p.jwksCacheData.keys[kid]; ok {
				p.mx.RUnlock()
				return key, nil
			}
		} else {
			for _, key := range p.jwksCacheData.keys {
				p.mx.RUnlock()
				return key, nil
			}
		}
		p.mx.RUnlock()
		return nil, ErrKeyIDNotFound
	}
	p.mx.RUnlock()

	jwksURL := p.cfg.JWKSURL
	if jwksURL == "" {
		return nil, fmt.Errorf("no JWKS URL configured")
	}

	cb := circuitbreaker.DefaultRegistry.GetOrCreate(
		"jwks:"+jwksURL, circuitbreaker.DefaultConfig,
	)

	var jwks *JWKS
	if cbErr := cb.Call(func() error {
		var fetchErr error
		jwks, fetchErr = p.fetchJWKS(ctx, jwksURL)
		return fetchErr
	}); cbErr != nil {
		return nil, cbErr
	}

	keys := make(map[string]interface{}, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		parsedKey, err := parseJWK(&jwk)
		if err != nil {
			slog.Warn("jwt: failed to parse JWK", "kid", jwk.Kid, "error", err)
			continue
		}
		if jwk.Kid != "" {
			keys[jwk.Kid] = parsedKey
		} else {
			keys["_default_"] = parsedKey
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no valid keys found in JWKS", ErrJWKSInvalidFormat)
	}

	p.mx.Lock()
	p.jwksCacheData = &jwksCache{
		jwks:    jwks,
		keys:    keys,
		expires: time.Now().Add(p.jwksCacheDur),
	}
	p.mx.Unlock()

	slog.Debug("jwt: fetched and cached JWKS", "url", jwksURL, "keys", len(keys))

	if kid != "" {
		if key, ok := keys[kid]; ok {
			return key, nil
		}
		return nil, fmt.Errorf("%w: %s", ErrKeyIDNotFound, kid)
	}

	for _, key := range keys {
		return key, nil
	}

	return nil, ErrPublicKeyNotFound
}

func (p *provider) fetchJWKS(ctx context.Context, jwksURL string) (*JWKS, error) {
	parsedURL, err := url.Parse(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid URL: %v", ErrJWKSFetchFailed, err)
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("%w: only HTTPS scheme allowed", ErrJWKSFetchFailed)
	}

	host := parsedURL.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: no hostname in URL", ErrJWKSFetchFailed)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("%w: DNS lookup failed: %v", ErrJWKSFetchFailed, err)
	}

	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("%w: SSRF detected - private/loopback IP rejected: %s", ErrJWKSFetchFailed, ip)
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrJWKSFetchFailed, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrJWKSFetchFailed, resp.StatusCode)
	}

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

func parseJWK(jwk *JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return parseRSAJWK(jwk)
	case "EC":
		return parseECDSAJWK(jwk)
	case "oct":
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

func parseRSAJWK(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf("missing 'n' or 'e' field for RSA key")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
	}

	var e int
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

func parseECDSAJWK(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.X == "" || jwk.Y == "" {
		return nil, fmt.Errorf("missing 'x' or 'y' field for ECDSA key")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ECDSA x: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ECDSA y: %w", err)
	}

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

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// hashTokenString creates a SHA256 hash of the token string for cache lookup.
func hashTokenString(token string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, token)
	return hex.EncodeToString(h.Sum(nil))
}

func extractIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return r.RemoteAddr
}
