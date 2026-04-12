// Package signature implements request signing and verification for upstream authentication.
package signature

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

const (
	// Signature algorithms
	SignatureAlgorithmHMACSHA256 = "hmac-sha256"
	// SignatureAlgorithmHMACSHA512 is a constant for signature algorithm hmacsha512.
	SignatureAlgorithmHMACSHA512 = "hmac-sha512"
	// SignatureAlgorithmRSASHA256 is a constant for signature algorithm rsasha256.
	SignatureAlgorithmRSASHA256 = "rsa-sha256"
	// SignatureAlgorithmRSASHA512 is a constant for signature algorithm rsasha512.
	SignatureAlgorithmRSASHA512 = "rsa-sha512"

	// Signature encoding
	SignatureEncodingBase64 = "base64"
	// SignatureEncodingHex is a constant for signature encoding hex.
	SignatureEncodingHex = "hex"

	// Default headers
	DefaultSignatureHeader = "X-Signature"
	// DefaultTimestampHeader is the default value for timestamp header.
	DefaultTimestampHeader = "X-Signature-Timestamp"
	// DefaultNonceHeader is the default value for nonce header.
	DefaultNonceHeader = "X-Signature-Nonce"
	// DefaultAlgorithmHeader is the default value for algorithm header.
	DefaultAlgorithmHeader = "X-Signature-Algorithm"

	// Signature components
	SignatureComponentMethod = "method"
	// SignatureComponentPath is a constant for signature component path.
	SignatureComponentPath = "path"
	// SignatureComponentQuery is a constant for signature component query.
	SignatureComponentQuery = "query"
	// SignatureComponentHeaders is a constant for signature component headers.
	SignatureComponentHeaders = "headers"
	// SignatureComponentBody is a constant for signature component body.
	SignatureComponentBody = "body"
	// SignatureComponentTimestamp is a constant for signature component timestamp.
	SignatureComponentTimestamp = "timestamp"
	// SignatureComponentNonce is a constant for signature component nonce.
	SignatureComponentNonce = "nonce"

	// Cache prefix for signature-verified responses
	signatureCachePrefix = "sig_verified"
)

// SignatureConfig represents signature configuration for requests/responses
type SignatureConfig struct {
	// Core settings
	Algorithm  string `json:"algorithm"`                           // hmac-sha256, hmac-sha512, rsa-sha256, rsa-sha512
	Secret     string `json:"secret,omitempty" secret:"true"`      // For HMAC
	PrivateKey string `json:"private_key,omitempty" secret:"true"` // For RSA signing (PEM format)
	PublicKey  string `json:"public_key,omitempty"`                // For RSA verification (PEM format)

	// Signature placement
	SignatureHeader string `json:"signature_header,omitempty"`
	TimestampHeader string `json:"timestamp_header,omitempty"`
	NonceHeader     string `json:"nonce_header,omitempty"`
	AlgorithmHeader string `json:"algorithm_header,omitempty"`

	// Components to include in signature
	IncludeMethod    bool     `json:"include_method,omitempty"`
	IncludePath      bool     `json:"include_path,omitempty"`
	IncludeQuery     bool     `json:"include_query,omitempty"`
	IncludeHeaders   []string `json:"include_headers,omitempty"`
	IncludeBody      bool     `json:"include_body,omitempty"`
	IncludeTimestamp bool     `json:"include_timestamp,omitempty"`
	IncludeNonce     bool     `json:"include_nonce,omitempty"`

	// Encoding
	Encoding string `json:"encoding,omitempty"` // base64 (default), hex

	// Verification (for response signatures)
	Verify          bool  `json:"verify,omitempty"`
	MaxTimestampAge int64 `json:"max_timestamp_age,omitempty"` // seconds

	// Advanced options
	HeaderPrefix       string            `json:"header_prefix,omitempty"`
	QueryParameterName string            `json:"query_parameter_name,omitempty"`
	CustomComponents   map[string]string `json:"custom_components,omitempty"`

	// Cached keys
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// RequestSigner signs HTTP requests
type RequestSigner struct {
	config *SignatureConfig
}

// ResponseVerifier verifies HTTP response signatures
type ResponseVerifier struct {
	config *SignatureConfig
}

// NewRequestSigner creates a new request signer
func NewRequestSigner(config *SignatureConfig) (*RequestSigner, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	if err := config.loadKeys(); err != nil {
		return nil, err
	}

	return &RequestSigner{config: config}, nil
}

// NewResponseVerifier creates a new response verifier
func NewResponseVerifier(config *SignatureConfig) (*ResponseVerifier, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	if err := config.loadKeys(); err != nil {
		return nil, err
	}

	return &ResponseVerifier{config: config}, nil
}

// validate validates the signature configuration
func (c *SignatureConfig) validate() error {
	switch c.Algorithm {
	case SignatureAlgorithmHMACSHA256, SignatureAlgorithmHMACSHA512:
		if c.Secret == "" {
			return fmt.Errorf("secret required for HMAC algorithms")
		}
	case SignatureAlgorithmRSASHA256, SignatureAlgorithmRSASHA512:
		if c.PrivateKey == "" && c.PublicKey == "" {
			return fmt.Errorf("private_key or public_key required for RSA algorithms")
		}
	default:
		return fmt.Errorf("unsupported signature algorithm: %s", c.Algorithm)
	}

	return nil
}

// loadKeys loads RSA keys if configured
func (c *SignatureConfig) loadKeys() error {
	if c.PrivateKey != "" {
		block, _ := pem.Decode([]byte(c.PrivateKey))
		if block == nil {
			return fmt.Errorf("failed to decode private key PEM")
		}

		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS1
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse private key: %w", err)
			}
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key is not RSA")
		}
		c.privateKey = rsaKey
	}

	if c.PublicKey != "" {
		block, _ := pem.Decode([]byte(c.PublicKey))
		if block == nil {
			return fmt.Errorf("failed to decode public key PEM")
		}

		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			// Try PKCS1
			key, err = x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse public key: %w", err)
			}
		}

		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not RSA")
		}
		c.publicKey = rsaKey
	}

	return nil
}

// SignRequest signs an HTTP request
func (s *RequestSigner) SignRequest(req *http.Request) error {
	// Generate timestamp and nonce if needed
	timestamp := ""
	nonce := ""

	if s.config.IncludeTimestamp {
		timestamp = strconv.FormatInt(time.Now().Unix(), 10)
		timestampHeader := s.getHeaderName(DefaultTimestampHeader, s.config.TimestampHeader)
		req.Header.Set(timestampHeader, timestamp)
	}

	if s.config.IncludeNonce {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return fmt.Errorf("failed to generate nonce: %w", err)
		}
		nonce = hex.EncodeToString(nonceBytes)
		nonceHeader := s.getHeaderName(DefaultNonceHeader, s.config.NonceHeader)
		req.Header.Set(nonceHeader, nonce)
	}

	// Build signature string
	sigString, err := s.buildSignatureString(req, timestamp, nonce)
	if err != nil {
		return fmt.Errorf("failed to build signature string: %w", err)
	}

	// Generate signature
	signature, err := s.sign(sigString)
	if err != nil {
		return fmt.Errorf("failed to generate signature: %w", err)
	}

	// Encode signature
	encodedSig := s.encodeSignature(signature)

	// Set signature header
	signatureHeader := s.getHeaderName(DefaultSignatureHeader, s.config.SignatureHeader)
	req.Header.Set(signatureHeader, encodedSig)

	// Optionally set algorithm header
	if s.config.AlgorithmHeader != "" {
		req.Header.Set(s.config.AlgorithmHeader, s.config.Algorithm)
	}

	return nil
}

// buildSignatureString builds the string to sign
func (s *RequestSigner) buildSignatureString(req *http.Request, timestamp, nonce string) (string, error) {
	var parts []string

	if s.config.IncludeMethod {
		parts = append(parts, req.Method)
	}

	if s.config.IncludePath {
		parts = append(parts, req.URL.Path)
	}

	if s.config.IncludeQuery && req.URL.RawQuery != "" {
		parts = append(parts, req.URL.RawQuery)
	}

	if len(s.config.IncludeHeaders) > 0 {
		headerParts := s.buildHeaderString(req)
		parts = append(parts, headerParts)
	}

	if s.config.IncludeBody {
		bodyStr, err := s.getBodyString(req)
		if err != nil {
			return "", err
		}
		parts = append(parts, bodyStr)
	}

	if s.config.IncludeTimestamp {
		parts = append(parts, timestamp)
	}

	if s.config.IncludeNonce {
		parts = append(parts, nonce)
	}

	// Add custom components
	for key, value := range s.config.CustomComponents {
		parts = append(parts, fmt.Sprintf("%s=%s", key, value))
	}

	return strings.Join(parts, "\n"), nil
}

// buildHeaderString builds a canonical header string
func (s *RequestSigner) buildHeaderString(req *http.Request) string {
	var headerParts []string

	for _, headerName := range s.config.IncludeHeaders {
		value := req.Header.Get(headerName)
		if value != "" {
			headerParts = append(headerParts, fmt.Sprintf("%s:%s", strings.ToLower(headerName), strings.TrimSpace(value)))
		}
	}

	sort.Strings(headerParts)
	return strings.Join(headerParts, "\n")
}

// getBodyString reads and restores request body
func (s *RequestSigner) getBodyString(req *http.Request) (string, error) {
	if req.Body == nil {
		return "", nil
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read body: %w", err)
	}

	// Restore body for later use
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	return string(bodyBytes), nil
}

// sign generates the signature
func (s *RequestSigner) sign(data string) ([]byte, error) {
	switch s.config.Algorithm {
	case SignatureAlgorithmHMACSHA256:
		return s.signHMAC([]byte(data), sha256.New)
	case SignatureAlgorithmHMACSHA512:
		return s.signHMAC([]byte(data), sha512.New)
	case SignatureAlgorithmRSASHA256:
		return s.signRSA([]byte(data), crypto.SHA256)
	case SignatureAlgorithmRSASHA512:
		return s.signRSA([]byte(data), crypto.SHA512)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", s.config.Algorithm)
	}
}

// signHMAC signs data with HMAC
func (s *RequestSigner) signHMAC(data []byte, hashFunc func() hash.Hash) ([]byte, error) {
	h := hmac.New(hashFunc, []byte(s.config.Secret))
	h.Write(data)
	return h.Sum(nil), nil
}

// signRSA signs data with RSA
func (s *RequestSigner) signRSA(data []byte, hashAlg crypto.Hash) ([]byte, error) {
	if s.config.privateKey == nil {
		return nil, fmt.Errorf("private key not loaded")
	}

	h := hashAlg.New()
	h.Write(data)
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, s.config.privateKey, hashAlg, hashed)
	if err != nil {
		return nil, fmt.Errorf("RSA signing failed: %w", err)
	}

	return signature, nil
}

// encodeSignature encodes the signature bytes
func (s *RequestSigner) encodeSignature(sig []byte) string {
	encoding := s.config.Encoding
	if encoding == "" {
		encoding = SignatureEncodingBase64
	}

	switch encoding {
	case SignatureEncodingHex:
		return hex.EncodeToString(sig)
	default:
		return base64.StdEncoding.EncodeToString(sig)
	}
}

// getHeaderName returns the configured header name or default
func (s *RequestSigner) getHeaderName(defaultName, configName string) string {
	if configName != "" {
		if s.config.HeaderPrefix != "" {
			return s.config.HeaderPrefix + configName
		}
		return configName
	}
	if s.config.HeaderPrefix != "" {
		return s.config.HeaderPrefix + defaultName
	}
	return defaultName
}

// VerifyResponse verifies an HTTP response signature
func (v *ResponseVerifier) VerifyResponse(resp *http.Response) error {
	// If no verification config, skip
	if v.config == nil {
		return nil
	}

	// Get signature from header
	signatureHeader := v.getHeaderName(DefaultSignatureHeader, v.config.SignatureHeader)
	encodedSig := resp.Header.Get(signatureHeader)
	if encodedSig == "" {
		return fmt.Errorf("signature header not found: %s", signatureHeader)
	}

	// Decode signature
	signature, err := v.decodeSignature(encodedSig)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Check timestamp if required
	if v.config.IncludeTimestamp && v.config.MaxTimestampAge > 0 {
		timestampHeader := v.getHeaderName(DefaultTimestampHeader, v.config.TimestampHeader)
		if err := v.validateTimestamp(resp.Header.Get(timestampHeader)); err != nil {
			return err
		}
	}

	// Build signature string (similar to request signing but for response)
	sigString, err := v.buildResponseSignatureString(resp)
	if err != nil {
		return fmt.Errorf("failed to build signature string: %w", err)
	}

	// Verify signature
	if err := v.verify(sigString, signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// buildResponseSignatureString builds signature string for response
func (v *ResponseVerifier) buildResponseSignatureString(resp *http.Response) (string, error) {
	var parts []string

	// For responses, we typically include status code instead of method
	parts = append(parts, strconv.Itoa(resp.StatusCode))

	if len(v.config.IncludeHeaders) > 0 {
		headerParts := v.buildHeaderString(resp)
		parts = append(parts, headerParts)
	}

	if v.config.IncludeBody {
		bodyStr, err := v.getBodyString(resp)
		if err != nil {
			return "", err
		}
		parts = append(parts, bodyStr)
	}

	if v.config.IncludeTimestamp {
		timestampHeader := v.getHeaderName(DefaultTimestampHeader, v.config.TimestampHeader)
		timestamp := resp.Header.Get(timestampHeader)
		if timestamp != "" {
			parts = append(parts, timestamp)
		}
	}

	return strings.Join(parts, "\n"), nil
}

// buildHeaderString builds canonical header string for response
func (v *ResponseVerifier) buildHeaderString(resp *http.Response) string {
	var headerParts []string

	for _, headerName := range v.config.IncludeHeaders {
		value := resp.Header.Get(headerName)
		if value != "" {
			headerParts = append(headerParts, fmt.Sprintf("%s:%s", strings.ToLower(headerName), strings.TrimSpace(value)))
		}
	}

	sort.Strings(headerParts)
	return strings.Join(headerParts, "\n")
}

// getBodyString reads and restores response body
func (v *ResponseVerifier) getBodyString(resp *http.Response) (string, error) {
	if resp.Body == nil {
		return "", nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read body: %w", err)
	}

	// Restore body
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	return string(bodyBytes), nil
}

// verify verifies the signature
func (v *ResponseVerifier) verify(data string, signature []byte) error {
	switch v.config.Algorithm {
	case SignatureAlgorithmHMACSHA256:
		return v.verifyHMAC([]byte(data), signature, sha256.New)
	case SignatureAlgorithmHMACSHA512:
		return v.verifyHMAC([]byte(data), signature, sha512.New)
	case SignatureAlgorithmRSASHA256:
		return v.verifyRSA([]byte(data), signature, crypto.SHA256)
	case SignatureAlgorithmRSASHA512:
		return v.verifyRSA([]byte(data), signature, crypto.SHA512)
	default:
		return fmt.Errorf("unsupported algorithm: %s", v.config.Algorithm)
	}
}

// verifyHMAC verifies HMAC signature
func (v *ResponseVerifier) verifyHMAC(data, signature []byte, hashFunc func() hash.Hash) error {
	h := hmac.New(hashFunc, []byte(v.config.Secret))
	h.Write(data)
	expected := h.Sum(nil)

	if !hmac.Equal(signature, expected) {
		return fmt.Errorf("HMAC signature mismatch")
	}

	return nil
}

// verifyRSA verifies RSA signature
func (v *ResponseVerifier) verifyRSA(data, signature []byte, hashAlg crypto.Hash) error {
	if v.config.publicKey == nil {
		return fmt.Errorf("public key not loaded")
	}

	h := hashAlg.New()
	h.Write(data)
	hashed := h.Sum(nil)

	err := rsa.VerifyPKCS1v15(v.config.publicKey, hashAlg, hashed, signature)
	if err != nil {
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}

	return nil
}

// decodeSignature decodes the signature string
func (v *ResponseVerifier) decodeSignature(encoded string) ([]byte, error) {
	encoding := v.config.Encoding
	if encoding == "" {
		encoding = SignatureEncodingBase64
	}

	switch encoding {
	case SignatureEncodingHex:
		return hex.DecodeString(encoded)
	default:
		return base64.StdEncoding.DecodeString(encoded)
	}
}

// validateTimestamp validates the timestamp is within allowed age
func (v *ResponseVerifier) validateTimestamp(timestampStr string) error {
	if timestampStr == "" {
		return fmt.Errorf("timestamp header missing")
	}

	var timestamp int64
	if _, err := fmt.Sscanf(timestampStr, "%d", &timestamp); err != nil {
		return fmt.Errorf("invalid timestamp format: %w", err)
	}

	now := time.Now().Unix()
	age := now - timestamp

	if age < 0 {
		return fmt.Errorf("timestamp is in the future")
	}

	if age > v.config.MaxTimestampAge {
		return fmt.Errorf("timestamp too old: %d seconds (max: %d)", age, v.config.MaxTimestampAge)
	}

	return nil
}

// getHeaderName returns the configured header name or default
func (v *ResponseVerifier) getHeaderName(defaultName, configName string) string {
	if configName != "" {
		if v.config.HeaderPrefix != "" {
			return v.config.HeaderPrefix + configName
		}
		return configName
	}
	if v.config.HeaderPrefix != "" {
		return v.config.HeaderPrefix + defaultName
	}
	return defaultName
}

// MarshalJSON implements json.Marshaler
func (c *SignatureConfig) MarshalJSON() ([]byte, error) {
	type Alias SignatureConfig
	return json.Marshal(&struct {
		*Alias
		// Omit sensitive fields from JSON
		PrivateKey string `json:"private_key,omitempty"`
		PublicKey  string `json:"public_key,omitempty"`
		Secret     string `json:"secret,omitempty"`
	}{
		Alias:      (*Alias)(c),
		PrivateKey: "",
		PublicKey:  "",
		Secret:     "",
	})
}

// CachedResponseVerifier wraps a ResponseVerifier with caching support.
// It serves cached responses immediately, then validates signatures in the background.
// If validation fails, the cache is invalidated.
type CachedResponseVerifier struct {
	verifier *ResponseVerifier
	cache    cacher.Cacher
	ttl      time.Duration
}

// CachedResponseVerifierConfig configures a cached response verifier
type CachedResponseVerifierConfig struct {
	Verifier *ResponseVerifier
	Cache    cacher.Cacher
	TTL      time.Duration // Time-to-live for cached responses
}

// NewCachedResponseVerifier creates a new cached response verifier
func NewCachedResponseVerifier(config CachedResponseVerifierConfig) (*CachedResponseVerifier, error) {
	if config.Verifier == nil {
		return nil, fmt.Errorf("verifier is required")
	}
	if config.Cache == nil {
		return nil, fmt.Errorf("cache is required")
	}
	if config.TTL <= 0 {
		config.TTL = 5 * time.Minute // Default TTL
	}

	return &CachedResponseVerifier{
		verifier: config.Verifier,
		cache:    config.Cache,
		ttl:      config.TTL,
	}, nil
}

// VerifyResponseWithCache verifies a response signature with caching support.
// It first checks the cache and serves a cached response if available.
// Then it validates the signature in the background. If validation fails, the cache is invalidated.
func (c *CachedResponseVerifier) VerifyResponseWithCache(req *http.Request, resp *http.Response) (*http.Response, error) {
	ctx := req.Context()

	// Generate cache key based on request URL and signature header
	cacheKey := c.generateCacheKey(req, resp)

	// Try to get cached response
	if cachedResp := c.getCachedResponse(req, cacheKey); cachedResp != nil {
		// Store cache key in RequestData for request logging
		if requestData := reqctx.GetRequestData(req.Context()); requestData != nil {
			requestData.SignatureCacheKey = cacheKey
			requestData.SignatureCacheHit = true
			requestData.AddDebugHeader(httputil.HeaderXSbCacheKey, cacheKey)
		}

		slog.Debug("signature cache hit",
			"method", req.Method,
			"url", req.URL.String(),
			"cache_key", cacheKey)

		// Serve cached response immediately, then validate in background
		go c.validateAndUpdateCache(req, resp, cacheKey)

		return cachedResp, nil
	}

	slog.Debug("signature cache miss",
		"method", req.Method,
		"url", req.URL.String(),
		"cache_key", cacheKey)

	// No cache hit - verify signature synchronously
	if err := c.verifier.VerifyResponse(resp); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Cache the verified response
	c.cacheResponse(ctx, cacheKey, resp)

	slog.Debug("signature verified and cached",
		"method", req.Method,
		"url", req.URL.String(),
		"cache_key", cacheKey,
		"ttl", c.ttl)

	return resp, nil
}

// VerifyResponse verifies a response signature (implements ResponseVerifier interface)
func (c *CachedResponseVerifier) VerifyResponse(resp *http.Response) error {
	return c.verifier.VerifyResponse(resp)
}

// generateCacheKey generates a cache key for a signature-verified response
func (c *CachedResponseVerifier) generateCacheKey(req *http.Request, resp *http.Response) string {
	// Include request URL and signature header in cache key
	signatureHeader := DefaultSignatureHeader
	if c.verifier.config != nil && c.verifier.config.SignatureHeader != "" {
		signatureHeader = c.verifier.config.SignatureHeader
	}
	signature := resp.Header.Get(signatureHeader)

	// Build cache key from request URL and signature
	builder := cacher.NewCacheKeyBuilder().
		Add("sig").
		Add(req.Method).
		Add(req.URL.String()).
		Add(signature)

	// Add workspace_id and config_id from RequestData.Config for workspace-level cache isolation
	if requestData := reqctx.GetRequestData(req.Context()); requestData != nil && requestData.Config != nil {
		configParams := reqctx.ConfigParams(requestData.Config)
		if workspaceID := configParams.GetWorkspaceID(); workspaceID != "" {
			builder.Add("workspace:" + workspaceID)
		}
		if configID := configParams.GetConfigID(); configID != "" {
			builder.Add("config:" + configID)
		}
	}

	return builder.BuildHashed()
}

// getCachedResponse retrieves a cached response
func (c *CachedResponseVerifier) getCachedResponse(req *http.Request, cacheKey string) *http.Response {
	ctx := req.Context()
	reader, err := c.cache.Get(ctx, signatureCachePrefix, cacheKey)
	if err != nil {
		if err != cacher.ErrNotFound {
			slog.Debug("signature cache get error",
				"cache_key", cacheKey,
				"error", err)
		}
		return nil
	}

	// Read cached response data
	data, err := io.ReadAll(reader)
	if err != nil {
		slog.Error("failed to read cached signature response",
			"cache_key", cacheKey,
			"error", err)
		return nil
	}

	// Deserialize response
	var cached cachedResponseData
	if err := json.Unmarshal(data, &cached); err != nil {
		slog.Error("failed to unmarshal cached signature response",
			"cache_key", cacheKey,
			"error", err)
		return nil
	}

	slog.Debug("signature cache retrieved",
		"cache_key", cacheKey,
		"size", len(data),
		"status_code", cached.StatusCode)

	// Reconstruct http.Response
	resp := &http.Response{
		StatusCode:       cached.StatusCode,
		Proto:            cached.Proto,
		ProtoMajor:       cached.ProtoMajor,
		ProtoMinor:       cached.ProtoMinor,
		Header:           cached.Header,
		Body:             io.NopCloser(bytes.NewReader(cached.Body)),
		ContentLength:    int64(len(cached.Body)),
		TransferEncoding: cached.TransferEncoding,
		Close:            cached.Close,
		Uncompressed:     cached.Uncompressed,
		Trailer:          cached.Trailer,
		Request:          req, // Set request for context
	}

	return resp
}

// cacheResponse stores a verified response in the cache
func (c *CachedResponseVerifier) cacheResponse(ctx context.Context, cacheKey string, resp *http.Response) {
	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("failed to read response body for caching", "error", err)
		return
	}
	// Restore body
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Create cache data
	cached := cachedResponseData{
		StatusCode:       resp.StatusCode,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           resp.Header.Clone(),
		Body:             bodyBytes,
		TransferEncoding: resp.TransferEncoding,
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
		Trailer:          resp.Trailer.Clone(),
	}

	// Serialize and cache
	data, err := json.Marshal(cached)
	if err != nil {
		slog.Error("failed to marshal response for caching", "error", err)
		return
	}

	if err := c.cache.PutWithExpires(ctx, signatureCachePrefix, cacheKey, bytes.NewReader(data), c.ttl); err != nil {
		slog.Error("failed to cache verified response",
			"cache_key", cacheKey,
			"ttl", c.ttl,
			"error", err)
	} else {
		slog.Debug("signature response cached",
			"cache_key", cacheKey,
			"ttl", c.ttl,
			"size", len(data))
	}
}

// validateAndUpdateCache validates a signature in the background and updates cache if needed
func (c *CachedResponseVerifier) validateAndUpdateCache(req *http.Request, resp *http.Response, cacheKey string) {
	ctx := req.Context()
	// Create a copy of the response for verification
	// Read body for verification
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Warn("failed to read response body for validation", "error", err)
		return
	}
	// Restore body
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Create a copy of the response for verification
	verifyResp := &http.Response{
		StatusCode:       resp.StatusCode,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           resp.Header.Clone(),
		Body:             io.NopCloser(bytes.NewReader(bodyBytes)),
		ContentLength:    resp.ContentLength,
		TransferEncoding: resp.TransferEncoding,
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
		Trailer:          resp.Trailer.Clone(),
		Request:          req,
	}

	// Verify signature
	if err := c.verifier.VerifyResponse(verifyResp); err != nil {
		slog.Warn("signature validation failed for cached response, invalidating cache",
			"method", req.Method,
			"url", req.URL.String(),
			"error", err,
			"cache_key", cacheKey)

		// Invalidate cache
		if err := c.cache.Delete(ctx, signatureCachePrefix, cacheKey); err != nil {
			slog.Error("failed to invalidate signature cache",
				"cache_key", cacheKey,
				"error", err)
		} else {
			slog.Debug("signature cache invalidated",
				"cache_key", cacheKey)
		}
		return
	}

	// Validation succeeded - update cache with fresh response
	// Restore body again for caching
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	c.cacheResponse(ctx, cacheKey, resp)

	slog.Debug("background signature validation succeeded, cache updated",
		"method", req.Method,
		"url", req.URL.String(),
		"cache_key", cacheKey,
		"ttl", c.ttl)
}

// cachedResponseData represents a cached HTTP response
type cachedResponseData struct {
	StatusCode       int         `json:"status_code"`
	Proto            string      `json:"proto"`
	ProtoMajor       int         `json:"proto_major"`
	ProtoMinor       int         `json:"proto_minor"`
	Header           http.Header `json:"header"`
	Body             []byte      `json:"body"`
	TransferEncoding []string    `json:"transfer_encoding"`
	Close            bool        `json:"close"`
	Uncompressed     bool        `json:"uncompressed"`
	Trailer          http.Header `json:"trailer"`
}
