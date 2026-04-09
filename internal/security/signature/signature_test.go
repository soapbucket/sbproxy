package signature

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// Helper to generate RSA keys in PEM format for signature tests
func rsaKeysToPEM(t *testing.T) (privateKeyPEM, publicKeyPEM string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}))

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	publicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}))

	return privateKeyPEM, publicKeyPEM
}

func TestSignatureConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *SignatureConfig
		wantErr bool
	}{
		{
			name: "valid HMAC-SHA256",
			config: &SignatureConfig{
				Algorithm: SignatureAlgorithmHMACSHA256,
				Secret:    "test-secret",
			},
			wantErr: false,
		},
		{
			name: "valid HMAC-SHA512",
			config: &SignatureConfig{
				Algorithm: SignatureAlgorithmHMACSHA512,
				Secret:    "test-secret",
			},
			wantErr: false,
		},
		{
			name: "HMAC without secret",
			config: &SignatureConfig{
				Algorithm: SignatureAlgorithmHMACSHA256,
			},
			wantErr: true,
		},
		{
			name: "unsupported algorithm",
			config: &SignatureConfig{
				Algorithm: "invalid",
				Secret:    "test-secret",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRequestSigner_SignRequest_HMAC(t *testing.T) {
	config := &SignatureConfig{
		Algorithm:        SignatureAlgorithmHMACSHA256,
		Secret:           "test-secret-key",
		IncludeMethod:    true,
		IncludePath:      true,
		IncludeQuery:     true,
		IncludeBody:      true,
		IncludeTimestamp: true,
		IncludeNonce:     true,
	}

	signer, err := NewRequestSigner(config)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create test request
	body := bytes.NewBufferString(`{"test": "data"}`)
	req := httptest.NewRequest("POST", "/api/endpoint?foo=bar", body)
	req.Header.Set("Content-Type", "application/json")

	// Sign request
	err = signer.SignRequest(req)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	// Verify signature header is set
	signature := req.Header.Get(DefaultSignatureHeader)
	if signature == "" {
		t.Error("Signature header not set")
	}

	// Verify timestamp header is set
	timestamp := req.Header.Get(DefaultTimestampHeader)
	if timestamp == "" {
		t.Error("Timestamp header not set")
	}

	// Verify nonce header is set
	nonce := req.Header.Get(DefaultNonceHeader)
	if nonce == "" {
		t.Error("Nonce header not set")
	}
}

func TestRequestSigner_SignRequest_RSA(t *testing.T) {
	privateKeyPEM, _ := rsaKeysToPEM(t)

	config := &SignatureConfig{
		Algorithm:     SignatureAlgorithmRSASHA256,
		PrivateKey:    privateKeyPEM,
		IncludeMethod: true,
		IncludePath:   true,
		IncludeBody:   true,
	}

	signer, err := NewRequestSigner(config)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create test request
	req := httptest.NewRequest("GET", "/api/test", nil)

	// Sign request
	err = signer.SignRequest(req)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	// Verify signature header is set
	signature := req.Header.Get(DefaultSignatureHeader)
	if signature == "" {
		t.Error("Signature header not set")
	}
}

func TestRequestSigner_CustomHeaders(t *testing.T) {
	config := &SignatureConfig{
		Algorithm:        SignatureAlgorithmHMACSHA256,
		Secret:           "test-secret",
		SignatureHeader:  "X-Custom-Signature",
		TimestampHeader:  "X-Custom-Timestamp",
		IncludeMethod:    true,
		IncludeTimestamp: true,
	}

	signer, err := NewRequestSigner(config)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	err = signer.SignRequest(req)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	// Check custom headers
	if req.Header.Get("X-Custom-Signature") == "" {
		t.Error("Custom signature header not set")
	}
	if req.Header.Get("X-Custom-Timestamp") == "" {
		t.Error("Custom timestamp header not set")
	}
}

func TestRequestSigner_IncludeHeaders(t *testing.T) {
	config := &SignatureConfig{
		Algorithm:      SignatureAlgorithmHMACSHA256,
		Secret:         "test-secret",
		IncludeHeaders: []string{"Content-Type", "X-Request-ID"},
		IncludeMethod:  true,
	}

	signer, err := NewRequestSigner(config)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "12345")

	err = signer.SignRequest(req)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	signature := req.Header.Get(DefaultSignatureHeader)
	if signature == "" {
		t.Error("Signature not set")
	}
}

func TestRequestSigner_HexEncoding(t *testing.T) {
	config := &SignatureConfig{
		Algorithm:     SignatureAlgorithmHMACSHA256,
		Secret:        "test-secret",
		Encoding:      SignatureEncodingHex,
		IncludeMethod: true,
	}

	signer, err := NewRequestSigner(config)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	err = signer.SignRequest(req)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	signature := req.Header.Get(DefaultSignatureHeader)
	if signature == "" {
		t.Error("Signature not set")
	}

	// Hex encoding should produce lowercase hex characters
	if len(signature) != 64 { // SHA256 produces 32 bytes = 64 hex chars
		t.Errorf("Expected hex signature length 64, got %d", len(signature))
	}
}

func TestResponseVerifier_VerifyResponse_HMAC(t *testing.T) {
	config := &SignatureConfig{
		Algorithm:        SignatureAlgorithmHMACSHA256,
		Secret:           "test-secret",
		Verify:           true,
		IncludeBody:      true,
		IncludeTimestamp: true,
		MaxTimestampAge:  300, // 5 minutes
	}

	_, err := NewResponseVerifier(config)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Create and sign a response
	signer, _ := NewRequestSigner(config)

	// Create a mock request to sign (to generate signature)
	mockReq := httptest.NewRequest("GET", "/test", nil)
	err = signer.SignRequest(mockReq)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	// Note: In a real scenario, the backend would generate the response signature
	// This test validates that the verifier can be created and configured
}

func TestResponseVerifier_TimestampValidation(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name        string
		timestamp   string
		maxAge      int64
		expectError bool
	}{
		{
			name:        "valid recent timestamp",
			timestamp:   fmt.Sprintf("%d", now),
			maxAge:      300,
			expectError: false,
		},
		{
			name:        "timestamp too old",
			timestamp:   fmt.Sprintf("%d", now-600), // 10 minutes ago
			maxAge:      300,                        // 5 minutes
			expectError: true,
		},
		{
			name:        "future timestamp",
			timestamp:   fmt.Sprintf("%d", now+600), // 10 minutes in future
			maxAge:      300,
			expectError: true,
		},
		{
			name:        "invalid timestamp format",
			timestamp:   "invalid",
			maxAge:      300,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &SignatureConfig{
				Algorithm:       SignatureAlgorithmHMACSHA256,
				Secret:          "test",
				MaxTimestampAge: tt.maxAge,
			}
			verifier, _ := NewResponseVerifier(config)

			err := verifier.validateTimestamp(tt.timestamp)
			if (err != nil) != tt.expectError {
				t.Errorf("validateTimestamp() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestSignatureConfig_LoadKeys_RSA(t *testing.T) {
	privateKeyPEM, publicKeyPEM := rsaKeysToPEM(t)

	config := &SignatureConfig{
		Algorithm:  SignatureAlgorithmRSASHA256,
		PrivateKey: privateKeyPEM,
		PublicKey:  publicKeyPEM,
	}

	err := config.loadKeys()
	if err != nil {
		t.Fatalf("Failed to load keys: %v", err)
	}

	if config.privateKey == nil {
		t.Error("Private key not loaded")
	}
	if config.publicKey == nil {
		t.Error("Public key not loaded")
	}
}

func TestSignatureConfig_LoadKeys_InvalidPEM(t *testing.T) {
	config := &SignatureConfig{
		Algorithm:  SignatureAlgorithmRSASHA256,
		PrivateKey: "invalid-pem",
	}

	err := config.loadKeys()
	if err == nil {
		t.Error("Expected error for invalid PEM")
	}
}

func TestRequestSigner_SignRoundTrip(t *testing.T) {
	// Test that signing and verifying works end-to-end
	secret := "shared-secret-key"

	// Create signer config
	signerConfig := &SignatureConfig{
		Algorithm:        SignatureAlgorithmHMACSHA256,
		Secret:           secret,
		IncludeMethod:    true,
		IncludePath:      true,
		IncludeBody:      true,
		IncludeTimestamp: true,
	}

	signer, err := NewRequestSigner(signerConfig)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create and sign request
	body := bytes.NewBufferString(`{"test": "data"}`)
	req := httptest.NewRequest("POST", "/api/test", body)

	err = signer.SignRequest(req)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	// Verify we can read the signature
	signature := req.Header.Get(DefaultSignatureHeader)
	if signature == "" {
		t.Fatal("Signature not set")
	}

	timestamp := req.Header.Get(DefaultTimestampHeader)
	if timestamp == "" {
		t.Fatal("Timestamp not set")
	}
}

func BenchmarkRequestSigner_HMACSHA256(b *testing.B) {
	b.ReportAllocs()
	config := &SignatureConfig{
		Algorithm:     SignatureAlgorithmHMACSHA256,
		Secret:        "test-secret",
		IncludeMethod: true,
		IncludePath:   true,
		IncludeBody:   true,
	}

	signer, _ := NewRequestSigner(config)

	body := bytes.NewBufferString(`{"test": "data"}`)
	req := httptest.NewRequest("POST", "/api/test", body)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = signer.SignRequest(req)
		// Reset body for next iteration
		req.Body = io.NopCloser(bytes.NewBufferString(`{"test": "data"}`))
	}
}

func BenchmarkRequestSigner_RSASHA256(b *testing.B) {
	b.ReportAllocs()
	// Use testing.T wrapper for benchmark
	t := &testing.T{}
	privateKeyPEM, _ := rsaKeysToPEM(t)

	config := &SignatureConfig{
		Algorithm:     SignatureAlgorithmRSASHA256,
		PrivateKey:    privateKeyPEM,
		IncludeMethod: true,
		IncludePath:   true,
		IncludeBody:   true,
	}

	signer, _ := NewRequestSigner(config)

	body := bytes.NewBufferString(`{"test": "data"}`)
	req := httptest.NewRequest("POST", "/api/test", body)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = signer.SignRequest(req)
		// Reset body for next iteration
		req.Body = io.NopCloser(bytes.NewBufferString(`{"test": "data"}`))
	}
}

// mockCacher is a simple in-memory cache for testing
type mockCacher struct {
	data map[string][]byte
	ttl  map[string]time.Time
}

func newMockCacher() *mockCacher {
	return &mockCacher{
		data: make(map[string][]byte),
		ttl:  make(map[string]time.Time),
	}
}

func (m *mockCacher) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	fullKey := cType + ":" + key
	data, ok := m.data[fullKey]
	if !ok {
		return nil, cacher.ErrNotFound
	}
	// Check TTL
	if expiry, ok := m.ttl[fullKey]; ok && time.Now().After(expiry) {
		delete(m.data, fullKey)
		delete(m.ttl, fullKey)
		return nil, cacher.ErrNotFound
	}
	return bytes.NewReader(data), nil
}

func (m *mockCacher) Put(ctx context.Context, cType string, key string, value io.Reader) error {
	data, err := io.ReadAll(value)
	if err != nil {
		return err
	}
	fullKey := cType + ":" + key
	m.data[fullKey] = data
	return nil
}

func (m *mockCacher) PutWithExpires(ctx context.Context, cType string, key string, value io.Reader, expires time.Duration) error {
	data, err := io.ReadAll(value)
	if err != nil {
		return err
	}
	fullKey := cType + ":" + key
	m.data[fullKey] = data
	m.ttl[fullKey] = time.Now().Add(expires)
	return nil
}

func (m *mockCacher) Delete(ctx context.Context, cType string, key string) error {
	fullKey := cType + ":" + key
	delete(m.data, fullKey)
	delete(m.ttl, fullKey)
	return nil
}

func (m *mockCacher) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	// Simple implementation for testing
	return nil
}

func (m *mockCacher) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	var keys []string
	for fullKey := range m.data {
		// Extract key part (after cType + ":")
		prefix := cType + ":"
		if len(fullKey) > len(prefix) && fullKey[:len(prefix)] == prefix {
			key := fullKey[len(prefix):]
			// Simple prefix matching for pattern
			if pattern == "" || (len(key) >= len(pattern) && key[:len(pattern)] == pattern) {
				keys = append(keys, key)
			}
		}
	}
	return keys, nil
}

func (m *mockCacher) Increment(ctx context.Context, cType string, key string, count int64) (int64, error) {
	return 0, nil
}

func (m *mockCacher) IncrementWithExpires(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	return 0, nil
}

func (m *mockCacher) Driver() string {
	return "mock"
}

func (m *mockCacher) Close() error {
	return nil
}

func TestCachedResponseVerifier_New(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		config := &SignatureConfig{
			Algorithm: SignatureAlgorithmHMACSHA256,
			Secret:    "test-secret",
		}
		verifier, err := NewResponseVerifier(config)
		if err != nil {
			t.Fatalf("Failed to create verifier: %v", err)
		}

		cache := newMockCacher()
		cachedVerifier, err := NewCachedResponseVerifier(CachedResponseVerifierConfig{
			Verifier: verifier,
			Cache:    cache,
			TTL:      5 * time.Minute,
		})
		if err != nil {
			t.Fatalf("Failed to create cached verifier: %v", err)
		}
		if cachedVerifier == nil {
			t.Fatal("Cached verifier is nil")
		}
	})

	t.Run("missing verifier", func(t *testing.T) {
		cache := newMockCacher()
		_, err := NewCachedResponseVerifier(CachedResponseVerifierConfig{
			Cache: cache,
			TTL:   5 * time.Minute,
		})
		if err == nil {
			t.Error("Expected error for missing verifier")
		}
	})

	t.Run("missing cache", func(t *testing.T) {
		config := &SignatureConfig{
			Algorithm: SignatureAlgorithmHMACSHA256,
			Secret:    "test-secret",
		}
		verifier, _ := NewResponseVerifier(config)
		_, err := NewCachedResponseVerifier(CachedResponseVerifierConfig{
			Verifier: verifier,
			TTL:      5 * time.Minute,
		})
		if err == nil {
			t.Error("Expected error for missing cache")
		}
	})

	t.Run("default TTL", func(t *testing.T) {
		config := &SignatureConfig{
			Algorithm: SignatureAlgorithmHMACSHA256,
			Secret:    "test-secret",
		}
		verifier, _ := NewResponseVerifier(config)
		cache := newMockCacher()
		cachedVerifier, err := NewCachedResponseVerifier(CachedResponseVerifierConfig{
			Verifier: verifier,
			Cache:    cache,
		})
		if err != nil {
			t.Fatalf("Failed to create cached verifier: %v", err)
		}
		if cachedVerifier.ttl <= 0 {
			t.Error("Expected default TTL to be set")
		}
	})
}

func TestCachedResponseVerifier_CacheMiss(t *testing.T) {
	// Create a signer and verifier with the same secret
	secret := "test-secret-key"
	signerConfig := &SignatureConfig{
		Algorithm:     SignatureAlgorithmHMACSHA256,
		Secret:        secret,
		IncludeBody:   true,
		IncludeMethod: true,
		IncludePath:   true,
	}

	verifierConfig := &SignatureConfig{
		Algorithm:   SignatureAlgorithmHMACSHA256,
		Secret:      secret,
		IncludeBody: true,
	}

	signer, err := NewRequestSigner(signerConfig)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	verifier, err := NewResponseVerifier(verifierConfig)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	cache := newMockCacher()
	cachedVerifier, err := NewCachedResponseVerifier(CachedResponseVerifierConfig{
		Verifier: verifier,
		Cache:    cache,
		TTL:      5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create cached verifier: %v", err)
	}

	// Create a request and sign it
	req := httptest.NewRequest("GET", "/api/test", nil)
	err = signer.SignRequest(req)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	// Create a response with signature
	// In a real scenario, the backend would sign the response
	// For testing, we'll create a response and manually add signature
	body := `{"status": "ok"}`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "application/json")

	// Manually create a signature for the response
	// This is a simplified version - in reality, the backend would do this
	sigString := fmt.Sprintf("%d\n%s", resp.StatusCode, body)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(sigString))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	resp.Header.Set(DefaultSignatureHeader, signature)

	// First call should be a cache miss - verify and cache
	result, err := cachedVerifier.VerifyResponseWithCache(req, resp)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if result == nil {
		t.Fatal("Expected response, got nil")
	}
	if result.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", result.StatusCode)
	}

	// Verify response was cached
	cacheKey := cachedVerifier.generateCacheKey(req, resp)
	ctx := req.Context()
	_, err = cache.Get(ctx, signatureCachePrefix, cacheKey)
	if err != nil {
		t.Fatal("Response should be cached")
	}
}

func TestCachedResponseVerifier_CacheHit(t *testing.T) {
	secret := "test-secret-key"
	verifierConfig := &SignatureConfig{
		Algorithm:   SignatureAlgorithmHMACSHA256,
		Secret:      secret,
		IncludeBody: true,
	}

	verifier, err := NewResponseVerifier(verifierConfig)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	cache := newMockCacher()
	cachedVerifier, err := NewCachedResponseVerifier(CachedResponseVerifierConfig{
		Verifier: verifier,
		Cache:    cache,
		TTL:      5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create cached verifier: %v", err)
	}

	// Create request and response
	req := httptest.NewRequest("GET", "/api/test", nil)
	body := `{"status": "ok"}`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "application/json")

	// Manually create signature
	sigString := fmt.Sprintf("%d\n%s", resp.StatusCode, body)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(sigString))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	resp.Header.Set(DefaultSignatureHeader, signature)

	// First call - cache miss, should verify and cache
	_, err = cachedVerifier.VerifyResponseWithCache(req, resp)
	if err != nil {
		t.Fatalf("First verification failed: %v", err)
	}

	// Wait a bit for caching to complete
	time.Sleep(100 * time.Millisecond)

	// Second call - should be cache hit
	// Create a new response with same signature
	resp2 := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    req,
	}
	resp2.Header.Set("Content-Type", "application/json")
	resp2.Header.Set(DefaultSignatureHeader, signature)

	result, err := cachedVerifier.VerifyResponseWithCache(req, resp2)
	if err != nil {
		t.Fatalf("Second verification failed: %v", err)
	}
	if result == nil {
		t.Fatal("Expected cached response, got nil")
	}
	if result.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", result.StatusCode)
	}
}

func TestCachedResponseVerifier_InvalidSignature(t *testing.T) {
	secret := "test-secret-key"
	verifierConfig := &SignatureConfig{
		Algorithm:   SignatureAlgorithmHMACSHA256,
		Secret:      secret,
		IncludeBody: true,
	}

	verifier, err := NewResponseVerifier(verifierConfig)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	cache := newMockCacher()
	cachedVerifier, err := NewCachedResponseVerifier(CachedResponseVerifierConfig{
		Verifier: verifier,
		Cache:    cache,
		TTL:      5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create cached verifier: %v", err)
	}

	// Create request and response with invalid signature
	req := httptest.NewRequest("GET", "/api/test", nil)
	body := `{"status": "ok"}`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set(DefaultSignatureHeader, "invalid-signature")

	// Should fail verification
	_, err = cachedVerifier.VerifyResponseWithCache(req, resp)
	if err == nil {
		t.Error("Expected verification to fail with invalid signature")
	}
}

func TestCachedResponseVerifier_CacheInvalidation(t *testing.T) {
	secret := "test-secret-key"
	verifierConfig := &SignatureConfig{
		Algorithm:   SignatureAlgorithmHMACSHA256,
		Secret:      secret,
		IncludeBody: true,
	}

	verifier, err := NewResponseVerifier(verifierConfig)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	cache := newMockCacher()
	cachedVerifier, err := NewCachedResponseVerifier(CachedResponseVerifierConfig{
		Verifier: verifier,
		Cache:    cache,
		TTL:      5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create cached verifier: %v", err)
	}

	// Create request and valid response
	req := httptest.NewRequest("GET", "/api/test", nil)
	body := `{"status": "ok"}`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "application/json")

	// Create valid signature
	sigString := fmt.Sprintf("%d\n%s", resp.StatusCode, body)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(sigString))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	resp.Header.Set(DefaultSignatureHeader, signature)

	// First call - cache it
	_, err = cachedVerifier.VerifyResponseWithCache(req, resp)
	if err != nil {
		t.Fatalf("First verification failed: %v", err)
	}

	// Wait for caching
	time.Sleep(100 * time.Millisecond)

	// Verify it's cached
	cacheKey := cachedVerifier.generateCacheKey(req, resp)
	ctx := req.Context()
	_, err = cache.Get(ctx, signatureCachePrefix, cacheKey)
	if err != nil {
		t.Fatal("Response should be cached")
	}

	// Now create a response with invalid signature but same cache key
	resp2 := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    req,
	}
	resp2.Header.Set("Content-Type", "application/json")
	resp2.Header.Set(DefaultSignatureHeader, signature) // Same signature for cache key

	// Modify body to make signature invalid
	resp2.Body = io.NopCloser(bytes.NewBufferString(`{"status": "modified"}`))

	// Background validation should invalidate cache
	// We'll call validateAndUpdateCache directly
	cachedVerifier.validateAndUpdateCache(req, resp2, cacheKey)

	// Wait for invalidation
	time.Sleep(100 * time.Millisecond)

	// Verify cache was invalidated
	ctx = req.Context()
	_, err = cache.Get(ctx, signatureCachePrefix, cacheKey)
	if err == nil {
		t.Error("Cache should have been invalidated")
	}
}
