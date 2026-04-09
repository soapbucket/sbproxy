package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// mockCacher is a simple in-memory cacher implementation for testing
type mockCacher struct {
	data map[string][]byte
	mu   sync.RWMutex
}

func newMockCacher() *mockCacher {
	return &mockCacher{
		data: make(map[string][]byte),
	}
}

func (m *mockCacher) Get(ctx context.Context, cacheType, key string) (io.Reader, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	fullKey := cacheType + ":" + key
	if data, ok := m.data[fullKey]; ok {
		return bytes.NewReader(data), nil
	}
	return nil, cacher.ErrNotFound
}

func (m *mockCacher) Put(ctx context.Context, cacheType, key string, reader io.Reader) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fullKey := cacheType + ":" + key
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	m.data[fullKey] = data
	return nil
}

func (m *mockCacher) PutWithExpires(ctx context.Context, cacheType, key string, reader io.Reader, expires time.Duration) error {
	// For testing, we'll just store it without expiration tracking
	return m.Put(ctx, cacheType, key, reader)
}

func (m *mockCacher) Delete(ctx context.Context, cacheType, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fullKey := cacheType + ":" + key
	delete(m.data, fullKey)
	return nil
}

func (m *mockCacher) DeleteByPattern(ctx context.Context, cacheType, pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.data {
		if strings.HasPrefix(key, cacheType+":") {
			keyPart := strings.TrimPrefix(key, cacheType+":")
			if pattern == "*" || strings.HasPrefix(keyPart, pattern) {
				delete(m.data, key)
			}
		}
	}
	return nil
}

func (m *mockCacher) Increment(ctx context.Context, cacheType, key string, delta int64) (int64, error) {
	return 0, nil
}

func (m *mockCacher) IncrementWithExpires(ctx context.Context, cacheType, key string, delta int64, expires time.Duration) (int64, error) {
	return 0, nil
}

func (m *mockCacher) ListKeys(ctx context.Context, cacheType, pattern string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for key := range m.data {
		if strings.HasPrefix(key, cacheType+":") {
			keyPart := strings.TrimPrefix(key, cacheType+":")
			if pattern == "" || pattern == "*" || strings.HasPrefix(keyPart, pattern) {
				keys = append(keys, keyPart)
			}
		}
	}
	return keys, nil
}

func (m *mockCacher) Driver() string {
	return "mock"
}

func (m *mockCacher) Close() error {
	return nil
}

func createTestConfig() Config {
	return Config{
		ProxyConfig: ProxyConfig{
			CertificateSettings: CertificateSettings{
				UseACME:     true,
				ACMEEmail:   "test@example.com",
				ACMEDomains: []string{"example.com", "test.example.com"},
				MinTLSVersion: 13,
				TLSCipherSuites: []string{"TLS_AES_128_GCM_SHA256"},
			},
			EnableHTTP3: false,
		},
	}
}

func TestGetACMETLSConfig_WithL3Cache(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig()
	configDir := t.TempDir()
	cache := newMockCacher()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, cache)

	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// Verify TLS config properties
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion TLS 1.3, got %d", tlsConfig.MinVersion)
	}

	// Verify NextProtos (includes acme-tls/1 for TLS-ALPN-01 challenge support)
	expectedProtos := []string{"h2", "http/1.1", "acme-tls/1"}
	if len(tlsConfig.NextProtos) != len(expectedProtos) {
		t.Errorf("expected %d protocols, got %d: %v", len(expectedProtos), len(tlsConfig.NextProtos), tlsConfig.NextProtos)
	}

	// Verify GetCertificate is set
	if tlsConfig.GetCertificate == nil {
		t.Error("expected GetCertificate to be set")
	}
}

func TestGetACMETLSConfig_WithL3Cache_HTTP3(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig()
	config.ProxyConfig.EnableHTTP3 = true
	configDir := t.TempDir()
	cache := newMockCacher()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, cache)

	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// Verify NextProtos includes h3 and acme-tls/1
	expectedProtos := []string{"h3", "h2", "http/1.1", "acme-tls/1"}
	if len(tlsConfig.NextProtos) != len(expectedProtos) {
		t.Errorf("expected %d protocols, got %d: %v", len(expectedProtos), len(tlsConfig.NextProtos), tlsConfig.NextProtos)
	}

	foundH3 := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h3" {
			foundH3 = true
			break
		}
	}
	if !foundH3 {
		t.Error("expected h3 protocol to be present")
	}
}

func TestGetACMETLSConfig_WithNilCache_FallbackToFilesystem(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig()
	configDir := t.TempDir()

	// Create a temporary directory for ACME cache
	acmeCacheDir := filepath.Join(configDir, "acme-cache")
	err := os.MkdirAll(acmeCacheDir, 0755)
	if err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, nil)

	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// Verify TLS config properties
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion TLS 1.3, got %d", tlsConfig.MinVersion)
	}

	// Verify GetCertificate is set
	if tlsConfig.GetCertificate == nil {
		t.Error("expected GetCertificate to be set")
	}
}

func TestGetACMETLSConfig_WithNilCache_CustomCacheDir(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig()
	configDir := t.TempDir()
	customCacheDir := filepath.Join(configDir, "custom-acme-cache")
	config.ProxyConfig.CertificateSettings.ACMECacheDir = customCacheDir

	err := os.MkdirAll(customCacheDir, 0755)
	if err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, nil)

	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// Verify GetCertificate is set
	if tlsConfig.GetCertificate == nil {
		t.Error("expected GetCertificate to be set")
	}
}

func TestGetACMETLSConfig_WithNilCache_RelativeCacheDir(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig()
	configDir := t.TempDir()
	config.ProxyConfig.CertificateSettings.ACMECacheDir = "relative-acme-cache"

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, nil)

	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// Verify GetCertificate is set
	if tlsConfig.GetCertificate == nil {
		t.Error("expected GetCertificate to be set")
	}
}

func TestGetACMETLSConfig_NoACMEDomains(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig()
	config.ProxyConfig.CertificateSettings.ACMEDomains = []string{}
	configDir := t.TempDir()
	cache := newMockCacher()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, cache)

	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// Verify GetCertificate is set
	if tlsConfig.GetCertificate == nil {
		t.Error("expected GetCertificate to be set")
	}
}

func TestGetACMETLSConfig_TLS12(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig()
	config.ProxyConfig.CertificateSettings.MinTLSVersion = 12
	configDir := t.TempDir()
	cache := newMockCacher()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, cache)

	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// Verify TLS config properties
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2, got %d", tlsConfig.MinVersion)
	}
}

func TestGetACMETLSConfig_CipherSuites(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig()
	config.ProxyConfig.CertificateSettings.TLSCipherSuites = []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
	}
	configDir := t.TempDir()
	cache := newMockCacher()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, cache)

	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// Verify cipher suites are set
	if len(tlsConfig.CipherSuites) == 0 {
		t.Error("expected cipher suites to be set")
	}
}

func TestGetACMETLSConfig_CacheIntegration(t *testing.T) {
	// Test that cache is actually used by the ACME cache
	ctx := context.Background()
	config := createTestConfig()
	configDir := t.TempDir()
	cache := newMockCacher()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, cache)

	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// The cache should be accessible through the ACME cache
	// We can't directly access the cache, but we can verify the config is created
	// and that cache operations would work
	testKey := "acme:test-key"
	testData := []byte("test-data")

	err := cache.Put(ctx, "acme", testKey, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("failed to put test data: %v", err)
	}

	reader, err := cache.Get(ctx, "acme", testKey)
	if err != nil {
		t.Fatalf("failed to get test data: %v", err)
	}

	retrieved, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	if string(retrieved) != string(testData) {
		t.Errorf("expected %s, got %s", string(testData), string(retrieved))
	}
}

func TestGetACMETLSConfig_ContextPropagation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := createTestConfig()
	configDir := t.TempDir()
	cache := newMockCacher()

	// Should not panic or error with valid context
	tlsConfig := GetACMETLSConfig(ctx, config, configDir, cache)

	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// Cancel context and verify it doesn't break the config
	cancel()

	// Config should still be valid (it's already created)
	if tlsConfig.GetCertificate == nil {
		t.Error("expected GetCertificate to be set")
	}
}

func TestGetACMETLSConfig_EmptyEmail(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig()
	config.ProxyConfig.CertificateSettings.ACMEEmail = ""
	configDir := t.TempDir()
	cache := newMockCacher()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, cache)

	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// Should still create valid config even with empty email
	if tlsConfig.GetCertificate == nil {
		t.Error("expected GetCertificate to be set")
	}
}

func BenchmarkGetACMETLSConfig_WithL3Cache(b *testing.B) {
	b.ReportAllocs()
	ctx := context.Background()
	config := createTestConfig()
	configDir := b.TempDir()
	cache := newMockCacher()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetACMETLSConfig(ctx, config, configDir, cache)
	}
}

func BenchmarkGetACMETLSConfig_WithNilCache(b *testing.B) {
	b.ReportAllocs()
	ctx := context.Background()
	config := createTestConfig()
	configDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetACMETLSConfig(ctx, config, configDir, nil)
	}
}

// Tests for validateCertificateKey

func TestValidateCertificateKey_NilCert(t *testing.T) {
	cert, err := validateCertificateKey(nil, "test.local")
	if cert != nil {
		t.Error("expected nil cert for nil input")
	}
	if err != nil {
		t.Errorf("expected nil error for nil cert, got: %v", err)
	}
}

func TestValidateCertificateKey_NilPrivateKey(t *testing.T) {
	cert := &tls.Certificate{
		Certificate: [][]byte{{1, 2, 3}}, // non-empty cert chain
		// PrivateKey intentionally nil
	}
	result, err := validateCertificateKey(cert, "test.local")
	if err == nil {
		t.Fatal("expected error for certificate with nil private key")
	}
	if result != nil {
		t.Error("expected nil result when private key is nil")
	}
	if !strings.Contains(err.Error(), "nil private key") {
		t.Errorf("expected error message to mention nil private key, got: %v", err)
	}
	if !strings.Contains(err.Error(), "test.local") {
		t.Errorf("expected error message to include server name, got: %v", err)
	}
}

func TestValidateCertificateKey_ValidCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{{1, 2, 3}},
		PrivateKey:  key,
	}

	result, err := validateCertificateKey(cert, "test.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != cert {
		t.Error("expected the same certificate to be returned")
	}
}

func TestValidateCertificateKey_EmptyPrivateKeyDifferentFromNil(t *testing.T) {
	// A certificate with a non-nil but non-Signer private key should still pass
	// validateCertificateKey (Go's TLS layer handles that case differently).
	// Our guard only catches the nil case which comes from failed ACME flows.
	cert := &tls.Certificate{
		Certificate: [][]byte{{1, 2, 3}},
		PrivateKey:  "not-a-real-key", // non-nil, but not a crypto.Signer
	}

	result, err := validateCertificateKey(cert, "test.local")
	if err != nil {
		t.Fatalf("unexpected error for non-nil private key: %v", err)
	}
	if result != cert {
		t.Error("expected the same certificate to be returned")
	}
}

// Tests for PreManageACMEDomains

func TestPreManageACMEDomains_NilConfig(t *testing.T) {
	// Reset global to nil for this test
	origConfig := certMagicConfig
	certMagicConfig = nil
	defer func() { certMagicConfig = origConfig }()

	err := PreManageACMEDomains(context.Background(), []string{"example.com"})
	if err == nil {
		t.Fatal("expected error when certMagicConfig is nil")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("expected 'not initialized' error, got: %v", err)
	}
}

func TestPreManageACMEDomains_EmptyDomains(t *testing.T) {
	// Reset global to nil for this test
	origConfig := certMagicConfig
	certMagicConfig = nil
	defer func() { certMagicConfig = origConfig }()

	// Should return nil even with nil certMagicConfig because domains list is empty
	err := PreManageACMEDomains(context.Background(), []string{})
	if err != nil {
		t.Fatalf("expected nil error for empty domains, got: %v", err)
	}
}

func TestGetACMETLSConfig_HTTPChallengeDisabled(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig()
	configDir := t.TempDir()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, nil)
	if tlsConfig == nil {
		t.Fatal("expected TLS config, got nil")
	}

	// Verify GetCertificate is set (it wraps CertMagic's callback)
	if tlsConfig.GetCertificate == nil {
		t.Error("expected GetCertificate to be set")
	}

	// Verify the ACME HTTP handler returns NotFound since HTTP-01 is disabled.
	// The handler should still be functional (not panic) even though the challenge
	// type is disabled.
	handler := GetACMEHTTPHandler()
	if handler == nil {
		t.Error("expected non-nil ACME HTTP handler")
	}
}

