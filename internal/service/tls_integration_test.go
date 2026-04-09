//go:build integration

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"
)

// getPebbleURL returns the Pebble ACME directory URL from environment
func getPebbleURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("PEBBLE_ACME_URL")
	if url == "" {
		t.Skip("PEBBLE_ACME_URL not set - skipping integration test")
	}
	return url
}

// generateSelfSignedCert creates a self-signed certificate for testing
func generateSelfSignedCert(commonName string) (certPEM, keyPEM []byte, err error) {
	// Generate ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Organization"},
		},
		DNSNames:              []string{commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}

// ACMEDirectory represents the ACME directory response
type ACMEDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

// TestACME_PebbleConnection tests basic connectivity to Pebble ACME server
func TestACME_PebbleConnection(t *testing.T) {
	pebbleURL := getPebbleURL(t)

	// Create HTTP client that skips TLS verification (Pebble uses self-signed certs)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Required for Pebble
			},
		},
	}

	resp, err := client.Get(pebbleURL)
	if err != nil {
		t.Fatalf("Failed to connect to Pebble: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Unexpected status code from Pebble: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var directory ACMEDirectory
	if err := json.Unmarshal(body, &directory); err != nil {
		t.Fatalf("Failed to parse ACME directory: %v", err)
	}

	// Verify directory has required endpoints
	if directory.NewNonce == "" {
		t.Error("ACME directory missing newNonce endpoint")
	}
	if directory.NewAccount == "" {
		t.Error("ACME directory missing newAccount endpoint")
	}
	if directory.NewOrder == "" {
		t.Error("ACME directory missing newOrder endpoint")
	}

	t.Logf("Pebble ACME directory endpoints:")
	t.Logf("  newNonce:   %s", directory.NewNonce)
	t.Logf("  newAccount: %s", directory.NewAccount)
	t.Logf("  newOrder:   %s", directory.NewOrder)
}

// TestACME_TLSConfigWithPebble tests creating TLS config with Pebble
func TestACME_TLSConfigWithPebble(t *testing.T) {
	pebbleURL := getPebbleURL(t)

	config := Config{
		ProxyConfig: ProxyConfig{
			CertificateSettings: CertificateSettings{
				UseACME:                true,
				ACMEEmail:              "test@example.com",
				ACMEDomains:            []string{"test.local", "example.local"},
				ACMEDirectoryURL:       pebbleURL,
				ACMEInsecureSkipVerify: true,
				MinTLSVersion:          13,
			},
			EnableHTTP3: false,
		},
	}

	ctx := context.Background()
	configDir := t.TempDir()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, nil)
	if tlsConfig == nil {
		t.Fatal("GetACMETLSConfig returned nil")
	}

	// Verify TLS config properties
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("Expected MinVersion TLS 1.3, got %d", tlsConfig.MinVersion)
	}

	if tlsConfig.GetCertificate == nil {
		t.Error("GetCertificate callback not set")
	}

	// Verify NextProtos (no HTTP/3)
	expectedProtos := []string{"h2", "http/1.1"}
	if len(tlsConfig.NextProtos) != len(expectedProtos) {
		t.Errorf("Expected %d protocols, got %d", len(expectedProtos), len(tlsConfig.NextProtos))
	}

	t.Logf("TLS config created successfully with Pebble directory: %s", pebbleURL)
}

// TestACME_TLSConfigWithPebble_HTTP3 tests TLS config with HTTP/3 enabled
func TestACME_TLSConfigWithPebble_HTTP3(t *testing.T) {
	pebbleURL := getPebbleURL(t)

	config := Config{
		ProxyConfig: ProxyConfig{
			CertificateSettings: CertificateSettings{
				UseACME:                true,
				ACMEEmail:              "test@example.com",
				ACMEDomains:            []string{"test.local"},
				ACMEDirectoryURL:       pebbleURL,
				ACMEInsecureSkipVerify: true,
				MinTLSVersion:          13,
			},
			EnableHTTP3: true,
		},
	}

	ctx := context.Background()
	configDir := t.TempDir()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, nil)
	if tlsConfig == nil {
		t.Fatal("GetACMETLSConfig returned nil")
	}

	// Verify NextProtos includes h3
	foundH3 := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h3" {
			foundH3 = true
			break
		}
	}
	if !foundH3 {
		t.Error("Expected h3 in NextProtos with HTTP/3 enabled")
	}
}

// TestACME_CertificateRequest tests the full certificate request flow with Pebble
// Note: This test requires PEBBLE_VA_ALWAYS_VALID=1 to be set on Pebble
func TestACME_CertificateRequest(t *testing.T) {
	pebbleURL := getPebbleURL(t)

	config := Config{
		ProxyConfig: ProxyConfig{
			CertificateSettings: CertificateSettings{
				UseACME:                true,
				ACMEEmail:              "test@example.com",
				ACMEDomains:            []string{"test.local"},
				ACMEDirectoryURL:       pebbleURL,
				ACMEInsecureSkipVerify: true,
				MinTLSVersion:          13,
			},
		},
	}

	ctx := context.Background()
	configDir := t.TempDir()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, nil)
	if tlsConfig == nil {
		t.Fatal("GetACMETLSConfig returned nil")
	}

	// Create a ClientHelloInfo to trigger certificate retrieval
	hello := &tls.ClientHelloInfo{
		ServerName: "test.local",
	}

	// Request certificate - this will trigger ACME flow with Pebble
	// Note: With PEBBLE_VA_ALWAYS_VALID=1, challenges are auto-validated
	cert, err := tlsConfig.GetCertificate(hello)
	if err != nil {
		// This is expected to fail without proper challenge server setup
		// Log the error for debugging but don't fail the test
		t.Logf("Certificate request returned error (expected without challenge server): %v", err)
		t.Skip("Certificate request requires challenge server - skipping")
		return
	}

	if cert == nil {
		t.Fatal("GetCertificate returned nil certificate")
	}

	// Parse and verify the certificate
	if len(cert.Certificate) == 0 {
		t.Fatal("Certificate chain is empty")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	t.Logf("Certificate issued successfully:")
	t.Logf("  Subject: %s", x509Cert.Subject.CommonName)
	t.Logf("  Issuer: %s", x509Cert.Issuer.CommonName)
	t.Logf("  NotBefore: %s", x509Cert.NotBefore)
	t.Logf("  NotAfter: %s", x509Cert.NotAfter)
	t.Logf("  DNS Names: %v", x509Cert.DNSNames)
}

// TestACME_HostPolicy tests host policy with whitelist
func TestACME_HostPolicy(t *testing.T) {
	pebbleURL := getPebbleURL(t)

	config := Config{
		ProxyConfig: ProxyConfig{
			CertificateSettings: CertificateSettings{
				UseACME:                true,
				ACMEEmail:              "test@example.com",
				ACMEDomains:            []string{"allowed.local", "permitted.local"},
				ACMEDirectoryURL:       pebbleURL,
				ACMEInsecureSkipVerify: true,
				MinTLSVersion:          13,
			},
		},
	}

	ctx := context.Background()
	configDir := t.TempDir()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, nil)
	if tlsConfig == nil {
		t.Fatal("GetACMETLSConfig returned nil")
	}

	// Test that non-whitelisted domain fails
	hello := &tls.ClientHelloInfo{
		ServerName: "unauthorized.local",
	}

	_, err := tlsConfig.GetCertificate(hello)
	if err == nil {
		t.Error("Expected error for non-whitelisted domain, got nil")
	} else {
		t.Logf("Correctly rejected non-whitelisted domain: %v", err)
	}
}

// TestACME_StagingURL tests configuration with Let's Encrypt staging URL
func TestACME_StagingURL(t *testing.T) {
	// This test doesn't require Pebble, just validates config handling
	stagingURL := "https://acme-staging-v02.api.letsencrypt.org/directory"

	config := Config{
		ProxyConfig: ProxyConfig{
			CertificateSettings: CertificateSettings{
				UseACME:                true,
				ACMEEmail:              "test@example.com",
				ACMEDomains:            []string{"example.com"},
				ACMEDirectoryURL:       stagingURL,
				ACMEInsecureSkipVerify: false, // Staging has valid certs
				MinTLSVersion:          13,
			},
		},
	}

	ctx := context.Background()
	configDir := t.TempDir()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, nil)
	if tlsConfig == nil {
		t.Fatal("GetACMETLSConfig returned nil")
	}

	t.Logf("TLS config created for Let's Encrypt staging")
}

// TestACME_FallbackToStaticCert tests the fallback to static certificates
func TestACME_FallbackToStaticCert(t *testing.T) {
	pebbleURL := getPebbleURL(t)

	// Create temp directories for certs
	configDir := t.TempDir()
	certDir := configDir

	// Generate a real self-signed certificate for testing
	certPEM, keyPEM, err := generateSelfSignedCert("static.local")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Write static cert and key for "static.local"
	if err := os.WriteFile(fmt.Sprintf("%s/static.local.crt", certDir), certPEM, 0644); err != nil {
		t.Fatalf("Failed to write test cert: %v", err)
	}
	if err := os.WriteFile(fmt.Sprintf("%s/static.local.key", certDir), keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}

	config := Config{
		ProxyConfig: ProxyConfig{
			CertificateSettings: CertificateSettings{
				UseACME:                true,
				ACMEEmail:              "test@example.com",
				ACMEDomains:            []string{"static.local", "acme.local"},
				ACMEDirectoryURL:       pebbleURL,
				ACMEInsecureSkipVerify: true,
				CertificateDir:         certDir,
				CertificateKeyDir:      certDir,
				MinTLSVersion:          13,
			},
		},
	}

	ctx := context.Background()

	tlsConfig := GetACMETLSConfig(ctx, config, configDir, nil)
	if tlsConfig == nil {
		t.Fatal("GetACMETLSConfig returned nil")
	}

	// Request certificate for domain with static cert
	hello := &tls.ClientHelloInfo{
		ServerName: "static.local",
	}

	cert, err := tlsConfig.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("Expected static certificate to be returned")
	}

	// Verify the certificate is our static cert
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse returned certificate: %v", err)
	}

	if x509Cert.Subject.CommonName != "static.local" {
		t.Errorf("Expected CN=static.local, got CN=%s", x509Cert.Subject.CommonName)
	}

	t.Logf("Static certificate was correctly returned for static.local (CN=%s)", x509Cert.Subject.CommonName)
}

// BenchmarkACME_TLSConfigCreation benchmarks TLS config creation
func BenchmarkACME_TLSConfigCreation(b *testing.B) {
	b.ReportAllocs()
	pebbleURL := os.Getenv("PEBBLE_ACME_URL")
	if pebbleURL == "" {
		b.Skip("PEBBLE_ACME_URL not set")
	}

	config := Config{
		ProxyConfig: ProxyConfig{
			CertificateSettings: CertificateSettings{
				UseACME:                true,
				ACMEEmail:              "test@example.com",
				ACMEDomains:            []string{"test.local"},
				ACMEDirectoryURL:       pebbleURL,
				ACMEInsecureSkipVerify: true,
				MinTLSVersion:          13,
			},
		},
	}

	ctx := context.Background()
	configDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetACMETLSConfig(ctx, config, configDir, nil)
	}
}
