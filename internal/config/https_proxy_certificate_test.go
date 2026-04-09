package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Helper to create a self-signed certificate for testing
func createTestCertificate(commonName string, isCA bool) (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privateKey,
	}, nil
}

func TestNewCertificateLoader(t *testing.T) {
	resolver := func(secret string) (string, error) {
		return "test_value", nil
	}

	loader := NewCertificateLoader(resolver)
	if loader == nil {
		t.Fatal("NewCertificateLoader returned nil")
	}
	if loader.secretResolver == nil {
		t.Error("secret resolver not set")
	}
}

func TestNewCertificateLoaderNilResolver(t *testing.T) {
	loader := NewCertificateLoader(nil)
	if loader == nil {
		t.Fatal("NewCertificateLoader returned nil")
	}

	// Default resolver should return error
	_, err := loader.secretResolver("test_secret")
	if err == nil {
		t.Error("default resolver should return error")
	}
}

func TestLoadServerCertificateNilConfig(t *testing.T) {
	resolver := func(secret string) (string, error) {
		return "test_value", nil
	}

	loader := NewCertificateLoader(resolver)
	cert, err := loader.LoadServerCertificate(nil)

	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if cert != nil {
		t.Error("expected nil certificate")
	}
}

func TestLoadServerCertificateMissingSecrets(t *testing.T) {
	resolver := func(secret string) (string, error) {
		return "test_value", nil
	}

	loader := NewCertificateLoader(resolver)

	tests := []struct {
		name      string
		config    *CertificateConfig
		expectErr bool
	}{
		{
			name:      "empty cert secret",
			config:    &CertificateConfig{CertSecret: "", KeySecret: "key"},
			expectErr: true,
		},
		{
			name:      "empty key secret",
			config:    &CertificateConfig{CertSecret: "cert", KeySecret: ""},
			expectErr: true,
		},
		{
			name:      "both empty",
			config:    &CertificateConfig{CertSecret: "", KeySecret: ""},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loader.LoadServerCertificate(tt.config)
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

func TestLoadMITMCACertificateDisabled(t *testing.T) {
	resolver := func(secret string) (string, error) {
		return "test_value", nil
	}

	loader := NewCertificateLoader(resolver)

	tests := []struct {
		name   string
		config *CertSpoofingConfig
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name:   "disabled",
			config: &CertSpoofingConfig{Enabled: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := loader.LoadMITMCACertificate(tt.config)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if cert != nil {
				t.Error("expected nil certificate for disabled config")
			}
		})
	}
}

func TestLoadMITMCACertificateMissingSecrets(t *testing.T) {
	resolver := func(secret string) (string, error) {
		return "test_value", nil
	}

	loader := NewCertificateLoader(resolver)
	config := &CertSpoofingConfig{
		Enabled:             true,
		CertificateSecret:   "",
		KeySecret:           "key",
		CacheTTL:            24 * time.Hour,
	}

	_, err := loader.LoadMITMCACertificate(config)
	if err == nil {
		t.Error("expected error for missing secrets")
	}
}

func TestNewMITMCertificateGeneratorNilCert(t *testing.T) {
	gen, err := NewMITMCertificateGenerator(nil)
	if err == nil {
		t.Error("expected error for nil certificate")
	}
	if gen != nil {
		t.Error("expected nil generator")
	}
}

func TestNewMITMCertificateGenerator(t *testing.T) {
	caCert, err := createTestCertificate("Test CA", true)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	gen, err := NewMITMCertificateGenerator(caCert)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if gen == nil {
		t.Fatal("generator is nil")
	}
	if gen.caCert == nil {
		t.Error("CA cert not set")
	}
	if gen.caX509 == nil {
		t.Error("CA x509 cert not set")
	}
}

func TestGenerateCertificate(t *testing.T) {
	caCert, err := createTestCertificate("Test CA", true)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	gen, err := NewMITMCertificateGenerator(caCert)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	tests := []struct {
		name      string
		hostname  string
		expectErr bool
	}{
		{
			name:      "valid hostname",
			hostname:  "example.com",
			expectErr: false,
		},
		{
			name:      "wildcard hostname",
			hostname:  "*.example.com",
			expectErr: false,
		},
		{
			name:      "IP address",
			hostname:  "192.168.1.1",
			expectErr: false,
		},
		{
			name:      "empty hostname",
			hostname:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := gen.GenerateCertificate(tt.hostname)
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !tt.expectErr && cert == nil {
				t.Error("expected certificate")
			}
		})
	}
}

func TestGenerateCertificateSAN(t *testing.T) {
	caCert, err := createTestCertificate("Test CA", true)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	gen, err := NewMITMCertificateGenerator(caCert)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Generate certificate
	cert, err := gen.GenerateCertificate("example.com")
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	// Parse certificate and verify SAN
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if len(x509Cert.DNSNames) == 0 {
		t.Error("expected DNS names in certificate")
	}

	foundHost := false
	for _, name := range x509Cert.DNSNames {
		if name == "example.com" {
			foundHost = true
			break
		}
	}
	if !foundHost {
		t.Errorf("expected 'example.com' in DNS names, got %v", x509Cert.DNSNames)
	}
}

func TestNewCertificateManager(t *testing.T) {
	resolver := func(secret string) (string, error) {
		return "test_value", nil
	}

	loader := NewCertificateLoader(resolver)
	manager := NewCertificateManager(loader)

	if manager == nil {
		t.Fatal("manager is nil")
	}
	if manager.loader == nil {
		t.Error("loader not set")
	}
}

func TestCertificateManagerInitializeNilConfig(t *testing.T) {
	resolver := func(secret string) (string, error) {
		return "test_value", nil
	}

	loader := NewCertificateLoader(resolver)
	manager := NewCertificateManager(loader)

	err := manager.Initialize(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestCertificateManagerInitializeDisabledSpoofing(t *testing.T) {
	resolver := func(secret string) (string, error) {
		return "test_value", nil
	}

	loader := NewCertificateLoader(resolver)
	manager := NewCertificateManager(loader)

	config := &HTTPSProxyConfig{
		CertificateSpoofing: &CertSpoofingConfig{
			Enabled: false,
		},
	}

	err := manager.Initialize(config)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if manager.generator != nil {
		t.Error("generator should be nil for disabled spoofing")
	}
}

func TestGetOrGenerateCertificateEmptyHostname(t *testing.T) {
	resolver := func(secret string) (string, error) {
		return "test_value", nil
	}

	loader := NewCertificateLoader(resolver)
	manager := NewCertificateManager(loader)

	_, err := manager.GetOrGenerateCertificate("", nil)
	if err == nil {
		t.Error("expected error for empty hostname")
	}
}

func TestGetOrGenerateCertificateWithoutGenerator(t *testing.T) {
	resolver := func(secret string) (string, error) {
		return "test_value", nil
	}

	loader := NewCertificateLoader(resolver)
	manager := NewCertificateManager(loader)

	_, err := manager.GetOrGenerateCertificate("example.com", nil)
	if err == nil {
		t.Error("expected error without generator")
	}
}
