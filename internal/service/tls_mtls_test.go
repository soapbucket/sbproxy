package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseClientAuthType(t *testing.T) {
	tests := []struct {
		input    string
		expected tls.ClientAuthType
	}{
		{"none", tls.NoClientCert},
		{"", tls.NoClientCert},
		{"invalid", tls.NoClientCert},
		{"request", tls.RequestClientCert},
		{"require", tls.RequireAnyClientCert},
		{"verify_if_given", tls.VerifyClientCertIfGiven},
		{"require_and_verify", tls.RequireAndVerifyClientCert},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseClientAuthType(tt.input)
			if result != tt.expected {
				t.Errorf("parseClientAuthType(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestApplyClientAuth_None(t *testing.T) {
	tlsConfig := &tls.Config{}
	settings := CertificateSettings{ClientAuth: "none"}
	applyClientAuth(tlsConfig, settings)

	if tlsConfig.ClientAuth != tls.NoClientCert {
		t.Errorf("expected NoClientCert, got %d", tlsConfig.ClientAuth)
	}
	if tlsConfig.ClientCAs != nil {
		t.Error("expected nil ClientCAs for 'none' mode")
	}
}

func TestApplyClientAuth_Empty(t *testing.T) {
	tlsConfig := &tls.Config{}
	settings := CertificateSettings{}
	applyClientAuth(tlsConfig, settings)

	if tlsConfig.ClientAuth != tls.NoClientCert {
		t.Errorf("expected NoClientCert, got %d", tlsConfig.ClientAuth)
	}
}

func TestApplyClientAuth_RequireAndVerify_WithFile(t *testing.T) {
	tmpDir := t.TempDir()
	caCertPath := filepath.Join(tmpDir, "ca.pem")

	caCertPEM := generateTestCACertPEM(t)
	if err := os.WriteFile(caCertPath, caCertPEM, 0600); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}

	tlsConfig := &tls.Config{}
	settings := CertificateSettings{
		ClientAuth:       "require_and_verify",
		ClientCACertFile: caCertPath,
	}
	applyClientAuth(tlsConfig, settings)

	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected RequireAndVerifyClientCert, got %d", tlsConfig.ClientAuth)
	}
	if tlsConfig.ClientCAs == nil {
		t.Fatal("expected non-nil ClientCAs")
	}
}

func TestApplyClientAuth_RequireAndVerify_WithBase64(t *testing.T) {
	caCertPEM := generateTestCACertPEM(t)
	encoded := base64.StdEncoding.EncodeToString(caCertPEM)

	tlsConfig := &tls.Config{}
	settings := CertificateSettings{
		ClientAuth:       "require_and_verify",
		ClientCACertData: encoded,
	}
	applyClientAuth(tlsConfig, settings)

	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected RequireAndVerifyClientCert, got %d", tlsConfig.ClientAuth)
	}
	if tlsConfig.ClientCAs == nil {
		t.Fatal("expected non-nil ClientCAs")
	}
}

func TestApplyClientAuth_Base64PreferredOverFile(t *testing.T) {
	caCertPEM := generateTestCACertPEM(t)
	encoded := base64.StdEncoding.EncodeToString(caCertPEM)

	tlsConfig := &tls.Config{}
	settings := CertificateSettings{
		ClientAuth:       "require_and_verify",
		ClientCACertData: encoded,
		ClientCACertFile: "/nonexistent/path/ca.pem",
	}
	applyClientAuth(tlsConfig, settings)

	if tlsConfig.ClientCAs == nil {
		t.Fatal("expected non-nil ClientCAs (base64 should be preferred over file)")
	}
}

func TestApplyClientAuth_InvalidBase64(t *testing.T) {
	tlsConfig := &tls.Config{}
	settings := CertificateSettings{
		ClientAuth:       "require_and_verify",
		ClientCACertData: "not-valid-base64!!!",
	}
	applyClientAuth(tlsConfig, settings)

	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected RequireAndVerifyClientCert, got %d", tlsConfig.ClientAuth)
	}
	if tlsConfig.ClientCAs != nil {
		t.Error("expected nil ClientCAs with invalid base64")
	}
}

func TestApplyClientAuth_Request_NoCACert(t *testing.T) {
	tlsConfig := &tls.Config{}
	settings := CertificateSettings{
		ClientAuth: "request",
	}
	applyClientAuth(tlsConfig, settings)

	if tlsConfig.ClientAuth != tls.RequestClientCert {
		t.Errorf("expected RequestClientCert, got %d", tlsConfig.ClientAuth)
	}
}

func TestApplyClientAuth_VerifyIfGiven(t *testing.T) {
	caCertPEM := generateTestCACertPEM(t)
	encoded := base64.StdEncoding.EncodeToString(caCertPEM)

	tlsConfig := &tls.Config{}
	settings := CertificateSettings{
		ClientAuth:       "verify_if_given",
		ClientCACertData: encoded,
	}
	applyClientAuth(tlsConfig, settings)

	if tlsConfig.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("expected VerifyClientCertIfGiven, got %d", tlsConfig.ClientAuth)
	}
	if tlsConfig.ClientCAs == nil {
		t.Fatal("expected non-nil ClientCAs")
	}
}

// generateTestCACertPEM creates a self-signed CA certificate for testing.
func generateTestCACertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}
