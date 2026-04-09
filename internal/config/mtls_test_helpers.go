// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// MTLSFixtures contains paths to test certificates
type MTLSFixtures struct {
	CACertPath     string
	CAKeyPath      string
	ServerCertPath string
	ServerKeyPath  string
	ClientCertPath string
	ClientKeyPath  string
}

// GetMTLSFixtures returns paths to test certificates, generating them if needed
func GetMTLSFixtures(t testingT) *MTLSFixtures {
	certDir := filepath.Join("..", "..", "certs")
	
	fixtures := &MTLSFixtures{
		CACertPath:     filepath.Join(certDir, "ca-cert.pem"),
		CAKeyPath:      filepath.Join(certDir, "ca-key.pem"),
		ServerCertPath: filepath.Join(certDir, "server-cert.pem"),
		ServerKeyPath:  filepath.Join(certDir, "server-key.pem"),
		ClientCertPath: filepath.Join(certDir, "client-cert.pem"),
		ClientKeyPath:  filepath.Join(certDir, "client-key.pem"),
	}

	// Check if certificates exist, if not, generate them
	if _, err := os.Stat(fixtures.ClientCertPath); os.IsNotExist(err) {
		// Try to generate certificates
		if err := generateTestCertificates(fixtures); err != nil {
			t.Skipf("Test certificates not found and could not be generated: %v. Run: cd certs && ./generate_test_certs.sh", err)
		}
	}

	return fixtures
}

// testingT is a minimal interface for testing.T
type testingT interface {
	Skipf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
}

// LoadMTLSCertificates loads certificates from fixture paths
func (f *MTLSFixtures) LoadMTLSCertificates() (*tls.Certificate, *tls.Certificate, *x509.CertPool, error) {
	// Load server certificate
	serverCert, err := tls.LoadX509KeyPair(f.ServerCertPath, f.ServerKeyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Load client certificate
	clientCert, err := tls.LoadX509KeyPair(f.ClientCertPath, f.ClientKeyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate
	caCertPEM, err := os.ReadFile(f.CACertPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, nil, nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &serverCert, &clientCert, caCertPool, nil
}

// GetBase64Certificates returns base64-encoded certificate data
func (f *MTLSFixtures) GetBase64Certificates() (clientCertBase64, clientKeyBase64, caCertBase64 string, err error) {
	clientCertPEM, err := os.ReadFile(f.ClientCertPath)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read client certificate: %w", err)
	}

	clientKeyPEM, err := os.ReadFile(f.ClientKeyPath)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read client key: %w", err)
	}

	caCertPEM, err := os.ReadFile(f.CACertPath)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read CA certificate: %w", err)
	}

	clientCertBase64 = base64.StdEncoding.EncodeToString(clientCertPEM)
	clientKeyBase64 = base64.StdEncoding.EncodeToString(clientKeyPEM)
	caCertBase64 = base64.StdEncoding.EncodeToString(caCertPEM)

	return clientCertBase64, clientKeyBase64, caCertBase64, nil
}

// generateTestCertificates generates test certificates if they don't exist
func generateTestCertificates(fixtures *MTLSFixtures) error {
	certDir := filepath.Dir(fixtures.CACertPath)
	
	// Create certs directory if it doesn't exist
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}

	// Generate CA key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Test"},
			OrganizationalUnit: []string{"Test CA"},
			CommonName:         "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Save CA certificate
	caCertFile, err := os.Create(fixtures.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to create CA cert file: %w", err)
	}
	defer caCertFile.Close()
	pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Save CA key
	caKeyFile, err := os.OpenFile(fixtures.CAKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create CA key file: %w", err)
	}
	defer caKeyFile.Close()
	pem.Encode(caKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})

	// Generate server key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	// Create server certificate
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test"},
			CommonName:   "localhost",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "*.localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Save server certificate
	serverCertFile, err := os.Create(fixtures.ServerCertPath)
	if err != nil {
		return fmt.Errorf("failed to create server cert file: %w", err)
	}
	defer serverCertFile.Close()
	pem.Encode(serverCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})

	// Save server key
	serverKeyFile, err := os.OpenFile(fixtures.ServerKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create server key file: %w", err)
	}
	defer serverKeyFile.Close()
	pem.Encode(serverKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	// Generate client key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate client key: %w", err)
	}

	// Create client certificate
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test"},
			CommonName:   "test-client",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Save client certificate
	clientCertFile, err := os.Create(fixtures.ClientCertPath)
	if err != nil {
		return fmt.Errorf("failed to create client cert file: %w", err)
	}
	defer clientCertFile.Close()
	pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})

	// Save client key
	clientKeyFile, err := os.OpenFile(fixtures.ClientKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create client key file: %w", err)
	}
	defer clientKeyFile.Close()
	pem.Encode(clientKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})

	return nil
}


