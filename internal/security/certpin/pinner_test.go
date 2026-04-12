package certpin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// generateTestCertificate generates a self-signed certificate for testing
func generateTestCertificate(t *testing.T) ([]byte, []byte, string) {
	t.Helper()

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Parse certificate to compute pin
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Compute SHA-256 pin of SPKI
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	pin := base64.StdEncoding.EncodeToString(spkiHash[:])

	return certPEM, privateKeyPEM, pin
}

func TestValidatePinFormat(t *testing.T) {
	tests := []struct {
		name    string
		pin     string
		wantErr bool
	}{
		{
			name:    "empty pin",
			pin:     "",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			pin:     "not-base64!@#$%",
			wantErr: true,
		},
		{
			name:    "wrong length",
			pin:     base64.StdEncoding.EncodeToString([]byte("too short")),
			wantErr: true,
		},
		{
			name:    "valid pin",
			pin:     base64.StdEncoding.EncodeToString(make([]byte, 32)),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePinFormat(tt.pin)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePinFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	validPin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	invalidPin := "invalid"

	tests := []struct {
		name    string
		config  *CertificatePinningConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled config",
			config: &CertificatePinningConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid config",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: validPin,
			},
			wantErr: false,
		},
		{
			name: "invalid primary pin",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: invalidPin,
			},
			wantErr: true,
		},
		{
			name: "invalid backup pin",
			config: &CertificatePinningConfig{
				Enabled:    true,
				PinSHA256:  validPin,
				BackupPins: []string{invalidPin},
			},
			wantErr: true,
		},
		{
			name: "invalid expiry format",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: validPin,
				PinExpiry: "2025-13-99",
			},
			wantErr: true,
		},
		{
			name: "valid expiry",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: validPin,
				PinExpiry: time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewCertificatePinner(t *testing.T) {
	validPin := base64.StdEncoding.EncodeToString(make([]byte, 32))

	tests := []struct {
		name       string
		config     *CertificatePinningConfig
		originName string
		wantNil    bool
		wantErr    bool
	}{
		{
			name:       "nil config",
			config:     nil,
			originName: "test",
			wantNil:    true,
			wantErr:    true,
		},
		{
			name: "disabled config",
			config: &CertificatePinningConfig{
				Enabled: false,
			},
			originName: "test",
			wantNil:    true,
			wantErr:    false,
		},
		{
			name: "no pin provided",
			config: &CertificatePinningConfig{
				Enabled: true,
			},
			originName: "test",
			wantNil:    true,
			wantErr:    true,
		},
		{
			name: "valid config",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: validPin,
			},
			originName: "test",
			wantNil:    false,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinner, err := NewCertificatePinner(tt.config, tt.originName)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertificatePinner() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (pinner == nil) != tt.wantNil {
				t.Errorf("NewCertificatePinner() pinner is nil = %v, wantNil %v", pinner == nil, tt.wantNil)
			}
		})
	}
}

func TestVerifyPeerCertificate(t *testing.T) {
	certPEM, _, pin := generateTestCertificate(t)

	// Parse the certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	wrongPin := base64.StdEncoding.EncodeToString(make([]byte, 32)) // All zeros

	tests := []struct {
		name     string
		config   *CertificatePinningConfig
		rawCerts [][]byte
		wantErr  bool
	}{
		{
			name: "matching pin",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: pin,
			},
			rawCerts: [][]byte{cert.Raw},
			wantErr:  false,
		},
		{
			name: "non-matching pin",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: wrongPin,
			},
			rawCerts: [][]byte{cert.Raw},
			wantErr:  true,
		},
		{
			name: "matching backup pin",
			config: &CertificatePinningConfig{
				Enabled:    true,
				PinSHA256:  wrongPin,
				BackupPins: []string{pin},
			},
			rawCerts: [][]byte{cert.Raw},
			wantErr:  false,
		},
		{
			name: "no certificates",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: pin,
			},
			rawCerts: [][]byte{},
			wantErr:  true,
		},
		{
			name: "expired pin",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: pin,
				PinExpiry: time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
			},
			rawCerts: [][]byte{cert.Raw},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinner, err := NewCertificatePinner(tt.config, "test")
			if err != nil {
				t.Fatalf("NewCertificatePinner() error = %v", err)
			}

			err = pinner.VerifyPeerCertificate(tt.rawCerts, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPeerCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCertificatePinningIntegration(t *testing.T) {
	// Generate test certificate
	certPEM, keyPEM, pin := generateTestCertificate(t)

	// Create TLS certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to create TLS certificate: %v", err)
	}

	// Create test HTTPS server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	server.StartTLS()
	defer server.Close()

	tests := []struct {
		name        string
		config      *CertificatePinningConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "correct pin - connection succeeds",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: pin,
			},
			wantErr: false,
		},
		{
			name: "wrong pin - connection fails",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: base64.StdEncoding.EncodeToString(make([]byte, 32)),
			},
			wantErr:     true,
			errContains: "pin mismatch",
		},
		{
			name: "disabled pinning - connection succeeds",
			config: &CertificatePinningConfig{
				Enabled: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create pinner
			pinner, err := NewCertificatePinner(tt.config, "test-server")
			if err != nil && tt.config.Enabled {
				t.Fatalf("NewCertificatePinner() error = %v", err)
			}

			// Configure TLS client
			baseTLSConfig := &tls.Config{
				InsecureSkipVerify: true, // We're testing pinning, not standard TLS verification
			}

			var tlsConfig *tls.Config
			if pinner != nil {
				tlsConfig = pinner.GetTLSConfig(baseTLSConfig)
			} else {
				tlsConfig = baseTLSConfig
			}

			// Create HTTP client
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
				Timeout: 5 * time.Second,
			}

			// Make request
			resp, err := client.Get(server.URL)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
			}
		})
	}
}

func TestWarnIfPinExpiringSoon(t *testing.T) {
	validPin := base64.StdEncoding.EncodeToString(make([]byte, 32))

	tests := []struct {
		name        string
		config      *CertificatePinningConfig
		warningDays int
		// We can't easily test logging output, but we can ensure no panics
	}{
		{
			name: "no expiry set",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: validPin,
			},
			warningDays: 7,
		},
		{
			name: "expiring soon",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: validPin,
				PinExpiry: time.Now().Add(3 * 24 * time.Hour).Format(time.RFC3339),
			},
			warningDays: 7,
		},
		{
			name: "not expiring soon",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: validPin,
				PinExpiry: time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
			},
			warningDays: 7,
		},
		{
			name: "already expired",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: validPin,
				PinExpiry: time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
			},
			warningDays: 7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinner, err := NewCertificatePinner(tt.config, "test")
			if err != nil {
				t.Fatalf("NewCertificatePinner() error = %v", err)
			}

			// Should not panic
			pinner.WarnIfPinExpiringSoon(tt.warningDays)
		})
	}
}

func TestGetTLSConfig(t *testing.T) {
	validPin := base64.StdEncoding.EncodeToString(make([]byte, 32))

	tests := []struct {
		name   string
		config *CertificatePinningConfig
	}{
		{
			name:   "nil pinner",
			config: nil,
		},
		{
			name: "disabled config",
			config: &CertificatePinningConfig{
				Enabled: false,
			},
		},
		{
			name: "enabled config",
			config: &CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: validPin,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pinner *CertificatePinner
			var err error

			if tt.config != nil && tt.config.Enabled {
				pinner, err = NewCertificatePinner(tt.config, "test")
				if err != nil {
					t.Fatalf("NewCertificatePinner() error = %v", err)
				}
			}

			baseTLSConfig := &tls.Config{
				InsecureSkipVerify: true,
			}

			tlsConfig := pinner.GetTLSConfig(baseTLSConfig)
			if tlsConfig == nil {
				t.Error("GetTLSConfig() returned nil")
			}

			// Verify that VerifyPeerCertificate is set when pinning is enabled
			if tt.config != nil && tt.config.Enabled {
				if tlsConfig.VerifyPeerCertificate == nil {
					t.Error("VerifyPeerCertificate should be set when pinning is enabled")
				}
			}
		})
	}
}
