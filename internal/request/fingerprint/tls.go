// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package fingerprint

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"slices"
	"strings"
)

const (
	// DefaultTLSKeyPairID is the default key pair ID for TLS certificates
	DefaultTLSKeyPairID = "default"
)

// TLSKeyPair represents a TLS certificate and key pair
type TLSKeyPair struct {
	Cert string
	Key  string
}

// CertManager manages TLS certificates
type CertManager struct {
	keyPairs  map[string]TLSKeyPair
	configDir string
	logSender string
}

// NewCertManager creates a new certificate manager
func NewCertManager(keyPairs []TLSKeyPair, configDir, logSender string) (*CertManager, error) {
	cm := &CertManager{
		keyPairs:  make(map[string]TLSKeyPair),
		configDir: configDir,
		logSender: logSender,
	}

	// Add key pairs to the manager
	for i, kp := range keyPairs {
		key := DefaultTLSKeyPairID
		if i > 0 {
			key = fmt.Sprintf("keypair_%d", i)
		}
		cm.keyPairs[key] = kp
	}

	return cm, nil
}

// GetCertificateFunc returns a function that can be used as tls.Config.GetCertificate
func (cm *CertManager) GetCertificateFunc(keyPairID string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kp, exists := cm.keyPairs[keyPairID]
		if !exists {
			// Fallback to default if the requested key pair doesn't exist
			kp, exists = cm.keyPairs[DefaultTLSKeyPairID]
			if !exists {
				return nil, fmt.Errorf("no certificate found for key pair ID: %s", keyPairID)
			}
		}

		cert, err := tls.LoadX509KeyPair(kp.Cert, kp.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}

		return &cert, nil
	}
}

// Reload reloads the certificate manager (placeholder implementation)
func (cm *CertManager) Reload() error {
	// For now, this is a no-op. In a real implementation, this would reload certificates
	return nil
}

// GetTLSVersion returns the TLS version constant from an integer value
// Default is TLS 1.3 for security. TLS 1.2 requires explicit opt-in.
func GetTLSVersion(val int) uint16 {
	switch val {
	case 12:
		// TLS 1.2 is allowed but not recommended (has known vulnerabilities)
		slog.Warn("SECURITY WARNING: TLS 1.2 is enabled. Consider upgrading to TLS 1.3",
			"tls_version", "1.2",
			"risk", "vulnerable to downgrade attacks")
		return tls.VersionTLS12
	case 13:
		return tls.VersionTLS13
	default:
		// Default to TLS 1.3 for security
		slog.Info("using default TLS version 1.3")
		return tls.VersionTLS13
	}
}

// GetTLSCiphersFromNames returns the TLS ciphers from the specified names
func GetTLSCiphersFromNames(cipherNames []string) []uint16 {
	var ciphers []uint16

	for _, name := range slices.CompactFunc(cipherNames, func(s1, s2 string) bool {
		return strings.TrimSpace(s1) == strings.TrimSpace(s2)
	}) {
		for _, c := range tls.CipherSuites() {
			if c.Name == strings.TrimSpace(name) {
				ciphers = append(ciphers, c.ID)
			}
		}
	}

	return ciphers
}
