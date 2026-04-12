// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
	
	"github.com/soapbucket/sbproxy/internal/security/certpin"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

var (
	// ErrCertificatePinMismatch is returned when certificate pin doesn't match
	ErrCertificatePinMismatch = errors.New("certificate pin mismatch")
	
	// ErrNoCertificatesProvided is returned when no certificates are available for verification
	ErrNoCertificatesProvided = errors.New("no certificates provided for pinning verification")
	
	// ErrPinExpired is returned when the pin has expired
	ErrPinExpired = errors.New("certificate pin has expired")
)

// CertificatePinner handles certificate pinning verification
type CertificatePinner struct {
	config     *certpin.CertificatePinningConfig
	originName string
}

// NewCertificatePinner creates a new certificate pinner with the given configuration
func NewCertificatePinner(config *certpin.CertificatePinningConfig, originName string) (*CertificatePinner, error) {
	if config == nil {
		return nil, fmt.Errorf("certificate pinning config is nil")
	}
	
	if !config.Enabled {
		return nil, nil
	}
	
	if config.PinSHA256 == "" {
		return nil, fmt.Errorf("certificate pinning enabled but no pin_sha256 provided for origin %s", originName)
	}
	
	return &CertificatePinner{
		config:     config,
		originName: originName,
	}, nil
}

// VerifyPeerCertificate verifies that at least one certificate in the chain matches the configured pins
func (p *CertificatePinner) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if p == nil || p.config == nil || !p.config.Enabled {
		return nil
	}
	
	// Check if pin has expired
	if p.config.PinExpiry != "" {
		expiryTime, err := time.Parse(time.RFC3339, p.config.PinExpiry)
		if err != nil {
			slog.Warn("failed to parse pin expiry time, ignoring expiry check",
				"origin", p.originName,
				"expiry", p.config.PinExpiry,
				"error", err)
		} else if time.Now().After(expiryTime) {
			slog.Error("certificate pin has expired",
				"origin", p.originName,
				"expiry", expiryTime)
			return ErrPinExpired
		}
	}
	
	if len(rawCerts) == 0 {
		slog.Error("no certificates provided for pinning verification",
			"origin", p.originName)
		return ErrNoCertificatesProvided
	}
	
	// Collect all valid pins (primary + backups)
	validPins := []string{p.config.PinSHA256}
	validPins = append(validPins, p.config.BackupPins...)
	
	// Check each certificate in the chain
	for i, rawCert := range rawCerts {
		// Compute SHA-256 hash of the certificate's public key
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			slog.Warn("failed to parse certificate for pinning verification",
				"origin", p.originName,
				"cert_index", i,
				"error", err)
			continue
		}
		
		// Extract Subject Public Key Info (SPKI) and hash it
		spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		spkiHashBase64 := base64.StdEncoding.EncodeToString(spkiHash[:])
		
		// Check if this certificate matches any of the valid pins
		for _, pin := range validPins {
			if spkiHashBase64 == pin {
				slog.Debug("certificate pin matched",
					"origin", p.originName,
					"cert_index", i,
					"subject", cert.Subject.String(),
					"pin", pin)
				return nil
			}
		}
		
		// Log pin for debugging purposes
		slog.Debug("certificate pin does not match",
			"origin", p.originName,
			"cert_index", i,
			"subject", cert.Subject.String(),
			"computed_pin", spkiHashBase64)
	}
	
	// No certificate matched any pin
	slog.Error("certificate pin verification failed - no matching pin found in certificate chain",
		"origin", p.originName,
		"certs_checked", len(rawCerts))
	
	// Record certificate pinning failure metric
	metric.CertPinFailure(p.originName, "pin_mismatch")
	
	return ErrCertificatePinMismatch
}

// GetTLSConfig returns a TLS config with certificate pinning verification
func (p *CertificatePinner) GetTLSConfig(baseTLSConfig *tls.Config) *tls.Config {
	if p == nil || p.config == nil || !p.config.Enabled {
		return baseTLSConfig
	}
	
	// Clone the base config to avoid modifying the original
	tlsConfig := baseTLSConfig.Clone()
	
	// Set custom verification function
	tlsConfig.VerifyPeerCertificate = p.VerifyPeerCertificate
	
	// We still want standard TLS verification, so we don't set InsecureSkipVerify to true
	// The VerifyPeerCertificate is called AFTER standard verification
	
	return tlsConfig
}

// WarnIfPinExpiringSoon logs a warning if the pin is expiring soon
func (p *CertificatePinner) WarnIfPinExpiringSoon(warningDays int) {
	if p == nil || p.config == nil || !p.config.Enabled {
		return
	}
	
	if p.config.PinExpiry == "" {
		return
	}
	
	expiryTime, err := time.Parse(time.RFC3339, p.config.PinExpiry)
	if err != nil {
		return
	}
	
	daysUntilExpiry := time.Until(expiryTime).Hours() / 24
	if daysUntilExpiry <= float64(warningDays) && daysUntilExpiry > 0 {
		slog.Warn("certificate pin expiring soon",
			"origin", p.originName,
			"expiry", expiryTime,
			"days_until_expiry", int(daysUntilExpiry))
	}
}

// ComputePinFromConnection connects to a host and computes the certificate pin
// This is a utility function for administrators to generate pins
func ComputePinFromConnection(host string, port string) ([]string, error) {
	if port == "" {
		port = "443"
	}
	
	address := net.JoinHostPort(host, port)
	
	slog.Info("connecting to host to compute certificate pins",
		"host", host,
		"port", port,
		"address", address)
	
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer conn.Close()
	
	state := conn.ConnectionState()
	var pins []string
	
	for i, cert := range state.PeerCertificates {
		spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		spkiHashBase64 := base64.StdEncoding.EncodeToString(spkiHash[:])
		pins = append(pins, spkiHashBase64)
		
		slog.Info("computed certificate pin",
			"host", host,
			"cert_index", i,
			"subject", cert.Subject.String(),
			"issuer", cert.Issuer.String(),
			"not_before", cert.NotBefore,
			"not_after", cert.NotAfter,
			"pin", spkiHashBase64)
	}
	
	return pins, nil
}

// ValidatePinFormat validates that a pin is in the correct format (base64-encoded SHA-256)
func ValidatePinFormat(pin string) error {
	if pin == "" {
		return fmt.Errorf("pin is empty")
	}
	
	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(pin)
	if err != nil {
		return fmt.Errorf("invalid base64 encoding: %w", err)
	}
	
	// SHA-256 hash is 32 bytes
	if len(decoded) != 32 {
		return fmt.Errorf("invalid pin length: expected 32 bytes (SHA-256), got %d bytes", len(decoded))
	}
	
	return nil
}

// ValidateConfig validates the certificate pinning configuration
func ValidateConfig(config *certpin.CertificatePinningConfig) error {
	if config == nil {
		return nil
	}
	
	if !config.Enabled {
		return nil
	}
	
	// Validate primary pin
	if err := ValidatePinFormat(config.PinSHA256); err != nil {
		return fmt.Errorf("invalid primary pin: %w", err)
	}
	
	// Validate backup pins
	for i, pin := range config.BackupPins {
		if err := ValidatePinFormat(pin); err != nil {
			return fmt.Errorf("invalid backup pin at index %d: %w", i, err)
		}
	}
	
	// Validate expiry if provided
	if config.PinExpiry != "" {
		_, err := time.Parse(time.RFC3339, config.PinExpiry)
		if err != nil {
			return fmt.Errorf("invalid pin expiry format (expected RFC3339): %w", err)
		}
	}
	
	return nil
}

