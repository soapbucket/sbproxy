// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
package service

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// MTLSConfig configures mutual TLS client authentication.
type MTLSConfig struct {
	Enabled      bool   `json:"enabled" yaml:"enabled"`
	ClientCAFile string `json:"client_ca_file" yaml:"client_ca_file"`
	VerifyMode   string `json:"verify_mode,omitempty" yaml:"verify_mode"` // "require", "optional", "none"
}

// ConfigureMTLS adds client certificate verification to a TLS config.
// When mtlsCfg.Enabled is false, this is a no-op.
// VerifyMode values:
//   - "require" or "" (default): RequireAndVerifyClientCert
//   - "optional": VerifyClientCertIfGiven
//   - "none": NoClientCert
func ConfigureMTLS(tlsCfg *tls.Config, mtlsCfg MTLSConfig) error {
	if !mtlsCfg.Enabled {
		return nil
	}

	caCert, err := os.ReadFile(mtlsCfg.ClientCAFile)
	if err != nil {
		return fmt.Errorf("read client CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse client CA certificate")
	}
	tlsCfg.ClientCAs = pool

	switch mtlsCfg.VerifyMode {
	case "require", "":
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	case "optional":
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	case "none":
		tlsCfg.ClientAuth = tls.NoClientCert
	default:
		return fmt.Errorf("unknown verify_mode: %s", mtlsCfg.VerifyMode)
	}

	return nil
}
