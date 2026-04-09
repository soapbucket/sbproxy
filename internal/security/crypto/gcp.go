// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
//
// The GCP KMS driver requires the enterprise build. In the core build,
// configuring driver: "gcp" will return ErrNotAvailable.
package crypto

import "fmt"

// ErrGCPNotAvailable is returned when the GCP KMS crypto driver is configured
// but the enterprise dependency is not compiled in.
var ErrGCPNotAvailable = fmt.Errorf("crypto: GCP KMS driver not available in core build (requires enterprise dependency)")

func init() {
	Register("gcp", func(_ Settings) (Crypto, error) {
		return nil, ErrGCPNotAvailable
	})
}
