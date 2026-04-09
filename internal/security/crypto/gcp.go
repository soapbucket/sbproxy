// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
//
// The GCP KMS driver is not available in this build. Configuring driver: "gcp"
// will return ErrGCPNotAvailable.
package crypto

import "fmt"

// ErrGCPNotAvailable is returned when the GCP KMS crypto driver is configured
// but has not been compiled in.
var ErrGCPNotAvailable = fmt.Errorf("crypto: GCP KMS driver not available in this build")

func init() {
	Register("gcp", func(_ Settings) (Crypto, error) {
		return nil, ErrGCPNotAvailable
	})
}
