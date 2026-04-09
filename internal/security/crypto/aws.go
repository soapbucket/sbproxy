// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
//
// The AWS KMS driver requires the enterprise build. In the core build,
// configuring driver: "aws" will return ErrNotAvailable.
package crypto

import "fmt"

// ErrAWSNotAvailable is returned when the AWS KMS crypto driver is configured
// but the enterprise dependency is not compiled in.
var ErrAWSNotAvailable = fmt.Errorf("crypto: AWS KMS driver not available in core build (requires enterprise dependency)")

func init() {
	Register("aws", func(_ Settings) (Crypto, error) {
		return nil, ErrAWSNotAvailable
	})
}
