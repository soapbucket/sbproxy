// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
//
// The AWS KMS driver is not available in this build. Configuring driver: "aws"
// will return ErrAWSNotAvailable.
package crypto

import "fmt"

// ErrAWSNotAvailable is returned when the AWS KMS crypto driver is configured
// but has not been compiled in.
var ErrAWSNotAvailable = fmt.Errorf("crypto: AWS KMS driver not available in this build")

func init() {
	Register("aws", func(_ Settings) (Crypto, error) {
		return nil, ErrAWSNotAvailable
	})
}
