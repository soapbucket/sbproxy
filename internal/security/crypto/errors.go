// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
package crypto

import "errors"

var (
	// ErrInvalidProvider is a sentinel error for invalid provider conditions.
	ErrInvalidProvider    = errors.New("crypto: invalid provider")
	// ErrInvalidCiphertext is a sentinel error for invalid ciphertext conditions.
	ErrInvalidCiphertext  = errors.New("crypto: invalid ciphertext format")
	// ErrEncryptionFailed is a sentinel error for encryption failed conditions.
	ErrEncryptionFailed   = errors.New("crypto: encryption failed")
	// ErrDecryptionFailed is a sentinel error for decryption failed conditions.
	ErrDecryptionFailed   = errors.New("crypto: decryption failed")
	// ErrSigningFailed is a sentinel error for signing failed conditions.
	ErrSigningFailed      = errors.New("crypto: signing failed")
	// ErrVerificationFailed is a sentinel error for verification failed conditions.
	ErrVerificationFailed = errors.New("crypto: verification failed")
	// ErrMissingKeyID is a sentinel error for missing key id conditions.
	ErrMissingKeyID       = errors.New("crypto: missing key ID")
	// ErrMissingProjectID is a sentinel error for missing project id conditions.
	ErrMissingProjectID   = errors.New("crypto: missing project ID")
	// ErrMissingLocation is a sentinel error for missing location conditions.
	ErrMissingLocation    = errors.New("crypto: missing location")
	// ErrMissingKeyRing is a sentinel error for missing key ring conditions.
	ErrMissingKeyRing     = errors.New("crypto: missing key ring")
	// ErrMissingRegion is a sentinel error for missing region conditions.
	ErrMissingRegion      = errors.New("crypto: missing region")
	// ErrMissingLocalKey is a sentinel error for missing local key conditions.
	ErrMissingLocalKey    = errors.New("crypto: missing local key")
)
