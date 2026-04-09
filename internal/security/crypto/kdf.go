// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey derives a key from a master key using HKDF-SHA256
// masterKey: the master key to derive from
// salt: unique salt for key derivation (e.g., session ID)
// info: context information (e.g., "session-encryption")
// keyLength: desired length of derived key (32 bytes for AES-256)
func DeriveKey(masterKey []byte, salt []byte, info []byte, keyLength int) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("crypto: master key cannot be empty")
	}
	if keyLength <= 0 {
		return nil, fmt.Errorf("crypto: key length must be positive")
	}
	if keyLength > 255*sha256.Size {
		return nil, fmt.Errorf("crypto: key length too large for HKDF")
	}

	// Create HKDF reader with SHA-256
	hkdfReader := hkdf.New(sha256.New, masterKey, salt, info)

	// Derive key
	derivedKey := make([]byte, keyLength)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("crypto: failed to derive key: %w", err)
	}

	return derivedKey, nil
}

// DeriveSessionKey derives a unique session key from the master encryption key
// This is a convenience function that uses standard parameters for session encryption
func DeriveSessionKey(masterKey []byte, sessionID string) ([]byte, error) {
	// Use session ID as salt
	salt := []byte(sessionID)
	
	// Use "session-encryption" as context info
	info := []byte("session-encryption")
	
	// Derive 32-byte key for AES-256
	return DeriveKey(masterKey, salt, info, 32)
}

// DeriveSessionSigningKey derives a unique session signing key from the master signing key
// This is a convenience function that uses standard parameters for session signing
func DeriveSessionSigningKey(masterKey []byte, sessionID string) ([]byte, error) {
	// Use session ID as salt
	salt := []byte(sessionID)
	
	// Use "session-signing" as context info
	info := []byte("session-signing")
	
	// Derive 32-byte key for HMAC-SHA256
	return DeriveKey(masterKey, salt, info, 32)
}

// encryptWithDerivedKey is a helper function to encrypt data with a derived key
// Used by cloud KMS providers to avoid repeated KMS calls
func encryptWithDerivedKey(data []byte, derivedKey []byte, provider Provider) ([]byte, error) {
	// Create AES cipher with derived key
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Encrypt and append nonce to the beginning
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Encode to base64 and add provider prefix
	encoded := EncodeBase64(ciphertext)
	return []byte(AddPrefix(provider, encoded)), nil
}

// decryptWithDerivedKey is a helper function to decrypt data with a derived key
// Used by cloud KMS providers to avoid repeated KMS calls
func decryptWithDerivedKey(data []byte, derivedKey []byte) ([]byte, error) {
	// Convert data to string and strip provider prefix if present
	ciphertext := StripPrefix(string(data))

	// Decode from base64
	decoded, err := DecodeBase64(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Create AES cipher with derived key
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(decoded) < nonceSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrInvalidCiphertext)
	}

	nonce, cipherData := decoded[:nonceSize], decoded[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

