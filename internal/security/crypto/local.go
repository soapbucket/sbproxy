// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// LocalCrypto implements the Crypto interface using AES-256-GCM with a local key
type LocalCrypto struct {
	encryptionKey []byte
	signingKey    []byte
	gcm           cipher.AEAD // Pre-initialized GCM for the encryption key
	driver        string
}

// NewLocalCrypto creates a new local crypto implementation
func NewLocalCrypto(settings Settings) (Crypto, error) {
	// Get encryption key from params
	encryptionKey, ok := settings.Params[ParamEncryptionKey]
	if !ok {
		return nil, ErrMissingLocalKey
	}

	// Decode the base64-encoded encryption key
	encKey, err := DecodeBase64(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to decode encryption key: %w", err)
	}

	// Validate encryption key length (must be 32 bytes for AES-256)
	if len(encKey) != 32 {
		return nil, fmt.Errorf("crypto: encryption key must be 32 bytes (256 bits), got %d bytes", len(encKey))
	}

	// Get signing key from params
	signingKey, ok := settings.Params[ParamSigningKey]
	var signKey []byte
	if !ok {
		// Derive signing key from encryption key using HKDF if no signing key provided
		// This ensures encryption and signing use different keys
		derivedKey, err := DeriveKey(encKey, nil, []byte("hmac-signing"), 32)
		if err != nil {
			return nil, fmt.Errorf("crypto: failed to derive signing key: %w", err)
		}
		signKey = derivedKey
	} else {
		// Decode the base64-encoded signing key if provided
		var err error
		signKey, err = DecodeBase64(signingKey)
		if err != nil {
			return nil, fmt.Errorf("crypto: failed to decode signing key: %w", err)
		}
	}

	// Pre-create AES block cipher and GCM once (key doesn't change between operations)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	return &LocalCrypto{
		encryptionKey: encKey,
		signingKey:    signKey,
		gcm:           gcm,
		driver:        settings.Driver,
	}, nil
}

// Encrypt encrypts data using the configured encryption key
func (c *LocalCrypto) Encrypt(data []byte) ([]byte, error) {
	// Generate nonce (only the nonce changes per operation)
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Encrypt and append nonce to the beginning
	ciphertext := c.gcm.Seal(nonce, nonce, data, nil)

	// Encode to base64 and add provider prefix
	encoded := EncodeBase64(ciphertext)
	return []byte(AddPrefix(ProviderLocal, encoded)), nil
}

// Decrypt decrypts data using the configured encryption key
func (c *LocalCrypto) Decrypt(data []byte) ([]byte, error) {
	// Convert data to string and strip provider prefix if present
	ciphertext := StripPrefix(string(data))

	// Decode from base64
	decoded, err := DecodeBase64(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Extract nonce and ciphertext
	nonceSize := c.gcm.NonceSize()
	if len(decoded) < nonceSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrInvalidCiphertext)
	}

	nonce, cipherData := decoded[:nonceSize], decoded[nonceSize:]

	// Decrypt using pre-initialized GCM
	plaintext, err := c.gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// Sign signs data using the configured signing key with salted hash
func (c *LocalCrypto) Sign(data []byte) ([]byte, error) {
	// Generate a random 16-byte salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Combine salt with data (create a new slice to avoid modifying salt)
	saltedData := make([]byte, 0, len(salt)+len(data))
	saltedData = append(saltedData, salt...)
	saltedData = append(saltedData, data...)

	// Create HMAC with the configured signing key
	h := hmac.New(sha256.New, c.signingKey)
	h.Write(saltedData)
	hmacResult := h.Sum(nil)

	// Combine salt and HMAC for storage
	result := make([]byte, 0, len(salt)+len(hmacResult))
	result = append(result, salt...)
	result = append(result, hmacResult...)
	return result, nil
}

// Verify verifies that data1 was signed with the configured signing key
func (c *LocalCrypto) Verify(data1 []byte, data2 []byte) (bool, error) {
	// data2 should contain salt + signature
	if len(data2) < 16 {
		return false, fmt.Errorf("invalid signature format")
	}

	// Extract salt and signature
	salt := data2[:16]
	signature := data2[16:]

	// Combine salt with data1
	saltedData := make([]byte, 0, len(salt)+len(data1))
	saltedData = append(saltedData, salt...)
	saltedData = append(saltedData, data1...)

	// Create HMAC with the configured signing key
	h := hmac.New(sha256.New, c.signingKey)
	h.Write(saltedData)
	expectedMAC := h.Sum(nil)

	// Compare signatures
	return hmac.Equal(expectedMAC, signature), nil
}

// GenerateKey generates a random 32-byte key for AES-256
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("crypto: failed to generate key: %w", err)
	}
	return EncodeBase64(key), nil
}

// EncryptWithContext encrypts data using a derived key based on context (e.g., session ID)
// This provides better security by ensuring each context uses a unique derived key
func (c *LocalCrypto) EncryptWithContext(data []byte, context string) ([]byte, error) {
	// Derive a unique key for this context using HKDF
	derivedKey, err := DeriveSessionKey(c.encryptionKey, context)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to derive key: %v", ErrEncryptionFailed, err)
	}

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
	return []byte(AddPrefix(ProviderLocal, encoded)), nil
}

// DecryptWithContext decrypts data using a derived key based on context (e.g., session ID)
// The context must match the one used during encryption
func (c *LocalCrypto) DecryptWithContext(data []byte, context string) ([]byte, error) {
	// Derive a unique key for this context using HKDF
	derivedKey, err := DeriveSessionKey(c.encryptionKey, context)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to derive key: %v", ErrDecryptionFailed, err)
	}

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

// Driver returns the driver name
func (c *LocalCrypto) Driver() string {
	return c.driver
}

func init() {
	Register("local", NewLocalCrypto)
}
