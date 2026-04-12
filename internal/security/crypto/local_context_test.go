package crypto

import (
	"bytes"
	"testing"
)

func TestLocalCryptoEncryptDecryptWithContext(t *testing.T) {
	t.Parallel()
	// Create a LocalCrypto instance
	encKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	settings := Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: encKey,
		},
	}

	crypto, err := NewLocalCrypto(settings)
	if err != nil {
		t.Fatalf("NewLocalCrypto() error: %v", err)
	}

	plaintext := []byte("sensitive session data")
	context := "session-12345"

	// Encrypt with context
	ciphertext, err := crypto.EncryptWithContext(plaintext, context)
	if err != nil {
		t.Fatalf("EncryptWithContext() error: %v", err)
	}

	// Decrypt with same context
	decrypted, err := crypto.DecryptWithContext(ciphertext, context)
	if err != nil {
		t.Fatalf("DecryptWithContext() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("DecryptWithContext() = %s, want %s", decrypted, plaintext)
	}
}

func TestLocalCryptoContextIsolation(t *testing.T) {
	t.Parallel()
	// Test that different contexts produce isolated encryption
	encKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	settings := Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: encKey,
		},
	}

	crypto, err := NewLocalCrypto(settings)
	if err != nil {
		t.Fatalf("NewLocalCrypto() error: %v", err)
	}

	plaintext := []byte("sensitive session data")
	context1 := "session-12345"
	context2 := "session-67890"

	// Encrypt with context1
	ciphertext1, err := crypto.EncryptWithContext(plaintext, context1)
	if err != nil {
		t.Fatalf("EncryptWithContext() error: %v", err)
	}

	// Encrypt same plaintext with context2
	ciphertext2, err := crypto.EncryptWithContext(plaintext, context2)
	if err != nil {
		t.Fatalf("EncryptWithContext() error: %v", err)
	}

	// Ciphertexts should be different
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Errorf("EncryptWithContext() produced same ciphertext for different contexts")
	}

	// Trying to decrypt context1's data with context2 should fail
	_, err = crypto.DecryptWithContext(ciphertext1, context2)
	if err == nil {
		t.Errorf("DecryptWithContext() should fail when using wrong context")
	}

	// Decrypting with correct context should work
	decrypted1, err := crypto.DecryptWithContext(ciphertext1, context1)
	if err != nil {
		t.Fatalf("DecryptWithContext() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted1) {
		t.Errorf("DecryptWithContext() = %s, want %s", decrypted1, plaintext)
	}

	decrypted2, err := crypto.DecryptWithContext(ciphertext2, context2)
	if err != nil {
		t.Fatalf("DecryptWithContext() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted2) {
		t.Errorf("DecryptWithContext() = %s, want %s", decrypted2, plaintext)
	}
}

func TestLocalCryptoContextDeterminism(t *testing.T) {
	t.Parallel()
	// Test that encryption with the same context produces decryptable results
	// (even though ciphertexts are different due to random nonces)
	encKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	settings := Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: encKey,
		},
	}

	crypto, err := NewLocalCrypto(settings)
	if err != nil {
		t.Fatalf("NewLocalCrypto() error: %v", err)
	}

	plaintext := []byte("test data")
	context := "session-test"

	// Encrypt twice with same context
	ciphertext1, err := crypto.EncryptWithContext(plaintext, context)
	if err != nil {
		t.Fatalf("EncryptWithContext() first call error: %v", err)
	}

	ciphertext2, err := crypto.EncryptWithContext(plaintext, context)
	if err != nil {
		t.Fatalf("EncryptWithContext() second call error: %v", err)
	}

	// Both should decrypt correctly with the same context
	decrypted1, err := crypto.DecryptWithContext(ciphertext1, context)
	if err != nil {
		t.Fatalf("DecryptWithContext() first call error: %v", err)
	}

	decrypted2, err := crypto.DecryptWithContext(ciphertext2, context)
	if err != nil {
		t.Fatalf("DecryptWithContext() second call error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted1) || !bytes.Equal(plaintext, decrypted2) {
		t.Errorf("DecryptWithContext() failed to decrypt correctly")
	}
}

func TestLocalCryptoWithContextVsWithoutContext(t *testing.T) {
	t.Parallel()
	// Test that context-aware encryption is independent from regular encryption
	encKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	settings := Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: encKey,
		},
	}

	crypto, err := NewLocalCrypto(settings)
	if err != nil {
		t.Fatalf("NewLocalCrypto() error: %v", err)
	}

	plaintext := []byte("test data")
	context := "session-test"

	// Regular encryption
	ciphertext1, err := crypto.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Context-aware encryption
	ciphertext2, err := crypto.EncryptWithContext(plaintext, context)
	if err != nil {
		t.Fatalf("EncryptWithContext() error: %v", err)
	}

	// Ciphertexts should be different
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Errorf("Regular and context-aware encryption produced same ciphertext")
	}

	// Regular decrypt should work for regular encryption
	decrypted1, err := crypto.Decrypt(ciphertext1)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted1) {
		t.Errorf("Decrypt() = %s, want %s", decrypted1, plaintext)
	}

	// Context-aware decrypt should work for context-aware encryption
	decrypted2, err := crypto.DecryptWithContext(ciphertext2, context)
	if err != nil {
		t.Fatalf("DecryptWithContext() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted2) {
		t.Errorf("DecryptWithContext() = %s, want %s", decrypted2, plaintext)
	}

	// Cross-decryption should fail
	_, err = crypto.Decrypt(ciphertext2)
	if err == nil {
		t.Errorf("Decrypt() should fail on context-encrypted data")
	}

	_, err = crypto.DecryptWithContext(ciphertext1, context)
	if err == nil {
		t.Errorf("DecryptWithContext() should fail on regularly encrypted data")
	}
}

func TestLocalCryptoEmptyContext(t *testing.T) {
	t.Parallel()
	// Test encryption with empty context
	encKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	settings := Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: encKey,
		},
	}

	crypto, err := NewLocalCrypto(settings)
	if err != nil {
		t.Fatalf("NewLocalCrypto() error: %v", err)
	}

	plaintext := []byte("test data")
	context := ""

	// Encrypt with empty context (should still work)
	ciphertext, err := crypto.EncryptWithContext(plaintext, context)
	if err != nil {
		t.Fatalf("EncryptWithContext() error: %v", err)
	}

	// Decrypt with empty context
	decrypted, err := crypto.DecryptWithContext(ciphertext, context)
	if err != nil {
		t.Fatalf("DecryptWithContext() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("DecryptWithContext() = %s, want %s", decrypted, plaintext)
	}
}

func TestLocalCryptoLargeDataWithContext(t *testing.T) {
	t.Parallel()
	// Test encryption of large data with context
	encKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	settings := Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: encKey,
		},
	}

	crypto, err := NewLocalCrypto(settings)
	if err != nil {
		t.Fatalf("NewLocalCrypto() error: %v", err)
	}

	// Create 1MB of data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	context := "large-session"

	// Encrypt
	ciphertext, err := crypto.EncryptWithContext(plaintext, context)
	if err != nil {
		t.Fatalf("EncryptWithContext() error: %v", err)
	}

	// Decrypt
	decrypted, err := crypto.DecryptWithContext(ciphertext, context)
	if err != nil {
		t.Fatalf("DecryptWithContext() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("DecryptWithContext() failed for large data")
	}
}



