package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	t.Parallel()
	masterKey := []byte("test-master-key-32-bytes-long!!")
	salt := []byte("test-salt")
	info := []byte("test-context")

	tests := []struct {
		name      string
		masterKey []byte
		salt      []byte
		info      []byte
		keyLength int
		wantErr   bool
	}{
		{
			name:      "valid key derivation",
			masterKey: masterKey,
			salt:      salt,
			info:      info,
			keyLength: 32,
			wantErr:   false,
		},
		{
			name:      "empty master key",
			masterKey: []byte{},
			salt:      salt,
			info:      info,
			keyLength: 32,
			wantErr:   true,
		},
		{
			name:      "zero key length",
			masterKey: masterKey,
			salt:      salt,
			info:      info,
			keyLength: 0,
			wantErr:   true,
		},
		{
			name:      "negative key length",
			masterKey: masterKey,
			salt:      salt,
			info:      info,
			keyLength: -1,
			wantErr:   true,
		},
		{
			name:      "different key lengths",
			masterKey: masterKey,
			salt:      salt,
			info:      info,
			keyLength: 16,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			derivedKey, err := DeriveKey(tt.masterKey, tt.salt, tt.info, tt.keyLength)

			if tt.wantErr {
				if err == nil {
					t.Errorf("DeriveKey() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("DeriveKey() unexpected error: %v", err)
				return
			}

			if len(derivedKey) != tt.keyLength {
				t.Errorf("DeriveKey() key length = %d, want %d", len(derivedKey), tt.keyLength)
			}
		})
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	t.Parallel()
	// Test that key derivation is deterministic
	masterKey := []byte("test-master-key-32-bytes-long!!")
	salt := []byte("test-salt")
	info := []byte("test-context")
	keyLength := 32

	key1, err := DeriveKey(masterKey, salt, info, keyLength)
	if err != nil {
		t.Fatalf("DeriveKey() first call failed: %v", err)
	}

	key2, err := DeriveKey(masterKey, salt, info, keyLength)
	if err != nil {
		t.Fatalf("DeriveKey() second call failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Errorf("DeriveKey() not deterministic: keys don't match")
	}
}

func TestDeriveKeyUniqueness(t *testing.T) {
	t.Parallel()
	// Test that different contexts produce different keys
	masterKey := []byte("test-master-key-32-bytes-long!!")
	keyLength := 32

	key1, err := DeriveKey(masterKey, []byte("salt1"), []byte("context1"), keyLength)
	if err != nil {
		t.Fatalf("DeriveKey() failed: %v", err)
	}

	key2, err := DeriveKey(masterKey, []byte("salt2"), []byte("context1"), keyLength)
	if err != nil {
		t.Fatalf("DeriveKey() failed: %v", err)
	}

	key3, err := DeriveKey(masterKey, []byte("salt1"), []byte("context2"), keyLength)
	if err != nil {
		t.Fatalf("DeriveKey() failed: %v", err)
	}

	// Keys should be different for different salts
	if bytes.Equal(key1, key2) {
		t.Errorf("DeriveKey() produced same key for different salts")
	}

	// Keys should be different for different contexts
	if bytes.Equal(key1, key3) {
		t.Errorf("DeriveKey() produced same key for different contexts")
	}
}

func TestDeriveSessionKey(t *testing.T) {
	t.Parallel()
	masterKey := []byte("test-master-key-32-bytes-long!!")
	sessionID := "test-session-12345"

	key, err := DeriveSessionKey(masterKey, sessionID)
	if err != nil {
		t.Fatalf("DeriveSessionKey() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("DeriveSessionKey() key length = %d, want 32", len(key))
	}

	// Test determinism
	key2, err := DeriveSessionKey(masterKey, sessionID)
	if err != nil {
		t.Fatalf("DeriveSessionKey() second call error: %v", err)
	}

	if !bytes.Equal(key, key2) {
		t.Errorf("DeriveSessionKey() not deterministic")
	}

	// Test uniqueness across sessions
	key3, err := DeriveSessionKey(masterKey, "different-session-67890")
	if err != nil {
		t.Fatalf("DeriveSessionKey() third call error: %v", err)
	}

	if bytes.Equal(key, key3) {
		t.Errorf("DeriveSessionKey() produced same key for different session IDs")
	}
}

func TestDeriveSessionSigningKey(t *testing.T) {
	t.Parallel()
	masterKey := []byte("test-master-key-32-bytes-long!!")
	sessionID := "test-session-12345"

	key, err := DeriveSessionSigningKey(masterKey, sessionID)
	if err != nil {
		t.Fatalf("DeriveSessionSigningKey() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("DeriveSessionSigningKey() key length = %d, want 32", len(key))
	}

	// Signing key should be different from encryption key
	encKey, err := DeriveSessionKey(masterKey, sessionID)
	if err != nil {
		t.Fatalf("DeriveSessionKey() error: %v", err)
	}

	if bytes.Equal(key, encKey) {
		t.Errorf("DeriveSessionSigningKey() produced same key as DeriveSessionKey()")
	}
}

func TestEncryptDecryptWithDerivedKey(t *testing.T) {
	t.Parallel()
	masterKey := []byte("test-master-key-32-bytes-long!!")
	sessionID := "test-session-12345"
	plaintext := []byte("secret session data")

	// Derive a session key
	derivedKey, err := DeriveSessionKey(masterKey, sessionID)
	if err != nil {
		t.Fatalf("DeriveSessionKey() error: %v", err)
	}

	// Encrypt with derived key
	ciphertext, err := encryptWithDerivedKey(plaintext, derivedKey, ProviderLocal)
	if err != nil {
		t.Fatalf("encryptWithDerivedKey() error: %v", err)
	}

	// Decrypt with same derived key
	decrypted, err := decryptWithDerivedKey(ciphertext, derivedKey)
	if err != nil {
		t.Fatalf("decryptWithDerivedKey() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decryptWithDerivedKey() = %s, want %s", decrypted, plaintext)
	}
}

func TestEncryptDecryptWithDerivedKeyDifferentSessions(t *testing.T) {
	t.Parallel()
	masterKey := []byte("test-master-key-32-bytes-long!!")
	plaintext := []byte("secret session data")

	// Session 1
	sessionID1 := "session-1"
	derivedKey1, err := DeriveSessionKey(masterKey, sessionID1)
	if err != nil {
		t.Fatalf("DeriveSessionKey() error: %v", err)
	}

	ciphertext1, err := encryptWithDerivedKey(plaintext, derivedKey1, ProviderLocal)
	if err != nil {
		t.Fatalf("encryptWithDerivedKey() error: %v", err)
	}

	// Session 2
	sessionID2 := "session-2"
	derivedKey2, err := DeriveSessionKey(masterKey, sessionID2)
	if err != nil {
		t.Fatalf("DeriveSessionKey() error: %v", err)
	}

	// Try to decrypt session 1's data with session 2's key (should fail)
	_, err = decryptWithDerivedKey(ciphertext1, derivedKey2)
	if err == nil {
		t.Errorf("decryptWithDerivedKey() should fail when using wrong session key")
	}

	// Decrypt with correct key should work
	decrypted1, err := decryptWithDerivedKey(ciphertext1, derivedKey1)
	if err != nil {
		t.Fatalf("decryptWithDerivedKey() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted1) {
		t.Errorf("decryptWithDerivedKey() = %s, want %s", decrypted1, plaintext)
	}
}

func TestEncryptWithDerivedKeyRandomness(t *testing.T) {
	t.Parallel()
	// Test that encrypting the same plaintext twice produces different ciphertexts
	// (due to random nonce generation)
	masterKey := []byte("test-master-key-32-bytes-long!!")
	sessionID := "test-session"
	plaintext := []byte("secret data")

	derivedKey, err := DeriveSessionKey(masterKey, sessionID)
	if err != nil {
		t.Fatalf("DeriveSessionKey() error: %v", err)
	}

	ciphertext1, err := encryptWithDerivedKey(plaintext, derivedKey, ProviderLocal)
	if err != nil {
		t.Fatalf("encryptWithDerivedKey() first call error: %v", err)
	}

	ciphertext2, err := encryptWithDerivedKey(plaintext, derivedKey, ProviderLocal)
	if err != nil {
		t.Fatalf("encryptWithDerivedKey() second call error: %v", err)
	}

	// Ciphertexts should be different (due to different nonces)
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Errorf("encryptWithDerivedKey() produced identical ciphertexts for same plaintext")
	}

	// But both should decrypt to the same plaintext
	decrypted1, err := decryptWithDerivedKey(ciphertext1, derivedKey)
	if err != nil {
		t.Fatalf("decryptWithDerivedKey() first call error: %v", err)
	}

	decrypted2, err := decryptWithDerivedKey(ciphertext2, derivedKey)
	if err != nil {
		t.Fatalf("decryptWithDerivedKey() second call error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted1) || !bytes.Equal(plaintext, decrypted2) {
		t.Errorf("decryptWithDerivedKey() failed to decrypt correctly")
	}
}
