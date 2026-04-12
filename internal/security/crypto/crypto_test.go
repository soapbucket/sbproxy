package crypto

import (
	"os"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if key == "" {
		t.Fatal("GenerateKey returned empty key")
	}

	// Decode to verify it's valid base64 and correct length
	decoded, err := DecodeBase64(key)
	if err != nil {
		t.Fatalf("Generated key is not valid base64: %v", err)
	}

	if len(decoded) != 32 {
		t.Fatalf("Generated key is not 32 bytes, got %d", len(decoded))
	}
}

func TestLocalEncryption(t *testing.T) {
	t.Parallel()
	// Generate a key
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Create crypto
	crypto, err := NewCrypto(Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: key,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}

	// Test data
	plaintext := []byte("my-secret-password-12345")

	// Encrypt
	ciphertext, err := crypto.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify it has the correct prefix
	ciphertextStr := string(ciphertext)
	if !IsEncrypted(ciphertextStr) {
		t.Fatal("Ciphertext is not marked as encrypted")
	}

	provider, err := GetProvider(ciphertextStr)
	if err != nil {
		t.Fatalf("Failed to get provider: %v", err)
	}

	if provider != ProviderLocal {
		t.Fatalf("Expected provider %s, got %s", ProviderLocal, provider)
	}

	// Decrypt
	decrypted, err := crypto.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify
	if string(decrypted) != string(plaintext) {
		t.Fatalf("Decrypted text doesn't match. Expected %s, got %s", plaintext, decrypted)
	}
}

func TestLocalEncryptionWithoutPrefix(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	crypto, err := NewCrypto(Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: key,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}

	plaintext := []byte("test-value")
	ciphertext, err := crypto.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Strip prefix and try to decrypt
	ciphertextStr := string(ciphertext)
	stripped := StripPrefix(ciphertextStr)
	decrypted, err := crypto.Decrypt([]byte(stripped))
	if err != nil {
		t.Fatalf("Decrypt without prefix failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("Decrypted text doesn't match. Expected %s, got %s", plaintext, decrypted)
	}
}

func TestIsEncrypted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value    string
		expected bool
	}{
		{"local:AbCdEfGhIjKlMnOpQrSt", true},
		{"gcp:XyZ789AbCdEfGhIjKlMnOp", true},
		{"aws:DEF456AbCdEfGhIjKlMnOp", true},
		{"local:abc123", false},       // too short after prefix (< 16 chars)
		{"gcp:short", false},          // too short after prefix
		{"local:development", false},  // not base64 (contains no valid pattern match for casual text)
		{"plain-text", false},
		{"", false},
		{"invalid:prefix:value", false},
	}

	for _, tt := range tests {
		result := IsEncrypted(tt.value)
		if result != tt.expected {
			t.Errorf("IsEncrypted(%q) = %v, expected %v", tt.value, result, tt.expected)
		}
	}
}

func TestGetProvider(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value       string
		expected    Provider
		expectError bool
	}{
		{"local:abc123", ProviderLocal, false},
		{"gcp:xyz789", ProviderGCP, false},
		{"aws:def456", ProviderAWS, false},
		{"invalid:test", "", true},
		{"no-prefix", "", true},
	}

	for _, tt := range tests {
		result, err := GetProvider(tt.value)
		if tt.expectError {
			if err == nil {
				t.Errorf("GetProvider(%q) expected error, got nil", tt.value)
			}
		} else {
			if err != nil {
				t.Errorf("GetProvider(%q) unexpected error: %v", tt.value, err)
			}
			if result != tt.expected {
				t.Errorf("GetProvider(%q) = %v, expected %v", tt.value, result, tt.expected)
			}
		}
	}
}

func TestDecryptorFromEnv(t *testing.T) {
	// Save original env vars
	origLocalKey := os.Getenv("CRYPTO_LOCAL_KEY")
	defer os.Setenv("CRYPTO_LOCAL_KEY", origLocalKey)

	// Generate a test key
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Set env var
	os.Setenv("CRYPTO_LOCAL_KEY", key)

	// Create decryptor from env
	decryptor, err := NewDecryptorFromEnv()
	if err != nil {
		t.Fatalf("NewDecryptorFromEnv failed: %v", err)
	}

	// Encrypt a value
	crypto, err := NewCrypto(Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: key,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}

	plaintext := "test-secret"
	encrypted, err := crypto.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt using decryptor
	decrypted, err := decryptor.DecryptString(string(encrypted))
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("Decrypted text doesn't match. Expected %s, got %s", plaintext, decrypted)
	}
}

func TestDecryptStruct(t *testing.T) {
	t.Parallel()
	// Generate a key
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Create crypto
	crypto, err := NewCrypto(Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: key,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}

	// Encrypt values
	encryptedPassword, err := crypto.Encrypt([]byte("secret-password"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	encryptedAPIKey, err := crypto.Encrypt([]byte("api-key-12345"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Create test struct
	type TestConfig struct {
		Host     string
		Port     int
		Password string
		APIKey   string
		Nested   struct {
			Secret string
		}
	}

	config := &TestConfig{
		Host:     "localhost",
		Port:     5432,
		Password: string(encryptedPassword),
		APIKey:   string(encryptedAPIKey),
		Nested: struct{ Secret string }{
			Secret: "plain-text",
		},
	}

	// Create decryptor
	decryptor, err := NewDecryptor(&DecryptorConfig{
		Providers: map[string]*Settings{
			"local": {
				Driver: "local",
				Params: map[string]string{
					"encryption_key": key,
					"signing_key":    key,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}

	// Decrypt struct
	if err := decryptor.DecryptStruct(config); err != nil {
		t.Fatalf("DecryptStruct failed: %v", err)
	}

	// Verify
	if config.Password != "secret-password" {
		t.Errorf("Password not decrypted correctly. Got %s", config.Password)
	}

	if config.APIKey != "api-key-12345" {
		t.Errorf("APIKey not decrypted correctly. Got %s", config.APIKey)
	}

	if config.Host != "localhost" {
		t.Errorf("Host was modified. Got %s", config.Host)
	}

	if config.Port != 5432 {
		t.Errorf("Port was modified. Got %d", config.Port)
	}
}

func TestMaskValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value    string
		expected string
	}{
		{"local:AbCdEfGhIjKlMnOpQrSt", "local:AbCd...QrSt"},
		{"gcp:XyZ789AbCdEfGhIjKlMnOp", "gcp:XyZ7...MnOp"},
		{"plain-text-value", "pl**********ue"},
		{"test", "****"},
		{"", "****"},
	}

	for _, tt := range tests {
		result := MaskValue(tt.value)
		if result != tt.expected {
			t.Errorf("MaskValue(%q) = %q, expected %q", tt.value, result, tt.expected)
		}
	}
}

func TestInvalidConfigs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		settings Settings
	}{
		{
			name: "Local without key",
			settings: Settings{
				Driver: "local",
				Params: map[string]string{},
			},
		},
		{
			name: "GCP without project",
			settings: Settings{
				Driver: "gcp",
				Params: map[string]string{
					"location": "global",
					"key_ring": "test",
					"key_id":   "test",
				},
			},
		},
		{
			name: "AWS without region",
			settings: Settings{
				Driver: "aws",
				Params: map[string]string{
					"key_id": "test",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewCrypto(tt.settings)
			if err == nil {
				t.Error("Expected error for invalid config, got nil")
			}
		})
	}
}

func TestAvailableDrivers(t *testing.T) {
	t.Parallel()
	drivers := AvailableDrivers()

	// Should have at least local driver
	if len(drivers) == 0 {
		t.Fatal("Expected at least one driver, got none")
	}

	// Check that local driver is available
	found := false
	for _, driver := range drivers {
		if driver == "local" {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("Expected 'local' driver to be available")
	}
}

func TestSignAndVerify(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	crypto, err := NewCrypto(Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: key,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}

	data := []byte("test data to sign")

	// Sign the data
	signature, err := crypto.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify the signature
	valid, err := crypto.Verify(data, signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !valid {
		t.Fatal("Signature verification failed")
	}

	// Test with different data (should fail)
	wrongData := []byte("different data")
	valid, err = crypto.Verify(wrongData, signature)
	if err != nil {
		t.Fatalf("Verify with wrong data failed: %v", err)
	}

	if valid {
		t.Fatal("Signature should be invalid with wrong data")
	}
}

func TestGCPSigning(t *testing.T) {
	// Skip if GCP credentials are not available
	if os.Getenv("GCP_PROJECT_ID") == "" {
		t.Skip("GCP credentials not available")
	}

	crypto, err := NewCrypto(Settings{
		Driver: "gcp",
		Params: map[string]string{
			ParamProjectID: os.Getenv("GCP_PROJECT_ID"),
			ParamLocation:  os.Getenv("GCP_LOCATION"),
			ParamKeyRing:   os.Getenv("GCP_KEYRING"),
			ParamKeyID:     os.Getenv("GCP_KEY_ID"),
		},
	})
	if err != nil {
		t.Fatalf("Failed to create GCP crypto: %v", err)
	}

	data := []byte("test data to sign with GCP")

	// Sign the data
	signature, err := crypto.Sign(data)
	if err != nil {
		t.Fatalf("GCP Sign failed: %v", err)
	}

	// Verify the signature
	valid, err := crypto.Verify(data, signature)
	if err != nil {
		t.Fatalf("GCP Verify failed: %v", err)
	}

	if !valid {
		t.Fatal("GCP signature verification failed")
	}

	// Test with different data (should fail)
	wrongData := []byte("different data")
	valid, err = crypto.Verify(wrongData, signature)
	if err != nil {
		t.Fatalf("GCP Verify with wrong data failed: %v", err)
	}

	if valid {
		t.Fatal("GCP signature should be invalid with wrong data")
	}
}

func TestAWSSigning(t *testing.T) {
	// Skip if AWS credentials are not available
	if os.Getenv("AWS_REGION") == "" || os.Getenv("AWS_KMS_KEY_ID") == "" {
		t.Skip("AWS credentials not available")
	}

	crypto, err := NewCrypto(Settings{
		Driver: "aws",
		Params: map[string]string{
			ParamRegion: os.Getenv("AWS_REGION"),
			ParamKeyID:  os.Getenv("AWS_KMS_KEY_ID"),
		},
	})
	if err != nil {
		t.Fatalf("Failed to create AWS crypto: %v", err)
	}

	data := []byte("test data to sign with AWS")

	// Sign the data
	signature, err := crypto.Sign(data)
	if err != nil {
		t.Fatalf("AWS Sign failed: %v", err)
	}

	// Verify the signature
	valid, err := crypto.Verify(data, signature)
	if err != nil {
		t.Fatalf("AWS Verify failed: %v", err)
	}

	if !valid {
		t.Fatal("AWS signature verification failed")
	}

	// Test with different data (should fail)
	wrongData := []byte("different data")
	valid, err = crypto.Verify(wrongData, signature)
	if err != nil {
		t.Fatalf("AWS Verify with wrong data failed: %v", err)
	}

	if valid {
		t.Fatal("AWS signature should be invalid with wrong data")
	}
}

func TestSaltedHashSigning(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	crypto, err := NewCrypto(Settings{
		Driver: "local",
		Params: map[string]string{
			ParamEncryptionKey: key,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}

	data := []byte("test data to sign")
	// Sign the same data twice
	signature1, err := crypto.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	signature2, err := crypto.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Signatures should be different due to salt
	if string(signature1) == string(signature2) {
		t.Fatal("Signatures should be different due to salt")
	}

	// Both signatures should verify
	valid1, err := crypto.Verify(data, signature1)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid1 {
		t.Fatal("First signature verification failed")
	}

	valid2, err := crypto.Verify(data, signature2)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid2 {
		t.Fatal("Second signature verification failed")
	}
}
