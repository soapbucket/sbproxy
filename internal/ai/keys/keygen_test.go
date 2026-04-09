package keys

import (
	"strings"
	"testing"
)

func TestGenerateKey_Format(t *testing.T) {
	rawKey, hashedKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	if !strings.HasPrefix(rawKey, KeyPrefix) {
		t.Errorf("GenerateKey() rawKey = %q, want prefix %q", rawKey, KeyPrefix)
	}

	// sk-sb- (6 chars) + 64 hex chars = 70 chars total
	expectedLen := len(KeyPrefix) + keyRandomBytes*2
	if len(rawKey) != expectedLen {
		t.Errorf("GenerateKey() rawKey length = %d, want %d", len(rawKey), expectedLen)
	}

	// Hashed key should be 64 hex chars (SHA256)
	if len(hashedKey) != 64 {
		t.Errorf("GenerateKey() hashedKey length = %d, want 64", len(hashedKey))
	}
}

func TestGenerateKey_Unique(t *testing.T) {
	raw1, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	raw2, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	if raw1 == raw2 {
		t.Error("GenerateKey() produced duplicate keys")
	}
}

func TestHashKey_Consistency(t *testing.T) {
	rawKey := "sk-sb-abc123"
	hash1 := HashKey(rawKey)
	hash2 := HashKey(rawKey)

	if hash1 != hash2 {
		t.Errorf("HashKey() not consistent: %q != %q", hash1, hash2)
	}
}

func TestHashKey_DifferentInputs(t *testing.T) {
	hash1 := HashKey("sk-sb-key1")
	hash2 := HashKey("sk-sb-key2")

	if hash1 == hash2 {
		t.Error("HashKey() produced same hash for different inputs")
	}
}

func TestGenerateKey_HashMatches(t *testing.T) {
	rawKey, hashedKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	reHashed := HashKey(rawKey)

	if hashedKey != reHashed {
		t.Errorf("GenerateKey() hash mismatch: %q != HashKey(%q) = %q", hashedKey, rawKey, reHashed)
	}
}
