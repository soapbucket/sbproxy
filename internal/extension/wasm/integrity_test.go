package wasm

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyIntegrity(t *testing.T) {
	data := []byte("test wasm binary content")
	hash := sha256.Sum256(data)
	validHash := hex.EncodeToString(hash[:])

	tests := []struct {
		name     string
		data     []byte
		hash     string
		wantErr  bool
	}{
		{"empty hash skips verification", data, "", false},
		{"valid hash passes", data, validHash, false},
		{"invalid hash fails", data, "0000000000000000000000000000000000000000000000000000000000000000", true},
		{"wrong length hash fails", data, "abc", true},
		{"empty data with empty hash", []byte{}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyIntegrity(tt.data, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyIntegrity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyIntegrity_EmptyData(t *testing.T) {
	data := []byte{}
	hash := sha256.Sum256(data)
	validHash := hex.EncodeToString(hash[:])

	if err := VerifyIntegrity(data, validHash); err != nil {
		t.Errorf("VerifyIntegrity() with empty data and valid hash should pass: %v", err)
	}
}

func BenchmarkVerifyIntegrity(b *testing.B) {
	b.ReportAllocs()
	data := make([]byte, 1024*1024) // 1MB
	hash := sha256.Sum256(data)
	validHash := hex.EncodeToString(hash[:])

	for b.Loop() {
		_ = VerifyIntegrity(data, validHash)
	}
}
