package security

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewSRIGenerator(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"sha256", SRIAlgorithmSHA256, false},
		{"sha384", SRIAlgorithmSHA384, false},
		{"sha512", SRIAlgorithmSHA512, false},
		{"default", "", false},
		{"invalid", "md5", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewSRIGenerator(tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSRIGenerator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && gen == nil {
				t.Error("NewSRIGenerator() returned nil generator")
			}
		})
	}
}

func TestSRIGenerator_GenerateHash(t *testing.T) {
	data := []byte("test data")

	tests := []struct {
		name      string
		algorithm string
	}{
		{"sha256", SRIAlgorithmSHA256},
		{"sha384", SRIAlgorithmSHA384},
		{"sha512", SRIAlgorithmSHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewSRIGenerator(tt.algorithm)
			if err != nil {
				t.Fatalf("NewSRIGenerator() error = %v", err)
			}

			hash, err := gen.GenerateHash(data)
			if err != nil {
				t.Fatalf("GenerateHash() error = %v", err)
			}

			// Verify it's valid base64
			_, err = base64.StdEncoding.DecodeString(hash)
			if err != nil {
				t.Errorf("GenerateHash() returned invalid base64: %v", err)
			}

			// Verify hash matches expected
			var expectedHash []byte
			switch tt.algorithm {
			case SRIAlgorithmSHA256:
				h := sha256.Sum256(data)
				expectedHash = h[:]
			case SRIAlgorithmSHA384:
				h := sha512.Sum384(data)
				expectedHash = h[:]
			case SRIAlgorithmSHA512:
				h := sha512.Sum512(data)
				expectedHash = h[:]
			}

			expectedBase64 := base64.StdEncoding.EncodeToString(expectedHash)
			if hash != expectedBase64 {
				t.Errorf("GenerateHash() = %v, want %v", hash, expectedBase64)
			}
		})
	}
}

func TestSRIGenerator_GenerateIntegrityAttribute(t *testing.T) {
	data := []byte("test data")
	gen, err := NewSRIGenerator(SRIAlgorithmSHA384)
	if err != nil {
		t.Fatalf("NewSRIGenerator() error = %v", err)
	}

	integrity, err := gen.GenerateIntegrityAttribute(data)
	if err != nil {
		t.Fatalf("GenerateIntegrityAttribute() error = %v", err)
	}

	// Should start with algorithm prefix
	if !strings.HasPrefix(integrity, "sha384-") {
		t.Errorf("GenerateIntegrityAttribute() = %v, want prefix sha384-", integrity)
	}

	// Should be valid base64 after prefix
	hashPart := strings.TrimPrefix(integrity, "sha384-")
	_, err = base64.StdEncoding.DecodeString(hashPart)
	if err != nil {
		t.Errorf("GenerateIntegrityAttribute() returned invalid base64: %v", err)
	}
}

func TestSRIGenerator_GenerateHashFromReader(t *testing.T) {
	data := []byte("test data")
	reader := bytes.NewReader(data)

	gen, err := NewSRIGenerator(SRIAlgorithmSHA256)
	if err != nil {
		t.Fatalf("NewSRIGenerator() error = %v", err)
	}

	hash1, err := gen.GenerateHashFromReader(reader)
	if err != nil {
		t.Fatalf("GenerateHashFromReader() error = %v", err)
	}

	// Generate hash directly for comparison
	hash2, err := gen.GenerateHash(data)
	if err != nil {
		t.Fatalf("GenerateHash() error = %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("GenerateHashFromReader() = %v, GenerateHash() = %v, want equal", hash1, hash2)
	}
}

func TestSRIValidator_ValidateIntegrity(t *testing.T) {
	knownHashes := map[string][]string{
		"https://example.com/script.js": {
			"sha384-abc123",
			"sha384-def456",
		},
	}

	validator := NewSRIValidator(knownHashes)

	tests := []struct {
		name      string
		url       string
		integrity string
		wantErr   bool
	}{
		{"valid hash", "https://example.com/script.js", "sha384-abc123", false},
		{"valid hash alternate", "https://example.com/script.js", "sha384-def456", false},
		{"invalid hash", "https://example.com/script.js", "sha384-invalid", true},
		{"unknown resource", "https://example.com/other.js", "sha384-abc123", true},
		{"empty integrity", "https://example.com/script.js", "", true},
		{"multiple hashes", "https://example.com/script.js", "sha384-xyz789 sha384-abc123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateIntegrity(tt.url, tt.integrity)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIntegrity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSRIValidator_ValidateResponse(t *testing.T) {
	knownHashes := map[string][]string{
		"https://example.com/script.js": {
			"sha384-abc123",
		},
	}

	validator := NewSRIValidator(knownHashes)

	tests := []struct {
		name      string
		url       string
		integrity string
		wantErr   bool
	}{
		{"valid integrity header", "https://example.com/script.js", "sha384-abc123", false},
		{"invalid integrity header", "https://example.com/script.js", "sha384-invalid", true},
		{"no integrity header", "https://example.com/script.js", "", true},
		{"integrity in link header", "https://example.com/script.js", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, nil)
			resp := httptest.NewRecorder()

			if tt.integrity != "" {
				resp.Header().Set("Integrity", tt.integrity)
			} else if tt.name == "integrity in link header" {
				resp.Header().Set("Link", `<https://example.com/script.js>; rel="preload"; integrity="sha384-abc123"`)
			}

			httpResp := resp.Result()
			httpResp.Request = req

			err := validator.ValidateResponse(httpResp)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSRIValidator_AddKnownHash(t *testing.T) {
	validator := NewSRIValidator(nil)

	url := "https://example.com/script.js"
	hash := "sha384-abc123"

	validator.AddKnownHash(url, hash)

	hashes := validator.GetKnownHashes(url)
	if len(hashes) != 1 || hashes[0] != hash {
		t.Errorf("AddKnownHash() failed, got %v, want [%v]", hashes, hash)
	}
}

func TestExtractIntegrityFromLinkHeader(t *testing.T) {
	tests := []struct {
		name       string
		linkHeader string
		want       string
	}{
		{"valid link header", `<https://example.com/script.js>; rel="preload"; integrity="sha384-abc123"`, "sha384-abc123"},
		{"no integrity", `<https://example.com/script.js>; rel="preload"`, ""},
		{"multiple attributes", `<https://example.com/script.js>; rel="preload"; crossorigin="anonymous"; integrity="sha384-def456"`, "sha384-def456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIntegrityFromLinkHeader(tt.linkHeader)
			if got != tt.want {
				t.Errorf("extractIntegrityFromLinkHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}
