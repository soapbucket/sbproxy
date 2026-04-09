package fingerprint

import (
	"crypto/tls"
	"testing"
)

func TestGetTLSVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected uint16
	}{
		{
			name:     "TLS 1.2",
			input:    12,
			expected: tls.VersionTLS12,
		},
		{
			name:     "TLS 1.3",
			input:    13,
			expected: tls.VersionTLS13,
		},
		{
			name:     "Default (invalid value)",
			input:    0,
			expected: tls.VersionTLS13,
		},
		{
			name:     "Default (negative value)",
			input:    -1,
			expected: tls.VersionTLS13,
		},
		{
			name:     "Default (high value)",
			input:    14,
			expected: tls.VersionTLS13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetTLSVersion(tt.input)
			if result != tt.expected {
				t.Errorf("GetTLSVersion(%d) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetTLSCiphersFromNames(t *testing.T) {
	tests := []struct {
		name      string
		cipherNames []string
		wantCount  int
		wantEmpty  bool
	}{
		{
			name:       "Valid cipher names",
			cipherNames: []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
			wantCount:  2,
			wantEmpty:  false,
		},
		{
			name:       "Empty list",
			cipherNames: []string{},
			wantCount:  0,
			wantEmpty:  true,
		},
		{
			name:       "Invalid cipher names",
			cipherNames: []string{"INVALID_CIPHER", "ALSO_INVALID"},
			wantCount:  0,
			wantEmpty:  true,
		},
		{
			name:       "Mixed valid and invalid",
			cipherNames: []string{"TLS_AES_128_GCM_SHA256", "INVALID_CIPHER"},
			wantCount:  1,
			wantEmpty:  false,
		},
		{
			name:       "Duplicate cipher names",
			cipherNames: []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"},
			wantCount:  1,
			wantEmpty:  false,
		},
		{
			name:       "Cipher names with whitespace",
			cipherNames: []string{" TLS_AES_128_GCM_SHA256 ", "  TLS_AES_256_GCM_SHA384  "},
			wantCount:  2,
			wantEmpty:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetTLSCiphersFromNames(tt.cipherNames)
			
			if tt.wantEmpty {
				if len(result) != 0 {
					t.Errorf("GetTLSCiphersFromNames(%v) = %v, want empty slice", tt.cipherNames, result)
				}
			} else {
				if len(result) != tt.wantCount {
					t.Errorf("GetTLSCiphersFromNames(%v) returned %d ciphers, want %d", tt.cipherNames, len(result), tt.wantCount)
				}
				
				// Verify all returned values are valid cipher suite IDs
				for _, cipherID := range result {
					found := false
					for _, suite := range tls.CipherSuites() {
						if suite.ID == cipherID {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("GetTLSCiphersFromNames(%v) returned invalid cipher ID: %d", tt.cipherNames, cipherID)
					}
				}
			}
		})
	}
}

func TestGetTLSCiphersFromNames_AllTLS13Ciphers(t *testing.T) {
	// Test that we can get all TLS 1.3 cipher suites
	tls13Ciphers := []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
	}
	
	result := GetTLSCiphersFromNames(tls13Ciphers)
	if len(result) != 3 {
		t.Errorf("GetTLSCiphersFromNames(%v) returned %d ciphers, want 3", tls13Ciphers, len(result))
	}
}

