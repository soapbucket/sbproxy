package vault

import (
	"testing"
)

func TestParseSecretReference(t *testing.T) {
	tests := []struct {
		name      string
		ref       string
		wantVault string
		wantPath  string
		wantErr   bool
	}{
		{
			name:      "system vault",
			ref:       "system:/gateway/cb-secret",
			wantVault: "system",
			wantPath:  "/gateway/cb-secret",
		},
		{
			name:      "hashicorp vault",
			ref:       "hashi:/kv/data/api-key",
			wantVault: "hashi",
			wantPath:  "/kv/data/api-key",
		},
		{
			name:      "simple path",
			ref:       "local:mykey",
			wantVault: "local",
			wantPath:  "mykey",
		},
		{
			name:    "no colon",
			ref:     "invalidref",
			wantErr: true,
		},
		{
			name:    "empty vault name",
			ref:     ":path",
			wantErr: true,
		},
		{
			name:    "empty path",
			ref:     "vault:",
			wantErr: true,
		},
		{
			name:    "empty string",
			ref:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := ParseSecretReference(tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSecretReference(%q) error = nil, want error", tt.ref)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSecretReference(%q) error = %v", tt.ref, err)
			}
			if ref.VaultName != tt.wantVault {
				t.Errorf("VaultName = %q, want %q", ref.VaultName, tt.wantVault)
			}
			if ref.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", ref.Path, tt.wantPath)
			}
		})
	}
}
