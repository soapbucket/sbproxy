package keys

import "testing"

func TestResolveModelAlias(t *testing.T) {
	tests := []struct {
		name      string
		key       *VirtualKey
		requested string
		want      string
	}{
		{
			name:      "nil key returns original",
			key:       nil,
			requested: "gpt-4o",
			want:      "gpt-4o",
		},
		{
			name:      "no aliases returns original",
			key:       &VirtualKey{ID: "sk-sb-1"},
			requested: "gpt-4o",
			want:      "gpt-4o",
		},
		{
			name: "empty aliases map returns original",
			key: &VirtualKey{
				ID:           "sk-sb-2",
				ModelAliases: map[string]string{},
			},
			requested: "gpt-4o",
			want:      "gpt-4o",
		},
		{
			name: "alias resolves to target model",
			key: &VirtualKey{
				ID: "sk-sb-3",
				ModelAliases: map[string]string{
					"fast":  "gpt-4o-mini",
					"smart": "gpt-4o",
				},
			},
			requested: "fast",
			want:      "gpt-4o-mini",
		},
		{
			name: "unknown model passes through",
			key: &VirtualKey{
				ID: "sk-sb-4",
				ModelAliases: map[string]string{
					"fast": "gpt-4o-mini",
				},
			},
			requested: "claude-3-sonnet",
			want:      "claude-3-sonnet",
		},
		{
			name: "empty alias value passes through",
			key: &VirtualKey{
				ID: "sk-sb-5",
				ModelAliases: map[string]string{
					"fast": "",
				},
			},
			requested: "fast",
			want:      "fast",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveModelAlias(tt.key, tt.requested)
			if got != tt.want {
				t.Errorf("ResolveModelAlias() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveModelAlias_PerKeyIsolation(t *testing.T) {
	keyA := &VirtualKey{
		ID: "sk-sb-a",
		ModelAliases: map[string]string{
			"fast": "gpt-4o-mini",
		},
	}
	keyB := &VirtualKey{
		ID: "sk-sb-b",
		ModelAliases: map[string]string{
			"fast": "claude-3-haiku-20240307",
		},
	}

	resultA := ResolveModelAlias(keyA, "fast")
	resultB := ResolveModelAlias(keyB, "fast")

	if resultA != "gpt-4o-mini" {
		t.Errorf("key A: got %q, want %q", resultA, "gpt-4o-mini")
	}
	if resultB != "claude-3-haiku-20240307" {
		t.Errorf("key B: got %q, want %q", resultB, "claude-3-haiku-20240307")
	}
	if resultA == resultB {
		t.Error("per-key isolation failed: both keys resolved to the same model")
	}
}
