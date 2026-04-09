package builtin

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestJWTDetector(t *testing.T) {
	d := &JWTDetector{}

	// Construct a valid-looking JWT for testing.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"John"}`))
	sig := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	validJWT := header + "." + payload + "." + sig

	tests := []struct {
		name      string
		content   string
		config    map[string]any
		triggered bool
	}{
		{
			name:      "JWT detected",
			content:   "Here is a token: " + validJWT,
			config:    nil,
			triggered: true,
		},
		{
			name:      "no JWT in text",
			content:   "This is a normal sentence with no tokens.",
			config:    nil,
			triggered: false,
		},
		{
			name:      "validate mode with valid JWT",
			content:   "Token: " + validJWT,
			config:    map[string]any{"mode": "validate"},
			triggered: true,
		},
		{
			name:      "validate mode with invalid structure",
			content:   "Token: eyJnotvalid.eyJnotvalid.notvalidsig",
			config:    map[string]any{"mode": "validate"},
			triggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &policy.GuardrailConfig{
				ID:     "test-jwt",
				Name:   "JWT Detector",
				Action: policy.GuardrailActionBlock,
				Config: tt.config,
			}
			result, err := d.Detect(context.Background(), cfg, tt.content)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Triggered != tt.triggered {
				t.Errorf("triggered = %v, want %v (details: %s)", result.Triggered, tt.triggered, result.Details)
			}
		})
	}
}
