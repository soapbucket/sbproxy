package vault

import (
	"testing"
)

func TestSecretWarner_DetectsKnownPatterns(t *testing.T) {
	tests := []struct {
		name      string
		fieldName string
		value     string
		wantWarn  bool
	}{
		{
			name:      "OpenAI API key",
			fieldName: "openai_key",
			value:     "sk-abcdefghijklmnopqrstuvwxyz1234567890",
			wantWarn:  true,
		},
		{
			name:      "GitHub personal access token",
			fieldName: "github_token",
			value:     "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			wantWarn:  true,
		},
		{
			name:      "AWS access key",
			fieldName: "aws_key",
			value:     "AKIAIOSFODNN7EXAMPLE",
			wantWarn:  true,
		},
		{
			name:      "Slack bot token",
			fieldName: "slack_token",
			value:     "xoxb-123456789012-abcdefghij",
			wantWarn:  true,
		},
		{
			name:      "GitLab personal access token",
			fieldName: "gitlab_token",
			value:     "glpat-abcdefghijklmnopqrstuvwxyz",
			wantWarn:  true,
		},
		{
			name:      "Stripe live secret key",
			fieldName: "stripe_key",
			value:     "sk_test_fake_not_real_placeholder_value",
			wantWarn:  true,
		},
		{
			name:      "plain text - not a secret",
			fieldName: "hostname",
			value:     "example.com",
			wantWarn:  false,
		},
		{
			name:      "empty value",
			fieldName: "empty",
			value:     "",
			wantWarn:  false,
		},
		{
			name:      "vault reference - skip",
			fieldName: "key",
			value:     "vault:api_key",
			wantWarn:  false,
		},
		{
			name:      "secret reference - skip",
			fieldName: "key",
			value:     "secret:api_key",
			wantWarn:  false,
		},
		{
			name:      "template reference - skip",
			fieldName: "key",
			value:     "{{secrets.API_KEY}}",
			wantWarn:  false,
		},
		{
			name:      "env var reference - skip",
			fieldName: "key",
			value:     "${API_KEY}",
			wantWarn:  false,
		},
		{
			name:      "file reference - skip",
			fieldName: "key",
			value:     "file:/etc/secrets/key",
			wantWarn:  false,
		},
		{
			name:      "short string - not a secret",
			fieldName: "flag",
			value:     "sk",
			wantWarn:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh warner for each test to avoid dedup
			w := NewSecretWarner()
			got := w.CheckAndWarn(tt.fieldName, tt.value)
			if got != tt.wantWarn {
				t.Errorf("CheckAndWarn(%q, %q) = %v, want %v", tt.fieldName, tt.value, got, tt.wantWarn)
			}
		})
	}
}

func TestSecretWarner_DeduplicatesWarnings(t *testing.T) {
	sw := NewSecretWarner()

	apiKey := "sk-abcdefghijklmnopqrstuvwxyz1234567890"

	// First call should warn
	if !sw.CheckAndWarn("api_key", apiKey) {
		t.Error("first CheckAndWarn() should return true")
	}

	// Second call for same field should not warn again
	if sw.CheckAndWarn("api_key", apiKey) {
		t.Error("second CheckAndWarn() for same field should return false (dedup)")
	}

	// Different field name with same pattern should still warn
	if !sw.CheckAndWarn("other_key", apiKey) {
		t.Error("CheckAndWarn() for different field should return true")
	}
}

func TestSecretWarner_Reset(t *testing.T) {
	sw := NewSecretWarner()

	apiKey := "sk-abcdefghijklmnopqrstuvwxyz1234567890"

	sw.CheckAndWarn("api_key", apiKey)

	// After reset, the same field should warn again
	sw.Reset()

	if !sw.CheckAndWarn("api_key", apiKey) {
		t.Error("CheckAndWarn() after Reset() should return true")
	}
}

func TestPatternHint(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"sk-abc", "sk-a***"},
		{"sk-abcdefghij", "sk-abc***"},
		{"abc", "***"},
		{"abcd", "abcd***"},
	}

	for _, tt := range tests {
		got := patternHint(tt.input)
		if got != tt.want {
			t.Errorf("patternHint(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsSecretReference(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"vault:api_key", true},
		{"secret:api_key", true},
		{"{{secrets.KEY}}", true},
		{"${ENV_VAR}", true},
		{"file:/path/to/secret", true},
		{"plain-text", false},
		{"", false},
		{"v", false},
	}

	for _, tt := range tests {
		got := isSecretReference(tt.input)
		if got != tt.want {
			t.Errorf("isSecretReference(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
