package logging

import (
	"strings"
	"testing"
)

func TestRedactSecrets_OpenAIKeys(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard sk- key",
			input: "key=sk-abc123def456ghi789jkl012mno",
			want:  "key=[REDACTED]",
		},
		{
			name:  "sk-proj key",
			input: "Authorization: sk-proj1234567890abcdefghij",
			want:  "Authorization: [REDACTED]",
		},
		{
			name:  "embedded in JSON",
			input: `{"api_key":"sk-abcdefghij1234567890xyz"}`,
			want:  `{"api_key":"[REDACTED]"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactSecrets(tt.input)
			if got != tt.want {
				t.Errorf("RedactSecrets(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactSecrets_GitHubTokens(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "ghp_ token",
			input: "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			want:  "token=[REDACTED]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactSecrets(tt.input)
			if got != tt.want {
				t.Errorf("RedactSecrets(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactSecrets_AWSKeys(t *testing.T) {
	input := "aws_key=AKIAIOSFODNN7EXAMPLE more text"
	got := RedactSecrets(input)
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected AKIA key to be redacted, got %q", got)
	}
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key should not appear in output, got %q", got)
	}
}

func TestRedactSecrets_BearerTokens(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "bearer with JWT",
			input: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
			want:  "Authorization: [REDACTED]",
		},
		{
			name:  "bearer with opaque token",
			input: "Bearer abc123-def456_ghi.789+jkl/mno=",
			want:  "[REDACTED]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactSecrets(tt.input)
			if got != tt.want {
				t.Errorf("RedactSecrets(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactSecrets_BasicAuth(t *testing.T) {
	input := "Basic dXNlcjpwYXNzd29yZA=="
	got := RedactSecrets(input)
	if got != "[REDACTED]" {
		t.Errorf("RedactSecrets(%q) = %q, want %q", input, got, "[REDACTED]")
	}
}

func TestRedactSecrets_SecretReferences(t *testing.T) {
	input := `vault ref secret:my-api-key/path end`
	got := RedactSecrets(input)
	if strings.Contains(got, "my-api-key") {
		t.Errorf("secret reference should be redacted, got %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output, got %q", got)
	}
}

func TestRedactSecrets_NoSecrets(t *testing.T) {
	inputs := []string{
		"just a normal log line",
		"status_code=200 duration_ms=42.5",
		"GET /api/v1/health HTTP/1.1",
		"",
	}
	for _, input := range inputs {
		got := RedactSecrets(input)
		if got != input {
			t.Errorf("RedactSecrets(%q) = %q, should be unchanged", input, got)
		}
	}
}

func TestRedactSecrets_MultipleSecrets(t *testing.T) {
	input := "key1=sk-abcdefghij1234567890xyz key2=AKIAIOSFODNN7EXAMPLE"
	got := RedactSecrets(input)
	count := strings.Count(got, "[REDACTED]")
	if count != 2 {
		t.Errorf("expected 2 redactions, got %d in %q", count, got)
	}
}

func TestRedactHeader(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		value     string
		wantValue string
	}{
		{
			name:      "authorization header",
			header:    "Authorization",
			value:     "Bearer eyJtoken",
			wantValue: "[REDACTED]",
		},
		{
			name:      "authorization lowercase",
			header:    "authorization",
			value:     "Basic dXNlcjpwYXNz",
			wantValue: "[REDACTED]",
		},
		{
			name:      "x-api-key header",
			header:    "X-Api-Key",
			value:     "sk-something",
			wantValue: "[REDACTED]",
		},
		{
			name:      "proxy-authorization",
			header:    "Proxy-Authorization",
			value:     "Basic abc123",
			wantValue: "[REDACTED]",
		},
		{
			name:      "api-key header",
			header:    "Api-Key",
			value:     "my-secret-key",
			wantValue: "[REDACTED]",
		},
		{
			name:      "content-type not redacted",
			header:    "Content-Type",
			value:     "application/json",
			wantValue: "application/json",
		},
		{
			name:      "non-sensitive with secret pattern",
			header:    "X-Custom",
			value:     "sk-abcdefghij1234567890xyz",
			wantValue: "[REDACTED]",
		},
		{
			name:      "non-sensitive without secret",
			header:    "X-Request-ID",
			value:     "req-abc-123",
			wantValue: "req-abc-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactHeader(tt.header, tt.value)
			if got != tt.wantValue {
				t.Errorf("RedactHeader(%q, %q) = %q, want %q", tt.header, tt.value, got, tt.wantValue)
			}
		})
	}
}
