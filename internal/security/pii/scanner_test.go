package pii

import (
	"testing"
)

func TestSSNDetector(t *testing.T) {
	d := NewSSNDetector()
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"valid SSN", "My SSN is 123-45-6789", 1},
		{"no SSN", "Hello world 12345", 0},
		{"invalid area 000", "SSN is 000-12-3456", 0},
		{"invalid area 666", "SSN is 666-12-3456", 0},
		{"invalid area 900+", "SSN is 900-12-3456", 0},
		{"multiple SSNs", "A: 123-45-6789 B: 234-56-7890", 2},
		{"SSN in JSON value", `"ssn":"456-78-9012"`, 1},
		{"not an SSN (too short)", "12-34-5678", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect([]byte(tt.input), "")
			if len(findings) != tt.expected {
				t.Errorf("got %d findings, want %d", len(findings), tt.expected)
			}
		})
	}
}

func TestSSNDetector_Redact(t *testing.T) {
	d := NewSSNDetector()
	redacted := d.Redact("123-45-6789")
	if redacted != "***-**-6789" {
		t.Errorf("got %q, want %q", redacted, "***-**-6789")
	}
}

func TestCreditCardDetector(t *testing.T) {
	d := NewCreditCardDetector()
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Visa valid Luhn", "Card: 4111111111111111", 1},
		{"Mastercard valid", "MC: 5500000000000004", 1},
		{"Amex valid", "Amex: 378282246310005", 1},
		{"Discover valid", "Disc: 6011111111111117", 1},
		{"invalid Luhn", "Card: 4111111111111112", 0},
		{"with spaces", "Card: 4111 1111 1111 1111", 1},
		{"with dashes", "Card: 4111-1111-1111-1111", 1},
		{"no card", "Just some text", 0},
		{"too short", "4111 1111", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect([]byte(tt.input), "")
			if len(findings) != tt.expected {
				t.Errorf("got %d findings, want %d", len(findings), tt.expected)
			}
		})
	}
}

func TestCreditCardDetector_Redact(t *testing.T) {
	d := NewCreditCardDetector()
	redacted := d.Redact("4111111111111111")
	if redacted != "****-****-****-1111" {
		t.Errorf("got %q, want %q", redacted, "****-****-****-1111")
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		number string
		valid  bool
	}{
		{"4111111111111111", true},   // Visa
		{"5500000000000004", true},   // Mastercard
		{"378282246310005", true},    // Amex
		{"6011111111111117", true},   // Discover
		{"4111111111111112", false},  // Invalid
		{"0000000000000000", true},   // All zeros (valid Luhn)
		{"1234", false},              // Too short
		{"", false},                  // Empty
		{"41111111111111111111", false}, // Too long
	}

	for _, tt := range tests {
		t.Run(tt.number, func(t *testing.T) {
			got := luhnCheck(tt.number)
			if got != tt.valid {
				t.Errorf("luhnCheck(%q) = %v, want %v", tt.number, got, tt.valid)
			}
		})
	}
}

func TestEmailDetector(t *testing.T) {
	d := NewEmailDetector()
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"simple email", "contact: user@example.com", 1},
		{"multiple emails", "a@b.com and c@d.org", 2},
		{"no email", "Hello world", 0},
		{"email with dots", "first.last@example.co.uk", 1},
		{"email with plus", "user+tag@example.com", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect([]byte(tt.input), "")
			if len(findings) != tt.expected {
				t.Errorf("got %d findings, want %d", len(findings), tt.expected)
			}
		})
	}
}

func TestPhoneDetector(t *testing.T) {
	d := NewPhoneDetector()
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"US phone", "Call 555-123-4567", 1},
		{"US phone with parens", "Phone: (555) 123-4567", 1},
		{"US phone with +1", "Call +1-555-123-4567", 1},
		{"no phone", "Hello world", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect([]byte(tt.input), "")
			if len(findings) != tt.expected {
				t.Errorf("got %d findings, want %d", len(findings), tt.expected)
			}
		})
	}
}

func TestAPIKeyDetector(t *testing.T) {
	d := NewAPIKeyDetector()
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Stripe key", "key: sk_abcdefghijklmnopqrstuv", 1},
		{"generic api key", "token_12345678901234567890ab", 1},
		{"AWS access key", "AKIAIOSFODNN7EXAMPLE", 1},
		{"short string", "sk_ab", 0},
		{"no key", "just regular text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect([]byte(tt.input), "")
			if len(findings) != tt.expected {
				t.Errorf("got %d findings, want %d", len(findings), tt.expected)
			}
		})
	}
}

func TestJWTDetector(t *testing.T) {
	d := NewJWTDetector()
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"valid JWT", "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", 1},
		{"no JWT", "just some text", 0},
		{"partial JWT", "eyJhbGciOiJIUzI1NiJ9.missing", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect([]byte(tt.input), "")
			if len(findings) != tt.expected {
				t.Errorf("got %d findings, want %d", len(findings), tt.expected)
			}
		})
	}
}

func TestScanner_Scan(t *testing.T) {
	scanner := NewScanner(DefaultDetectors(), nil, 0)

	tests := []struct {
		name        string
		input       string
		minFindings int
	}{
		{"SSN in text", "SSN: 123-45-6789", 1},
		{"email in text", "Email: user@example.com", 1},
		{"mixed PII", "SSN: 123-45-6789, email: user@example.com, card: 4111111111111111", 3},
		{"clean text", "Hello world, no PII here", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.Scan([]byte(tt.input), "/test")
			if len(result.Findings) < tt.minFindings {
				t.Errorf("got %d findings, want at least %d", len(result.Findings), tt.minFindings)
			}
		})
	}
}

func TestScanner_MaxBodySize(t *testing.T) {
	scanner := NewScanner(DefaultDetectors(), nil, 20)
	// SSN is beyond the 20-byte limit
	result := scanner.Scan([]byte("some padding text...123-45-6789"), "/test")
	if !result.Truncated {
		t.Error("expected result to be truncated")
	}
}

func TestAllowlist(t *testing.T) {
	al := NewAllowlist([]AllowlistRule{
		{FieldPath: "user.email", DetectorType: DetectorEmail, PathPrefix: "/api/login"},
		{FieldPath: "*.phone", DetectorType: DetectorPhone},
	})

	tests := []struct {
		name         string
		fieldPath    string
		detectorType DetectorType
		requestPath  string
		expected     bool
	}{
		{"allowed email at login", "user.email", DetectorEmail, "/api/login", true},
		{"email at other path", "user.email", DetectorEmail, "/api/users", false},
		{"phone wildcard", "contact.phone", DetectorPhone, "/any/path", true},
		{"SSN not allowed", "user.ssn", DetectorSSN, "/api/login", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := al.IsAllowed(tt.fieldPath, tt.detectorType, tt.requestPath)
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNilAllowlist(t *testing.T) {
	var al *Allowlist
	if al.IsAllowed("any", DetectorSSN, "/") {
		t.Error("nil allowlist should never allow")
	}
}
