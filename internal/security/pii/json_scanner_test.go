package pii

import (
	"bytes"
	"testing"
)

func TestJSONScanner_ScanJSON(t *testing.T) {
	scanner := NewScanner(DefaultDetectors(), nil, 0)
	js := NewJSONScanner(scanner)

	tests := []struct {
		name        string
		body        string
		minFindings int
	}{
		{
			"flat object with SSN",
			`{"ssn":"123-45-6789","name":"John"}`,
			1,
		},
		{
			"nested object",
			`{"user":{"email":"test@example.com","ssn":"234-56-7890"}}`,
			2,
		},
		{
			"array of objects",
			`{"users":[{"email":"a@b.com"},{"email":"c@d.com"}]}`,
			2,
		},
		{
			"no PII",
			`{"name":"John","age":30,"active":true}`,
			0,
		},
		{
			"deeply nested",
			`{"a":{"b":{"c":{"email":"deep@example.com"}}}}`,
			1,
		},
		{
			"mixed types (numbers and bools skipped)",
			`{"count":42,"active":true,"email":"user@test.com"}`,
			1,
		},
		{
			"non-JSON falls back to raw scan",
			`SSN: 345-67-8901`,
			1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := js.ScanJSON([]byte(tt.body), "/test")
			if len(result.Findings) < tt.minFindings {
				t.Errorf("got %d findings, want at least %d", len(result.Findings), tt.minFindings)
			}
		})
	}
}

func TestJSONScanner_ScanJSON_WithAllowlist(t *testing.T) {
	al := NewAllowlist([]AllowlistRule{
		{FieldPath: "user.email", DetectorType: DetectorEmail},
	})
	scanner := NewScanner(DefaultDetectors(), al, 0)
	js := NewJSONScanner(scanner)

	body := []byte(`{"user":{"email":"allowed@test.com","ssn":"456-78-9012"}}`)
	result := js.ScanJSON(body, "/test")

	// Email should be allowed, SSN should be detected
	for _, f := range result.Findings {
		if f.Type == DetectorEmail {
			t.Error("email should be allowlisted but was detected")
		}
	}

	ssnFound := false
	for _, f := range result.Findings {
		if f.Type == DetectorSSN {
			ssnFound = true
		}
	}
	if !ssnFound {
		t.Error("SSN should have been detected")
	}
}

func TestJSONScanner_RedactJSON(t *testing.T) {
	scanner := NewScanner(DefaultDetectors(), nil, 0)
	js := NewJSONScanner(scanner)

	body := []byte(`{"email":"user@example.com","name":"John"}`)
	result := js.ScanJSON(body, "/test")

	if len(result.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	redacted, err := js.RedactJSON(body, result.Findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The redacted body should not contain the original email
	if string(redacted) == string(body) {
		t.Error("redacted body should differ from original")
	}

	// Should contain the redaction placeholder
	if !bytes.Contains(redacted, []byte("[REDACTED-EMAIL]")) {
		t.Errorf("expected redaction placeholder in: %s", string(redacted))
	}
}

