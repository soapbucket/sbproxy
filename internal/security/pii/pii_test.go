package pii

import (
	"strings"
	"testing"
)

func TestRedact_Mask(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		detectors []string
		contains  string
		absent    string
	}{
		{
			name:      "SSN masked",
			input:     "My SSN is 123-45-6789",
			detectors: []string{"ssn"},
			contains:  "***-**-6789",
			absent:    "123-45-6789",
		},
		{
			name:      "email masked",
			input:     "Email: user@example.com",
			detectors: []string{"email"},
			contains:  "[REDACTED-EMAIL]",
			absent:    "user@example.com",
		},
		{
			name:      "credit card masked",
			input:     "Card: 4111111111111111",
			detectors: []string{"credit_card"},
			contains:  "****-****-****-1111",
			absent:    "4111111111111111",
		},
		{
			name:      "no detectors uses all defaults",
			input:     "SSN 123-45-6789 email user@example.com",
			detectors: nil,
			absent:    "123-45-6789",
		},
		{
			name:      "clean text unchanged",
			input:     "Hello world, no PII here",
			detectors: nil,
			contains:  "Hello world, no PII here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Redact(tt.input, tt.detectors, ModeMask)
			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("expected result to contain %q, got %q", tt.contains, result)
			}
			if tt.absent != "" && strings.Contains(result, tt.absent) {
				t.Errorf("expected result NOT to contain %q, got %q", tt.absent, result)
			}
		})
	}
}

func TestRedact_Hash(t *testing.T) {
	input := "SSN: 123-45-6789"
	result := Redact(input, []string{"ssn"}, ModeHash)
	if !strings.Contains(result, "sha256:") {
		t.Errorf("expected sha256: prefix, got %q", result)
	}
	if strings.Contains(result, "123-45-6789") {
		t.Error("SSN should have been replaced in hash mode")
	}
}

func TestRedact_Remove(t *testing.T) {
	input := "SSN: 123-45-6789 is here"
	result := Redact(input, []string{"ssn"}, ModeRemove)
	if strings.Contains(result, "123-45-6789") {
		t.Error("SSN should have been removed")
	}
	if !strings.Contains(result, "SSN:") {
		t.Error("surrounding text should remain")
	}
}

func TestRedactBytes(t *testing.T) {
	input := []byte("Email: user@example.com")
	result := RedactBytes(input, []string{"email"}, ModeMask)
	if strings.Contains(string(result), "user@example.com") {
		t.Error("email should have been redacted")
	}
	if !strings.Contains(string(result), "[REDACTED-EMAIL]") {
		t.Errorf("expected [REDACTED-EMAIL], got %q", string(result))
	}
}

func TestRedactBytes_Empty(t *testing.T) {
	result := RedactBytes(nil, nil, ModeMask)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
	result = RedactBytes([]byte{}, nil, ModeMask)
	if len(result) != 0 {
		t.Errorf("expected empty, got %v", result)
	}
}

func TestAWSKeyDetector(t *testing.T) {
	d := NewAWSKeyDetector()
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"valid AWS key", "key: AKIAIOSFODNN7EXAMPLE", 1},
		{"no AWS key", "just regular text", 0},
		{"short AKIA", "AKIA1234", 0},
		{"AWS key in JSON", `"access_key":"AKIAIOSFODNN7EXAMPLE"`, 1},
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

func TestAWSKeyDetector_Redact(t *testing.T) {
	d := NewAWSKeyDetector()
	redacted := d.Redact("AKIAIOSFODNN7EXAMPLE")
	if redacted != "AKIA****************" {
		t.Errorf("got %q, want %q", redacted, "AKIA****************")
	}
}

func TestPrivateKeyDetector(t *testing.T) {
	d := NewPrivateKeyDetector()
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"RSA private key", "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----", 1},
		{"EC private key", "-----BEGIN EC PRIVATE KEY-----\ndata", 1},
		{"generic private key", "-----BEGIN PRIVATE KEY-----\ndata", 1},
		{"public key (not private)", "-----BEGIN PUBLIC KEY-----\ndata", 0},
		{"no key", "just some text", 0},
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

func TestPrivateKeyDetector_Redact(t *testing.T) {
	d := NewPrivateKeyDetector()
	redacted := d.Redact("-----BEGIN RSA PRIVATE KEY-----")
	if redacted != "[REDACTED-PRIVATE-KEY]" {
		t.Errorf("got %q, want %q", redacted, "[REDACTED-PRIVATE-KEY]")
	}
}

func TestDBConnectionStringDetector(t *testing.T) {
	d := NewDBConnectionStringDetector()
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"postgres URI", "conn: postgres://user:pass@localhost:5432/mydb", 1},
		{"postgresql URI", "conn: postgresql://user:pass@localhost/mydb", 1},
		{"mysql URI", "conn: mysql://user:pass@localhost:3306/mydb", 1},
		{"mongodb URI", "conn: mongodb://user:pass@localhost:27017/mydb", 1},
		{"mongodb+srv", "conn: mongodb+srv://user:pass@cluster.example.com/mydb", 1},
		{"redis URI", "conn: redis://user:pass@localhost:6379/0", 1},
		{"rediss URI", "conn: rediss://user:pass@localhost:6380/0", 1},
		{"no connection string", "just regular text", 0},
		{"partial URI no host", "postgres://", 0},
		{"URI with only host", "postgres://localhost", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect([]byte(tt.input), "")
			if len(findings) != tt.expected {
				t.Errorf("got %d findings, want %d for input %q", len(findings), tt.expected, tt.input)
			}
		})
	}
}

func TestDBConnectionStringDetector_Redact(t *testing.T) {
	d := NewDBConnectionStringDetector()
	redacted := d.Redact("postgres://user:pass@localhost:5432/mydb")
	if redacted != "[REDACTED-DB-CONNECTION]" {
		t.Errorf("got %q, want %q", redacted, "[REDACTED-DB-CONNECTION]")
	}
}

func TestAllDetectors(t *testing.T) {
	dets := AllDetectors()
	// Should include the 6 defaults plus 3 extended (AWS key, private key, DB connection)
	if len(dets) != 9 {
		t.Errorf("expected 9 detectors, got %d", len(dets))
	}

	types := make(map[DetectorType]bool)
	for _, d := range dets {
		types[d.Type()] = true
	}

	expected := []DetectorType{
		DetectorSSN, DetectorCreditCard, DetectorEmail, DetectorPhone,
		DetectorAPIKey, DetectorJWT, DetectorAWSKey, DetectorPrivateKey,
		DetectorDBConnectionString,
	}
	for _, dt := range expected {
		if !types[dt] {
			t.Errorf("AllDetectors() missing %s", dt)
		}
	}
}

func TestDetectorForName(t *testing.T) {
	tests := []struct {
		name     string
		expected DetectorType
	}{
		{"ssn", DetectorSSN},
		{"credit_card", DetectorCreditCard},
		{"email", DetectorEmail},
		{"phone", DetectorPhone},
		{"ip_address", DetectorIPAddress},
		{"api_key", DetectorAPIKey},
		{"jwt", DetectorJWT},
		{"aws_key", DetectorAWSKey},
		{"private_key", DetectorPrivateKey},
		{"db_connection_string", DetectorDBConnectionString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := DetectorForName(tt.name)
			if d == nil {
				t.Fatalf("DetectorForName(%q) returned nil", tt.name)
			}
			if d.Type() != tt.expected {
				t.Errorf("got type %s, want %s", d.Type(), tt.expected)
			}
		})
	}
}

func TestDetectorForName_Unknown(t *testing.T) {
	d := DetectorForName("nonexistent")
	if d != nil {
		t.Error("expected nil for unknown detector name")
	}
}

func TestRedact_MultipleDetectors(t *testing.T) {
	input := "SSN: 123-45-6789, email: user@example.com, key: AKIAIOSFODNN7EXAMPLE"
	result := Redact(input, []string{"ssn", "email", "aws_key"}, ModeMask)

	if strings.Contains(result, "123-45-6789") {
		t.Error("SSN should be redacted")
	}
	if strings.Contains(result, "user@example.com") {
		t.Error("email should be redacted")
	}
	if strings.Contains(result, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS key should be redacted")
	}
}

func TestRedact_PrivateKeyInBody(t *testing.T) {
	input := `Config: -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds...
-----END RSA PRIVATE KEY-----`
	result := Redact(input, []string{"private_key"}, ModeMask)
	if strings.Contains(result, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("private key header should be redacted")
	}
	if !strings.Contains(result, "[REDACTED-PRIVATE-KEY]") {
		t.Errorf("expected [REDACTED-PRIVATE-KEY], got %q", result)
	}
}

func TestRedact_DBConnectionString(t *testing.T) {
	input := `DATABASE_URL=postgres://admin:secret@db.example.com:5432/production`
	result := Redact(input, []string{"db_connection_string"}, ModeMask)
	if strings.Contains(result, "postgres://admin:secret") {
		t.Error("DB connection string should be redacted")
	}
	if !strings.Contains(result, "[REDACTED-DB-CONNECTION]") {
		t.Errorf("expected [REDACTED-DB-CONNECTION], got %q", result)
	}
}
