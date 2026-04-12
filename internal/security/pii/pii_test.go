package pii

import (
	"testing"
)

// --- Scanner ---

func TestNewScanner_NonNil(t *testing.T) {
	s := NewScanner(nil, nil, 0)
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
}

func TestNewScanner_DefaultMaxSize(t *testing.T) {
	s := NewScanner(nil, nil, 0)
	if s.MaxSize() != DefaultMaxBodySize {
		t.Fatalf("expected default max size %d, got %d", DefaultMaxBodySize, s.MaxSize())
	}
}

func TestNewScanner_NegativeMaxSize(t *testing.T) {
	s := NewScanner(nil, nil, -100)
	if s.MaxSize() != DefaultMaxBodySize {
		t.Fatalf("expected default max size %d for negative input, got %d", DefaultMaxBodySize, s.MaxSize())
	}
}

func TestNewScanner_CustomMaxSize(t *testing.T) {
	s := NewScanner(nil, nil, 4096)
	if s.MaxSize() != 4096 {
		t.Fatalf("expected max size 4096, got %d", s.MaxSize())
	}
}

func TestScanner_ScanEmpty(t *testing.T) {
	s := NewScanner(nil, nil, 0)
	result := s.Scan(nil, "")
	if result == nil {
		t.Fatal("Scan returned nil result")
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings on empty input, got %d", len(result.Findings))
	}
	if result.Truncated {
		t.Fatal("expected Truncated=false on empty input")
	}
}

func TestScanner_ScanNonEmpty(t *testing.T) {
	s := NewScanner(nil, nil, 0)
	result := s.Scan([]byte("my SSN is 123-45-6789"), "body")
	if result == nil {
		t.Fatal("Scan returned nil result")
	}
	// No-op scanner should return no findings regardless of content.
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings from no-op scanner, got %d", len(result.Findings))
	}
}

// --- Buffer lifecycle ---

func TestGetBuffer_NonNil(t *testing.T) {
	buf := GetBuffer()
	if buf == nil {
		t.Fatal("GetBuffer returned nil")
	}
	if *buf == nil {
		t.Fatal("GetBuffer returned pointer to nil slice")
	}
}

func TestGetBuffer_Capacity(t *testing.T) {
	buf := GetBuffer()
	if cap(*buf) != 8*1024 {
		t.Fatalf("expected buffer capacity 8192, got %d", cap(*buf))
	}
	if len(*buf) != 0 {
		t.Fatalf("expected buffer length 0, got %d", len(*buf))
	}
}

func TestPutBuffer_NoPanic(t *testing.T) {
	buf := GetBuffer()
	// PutBuffer is a no-op but should not panic.
	PutBuffer(buf)
	PutBuffer(nil)
}

// --- Allowlist ---

func TestNewAllowlist_Empty(t *testing.T) {
	al := NewAllowlist(nil)
	// OSS build returns nil.
	if al != nil {
		t.Fatal("expected nil allowlist from OSS build")
	}
}

func TestNewAllowlist_WithRules(t *testing.T) {
	rules := []AllowlistRule{
		{FieldPath: "body.email", DetectorType: DetectorEmail},
	}
	al := NewAllowlist(rules)
	if al != nil {
		t.Fatal("expected nil allowlist from OSS build even with rules")
	}
}

// IsAllowed is called on a nil receiver in production (since NewAllowlist
// returns nil in OSS). The Scanner passes nil *Allowlist, so we verify
// the method works on a zero-value Allowlist as well.
func TestAllowlist_IsAllowed(t *testing.T) {
	al := &Allowlist{}
	if al.IsAllowed("body.email", DetectorEmail, "/api/v1") {
		t.Fatal("expected IsAllowed to return false")
	}
}

// --- Detector factories ---

func TestDetectorFactories(t *testing.T) {
	tests := []struct {
		name     string
		factory  func() Detector
		wantType DetectorType
	}{
		{"SSN", NewSSNDetector, DetectorSSN},
		{"CreditCard", NewCreditCardDetector, DetectorCreditCard},
		{"Email", NewEmailDetector, DetectorEmail},
		{"Phone", NewPhoneDetector, DetectorPhone},
		{"IPAddress", NewIPAddressDetector, DetectorIPAddress},
		{"APIKey", NewAPIKeyDetector, DetectorAPIKey},
		{"JWT", NewJWTDetector, DetectorJWT},
		{"AWSKey", NewAWSKeyDetector, DetectorAWSKey},
		{"PrivateKey", NewPrivateKeyDetector, DetectorPrivateKey},
		{"DBConnectionString", NewDBConnectionStringDetector, DetectorDBConnectionString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.factory()
			if d == nil {
				t.Fatal("factory returned nil detector")
			}
			if d.Type() != tt.wantType {
				t.Fatalf("expected type %q, got %q", tt.wantType, d.Type())
			}
			// No-op: Detect should return nil.
			if findings := d.Detect([]byte("test data"), "field"); findings != nil {
				t.Fatalf("expected nil findings, got %v", findings)
			}
			// No-op: MatchesFlags should return false.
			if d.MatchesFlags(HasDigit | HasDash) {
				t.Fatal("expected MatchesFlags to return false")
			}
			// Redact should return a redacted placeholder.
			if r := d.Redact("secret"); r != "[REDACTED]" {
				t.Fatalf("expected [REDACTED], got %q", r)
			}
		})
	}
}

func TestDetectorDetectTo_NoOp(t *testing.T) {
	d := NewSSNDetector()
	var findings []Finding
	d.DetectTo([]byte("123-45-6789"), "field", &findings)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings after DetectTo, got %d", len(findings))
	}
}

// --- Global functions ---

func TestDefaultDetectors_Empty(t *testing.T) {
	if d := DefaultDetectors(); d != nil {
		t.Fatalf("expected nil from DefaultDetectors, got %v", d)
	}
}

func TestAllDetectors_Empty(t *testing.T) {
	if d := AllDetectors(); d != nil {
		t.Fatalf("expected nil from AllDetectors, got %v", d)
	}
}

func TestDetectorForName_Nil(t *testing.T) {
	if d := DetectorForName("email"); d != nil {
		t.Fatalf("expected nil from DetectorForName, got %v", d)
	}
}

func TestRedact_PassThrough(t *testing.T) {
	input := "my email is test@example.com"
	result := Redact(input, []string{"email"}, ModeMask)
	if result != input {
		t.Fatalf("expected input unchanged, got %q", result)
	}
}

func TestRedactBytes_PassThrough(t *testing.T) {
	input := []byte("credit card 4111111111111111")
	result := RedactBytes(input, []string{"credit_card"}, ModeRemove)
	if string(result) != string(input) {
		t.Fatalf("expected input unchanged, got %q", string(result))
	}
}

// --- Finding ---

func TestFinding_GetRedacted_WithRedactFn(t *testing.T) {
	f := &Finding{
		Value:    "secret",
		redactFn: func(s string) string { return "***" },
	}
	if got := f.GetRedacted(); got != "***" {
		t.Fatalf("expected '***', got %q", got)
	}
	// Second call should use cached value.
	if got := f.GetRedacted(); got != "***" {
		t.Fatalf("expected cached '***', got %q", got)
	}
}

func TestFinding_GetRedacted_PreSet(t *testing.T) {
	f := &Finding{
		Value:    "secret",
		Redacted: "already-redacted",
	}
	if got := f.GetRedacted(); got != "already-redacted" {
		t.Fatalf("expected 'already-redacted', got %q", got)
	}
}

func TestFinding_GetRedacted_NoFn(t *testing.T) {
	f := &Finding{Value: "secret"}
	if got := f.GetRedacted(); got != "" {
		t.Fatalf("expected empty string when no redactFn and no Redacted, got %q", got)
	}
}

// --- AITrafficScanner ---

func TestNewAITrafficScanner(t *testing.T) {
	cfg := AITrafficScannerConfig{
		Enabled:       true,
		ScanRequests:  true,
		ScanResponses: true,
		Mode:          ModeMask,
	}
	s := NewAITrafficScanner(cfg)
	if s == nil {
		t.Fatal("NewAITrafficScanner returned nil")
	}
}

func TestAITrafficScanner_ScanRequest(t *testing.T) {
	s := NewAITrafficScanner(AITrafficScannerConfig{Enabled: true})
	result, err := s.ScanRequest([]byte(`{"prompt":"tell me secrets"}`), "openai", "gpt-4")
	if err != nil {
		t.Fatalf("ScanRequest error: %v", err)
	}
	if result == nil {
		t.Fatal("ScanRequest returned nil result")
	}
	if result.Action != "pass" {
		t.Fatalf("expected action 'pass', got %q", result.Action)
	}
	if result.HasPII {
		t.Fatal("expected HasPII=false from no-op scanner")
	}
}

func TestAITrafficScanner_ScanResponse(t *testing.T) {
	s := NewAITrafficScanner(AITrafficScannerConfig{Enabled: true})
	result, err := s.ScanResponse([]byte(`{"text":"response"}`), "openai", "gpt-4")
	if err != nil {
		t.Fatalf("ScanResponse error: %v", err)
	}
	if result.Action != "pass" {
		t.Fatalf("expected action 'pass', got %q", result.Action)
	}
}

func TestAITrafficScanner_Stats(t *testing.T) {
	s := NewAITrafficScanner(AITrafficScannerConfig{})
	stats := s.Stats()
	if stats.RequestsScanned != 0 || stats.ResponsesScanned != 0 ||
		stats.FindingsCount != 0 || stats.BlockedCount != 0 || stats.RedactedCount != 0 {
		t.Fatalf("expected all zero stats, got %+v", stats)
	}
}

// --- JSONScanner ---

func TestNewJSONScanner(t *testing.T) {
	js := NewJSONScanner(nil)
	if js == nil {
		t.Fatal("NewJSONScanner returned nil")
	}
}

func TestJSONScanner_ScanJSON(t *testing.T) {
	js := NewJSONScanner(nil)
	body := []byte(`{"email":"test@example.com","name":"Alice"}`)
	result := js.ScanJSON(body, "body")
	if result == nil {
		t.Fatal("ScanJSON returned nil")
	}
	if result.ScannedSize != int64(len(body)) {
		t.Fatalf("expected ScannedSize %d, got %d", len(body), result.ScannedSize)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestJSONScanner_RedactJSON(t *testing.T) {
	js := NewJSONScanner(nil)
	body := []byte(`{"secret":"value"}`)
	result, err := js.RedactJSON(body, nil)
	if err != nil {
		t.Fatalf("RedactJSON error: %v", err)
	}
	if string(result) != string(body) {
		t.Fatalf("expected body unchanged, got %q", string(result))
	}
}

// --- LuaDetector ---

func TestNewLuaDetector(t *testing.T) {
	d, err := NewLuaDetector("custom_ssn", "function detect(data) end", nil)
	if err != nil {
		t.Fatalf("NewLuaDetector error: %v", err)
	}
	if d == nil {
		t.Fatal("NewLuaDetector returned nil")
	}
	if d.Type() != DetectorCustom {
		t.Fatalf("expected type %q, got %q", DetectorCustom, d.Type())
	}
	if r := d.Redact("value"); r != "[REDACTED-custom_ssn]" {
		t.Fatalf("expected '[REDACTED-custom_ssn]', got %q", r)
	}
	if d.MatchesFlags(HasDigit) {
		t.Fatal("expected MatchesFlags to return false")
	}
	if findings := d.Detect([]byte("data"), "field"); findings != nil {
		t.Fatalf("expected nil findings, got %v", findings)
	}
}

func TestLuaDetector_DetectTo(t *testing.T) {
	d, _ := NewLuaDetector("test", "", nil)
	var findings []Finding
	d.DetectTo([]byte("data"), "field", &findings)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// --- Constants ---

func TestRedactionModes(t *testing.T) {
	if ModeMask != "mask" {
		t.Fatalf("expected ModeMask='mask', got %q", ModeMask)
	}
	if ModeHash != "hash" {
		t.Fatalf("expected ModeHash='hash', got %q", ModeHash)
	}
	if ModeRemove != "remove" {
		t.Fatalf("expected ModeRemove='remove', got %q", ModeRemove)
	}
}

func TestDefaultMaxBodySize(t *testing.T) {
	if DefaultMaxBodySize != 1*1024*1024 {
		t.Fatalf("expected 1MB, got %d", DefaultMaxBodySize)
	}
}

// --- CandidateFlags ---

func TestCandidateFlags(t *testing.T) {
	// Verify flags are distinct powers of two.
	flags := []CandidateFlags{HasDigit, HasDash, HasAt, HasDot, HasUnderscore, HasAKIA, HasEYJ, HasColon}
	for i := 0; i < len(flags); i++ {
		for j := i + 1; j < len(flags); j++ {
			if flags[i]&flags[j] != 0 {
				t.Fatalf("flags at index %d and %d overlap", i, j)
			}
		}
	}
	// Verify combining works.
	combined := HasDigit | HasAt | HasDot
	if combined&HasDigit == 0 || combined&HasAt == 0 || combined&HasDot == 0 {
		t.Fatal("combined flags missing expected bits")
	}
	if combined&HasDash != 0 {
		t.Fatal("combined flags should not include HasDash")
	}
}
