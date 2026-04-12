// Package pii provides PII detection and redaction stubs.
//
// In the open-source build, PII detection is a no-op. All functions return the
// input unchanged and report no findings.
package pii

// Redaction modes.
const (
	ModeMask   = "mask"
	ModeHash   = "hash"
	ModeRemove = "remove"
)

// DetectorType identifies the kind of PII detected.
type DetectorType string

const (
	DetectorSSN                DetectorType = "ssn"
	DetectorCreditCard         DetectorType = "credit_card"
	DetectorEmail              DetectorType = "email"
	DetectorPhone              DetectorType = "phone"
	DetectorIPAddress          DetectorType = "ip_address"
	DetectorAPIKey             DetectorType = "api_key"
	DetectorJWT                DetectorType = "jwt"
	DetectorCustom             DetectorType = "custom"
	DetectorAWSKey             DetectorType = "aws_key"
	DetectorPrivateKey         DetectorType = "private_key"
	DetectorDBConnectionString DetectorType = "db_connection_string"
)

// CandidateFlags represents the set of characters found in a block of data.
type CandidateFlags uint32

const (
	HasDigit CandidateFlags = 1 << iota
	HasDash
	HasAt
	HasDot
	HasUnderscore
	HasAKIA
	HasEYJ
	HasColon
)

// Finding represents a single PII detection in scanned content.
type Finding struct {
	Type       DetectorType
	Value      string
	Redacted   string
	FieldPath  string
	Start      int
	End        int
	Confidence float64
	redactFn   func(string) string
}

// GetRedacted returns the redacted value.
func (f *Finding) GetRedacted() string {
	if f.Redacted == "" && f.redactFn != nil {
		f.Redacted = f.redactFn(f.Value)
	}
	return f.Redacted
}

// ScanResult holds all findings from a scan operation.
type ScanResult struct {
	Findings    []Finding
	ScannedSize int64
	Truncated   bool
}

// DefaultMaxBodySize is the default maximum body size to scan (1MB).
const DefaultMaxBodySize int64 = 1 * 1024 * 1024

// Detector is the interface for PII detection implementations.
type Detector interface {
	Type() DetectorType
	Detect(data []byte, fieldPath string) []Finding
	DetectTo(data []byte, fieldPath string, findings *[]Finding)
	Redact(value string) string
	MatchesFlags(flags CandidateFlags) bool
}

// noopDetector is a Detector that never finds anything.
type noopDetector struct {
	detectorType DetectorType
}

func (d *noopDetector) Type() DetectorType                        { return d.detectorType }
func (d *noopDetector) Detect(_ []byte, _ string) []Finding       { return nil }
func (d *noopDetector) DetectTo(_ []byte, _ string, _ *[]Finding) {}
func (d *noopDetector) Redact(_ string) string                    { return "[REDACTED]" }
func (d *noopDetector) MatchesFlags(_ CandidateFlags) bool        { return false }

// Factory functions - all return no-op detectors.

func NewSSNDetector() Detector        { return &noopDetector{detectorType: DetectorSSN} }
func NewCreditCardDetector() Detector { return &noopDetector{detectorType: DetectorCreditCard} }
func NewEmailDetector() Detector      { return &noopDetector{detectorType: DetectorEmail} }
func NewPhoneDetector() Detector      { return &noopDetector{detectorType: DetectorPhone} }
func NewIPAddressDetector() Detector  { return &noopDetector{detectorType: DetectorIPAddress} }
func NewAPIKeyDetector() Detector     { return &noopDetector{detectorType: DetectorAPIKey} }
func NewJWTDetector() Detector        { return &noopDetector{detectorType: DetectorJWT} }
func NewAWSKeyDetector() Detector     { return &noopDetector{detectorType: DetectorAWSKey} }
func NewPrivateKeyDetector() Detector { return &noopDetector{detectorType: DetectorPrivateKey} }
func NewDBConnectionStringDetector() Detector {
	return &noopDetector{detectorType: DetectorDBConnectionString}
}

// DefaultDetectors returns an empty set of detectors (no-op in open-source build).
func DefaultDetectors() []Detector { return nil }

// AllDetectors returns an empty set of detectors (no-op in open-source build).
func AllDetectors() []Detector { return nil }

// DetectorForName returns nil (no-op in open-source build).
func DetectorForName(_ string) Detector { return nil }

// Redact returns the input unchanged (no-op in open-source build).
func Redact(input string, _ []string, _ string) string { return input }

// RedactBytes returns the input unchanged (no-op in open-source build).
func RedactBytes(input []byte, _ []string, _ string) []byte { return input }

// Scanner coordinates multiple detectors to scan content for PII.
type Scanner struct {
	maxSize int64
}

// NewScanner creates a Scanner. In the open-source build, all scans are no-ops.
func NewScanner(_ []Detector, _ *Allowlist, maxSize int64) *Scanner {
	if maxSize <= 0 {
		maxSize = DefaultMaxBodySize
	}
	return &Scanner{maxSize: maxSize}
}

// MaxSize returns the maximum body size this scanner will process.
func (s *Scanner) MaxSize() int64 { return s.maxSize }

// Scan returns an empty result (no-op in open-source build).
func (s *Scanner) Scan(_ []byte, _ string) *ScanResult {
	return &ScanResult{}
}

// GetBuffer returns a pooled byte buffer.
func GetBuffer() *[]byte {
	b := make([]byte, 0, 8*1024)
	return &b
}

// PutBuffer is a no-op in the open-source build.
func PutBuffer(_ *[]byte) {}

// AllowlistRule defines an exemption from PII detection.
type AllowlistRule struct {
	FieldPath    string       `json:"field_path"`
	DetectorType DetectorType `json:"detector_type,omitempty"`
	PathPrefix   string       `json:"path_prefix,omitempty"`
}

// Allowlist holds rules that exempt certain fields from PII detection.
type Allowlist struct{}

// NewAllowlist creates an Allowlist (no-op in open-source build).
func NewAllowlist(_ []AllowlistRule) *Allowlist { return nil }

// IsAllowed always returns false (no-op in open-source build).
func (a *Allowlist) IsAllowed(_ string, _ DetectorType, _ string) bool { return false }

// AITrafficScannerConfig configures PII scanning for AI traffic.
type AITrafficScannerConfig struct {
	Enabled         bool           `json:"enabled,omitempty"`
	ScanRequests    bool           `json:"scan_requests,omitempty"`
	ScanResponses   bool           `json:"scan_responses,omitempty"`
	Mode            string         `json:"mode,omitempty"`
	Detectors       []DetectorType `json:"detectors,omitempty"`
	ExemptModels    []string       `json:"exempt_models,omitempty"`
	ExemptProviders []string       `json:"exempt_providers,omitempty"`
	MaxScanSize     int            `json:"max_scan_size,omitempty"`
}

// AITrafficScanner scans AI request/response bodies for PII.
type AITrafficScanner struct {
	config AITrafficScannerConfig
}

// AITrafficScanResult holds the result of scanning AI traffic.
type AITrafficScanResult struct {
	HasPII          bool      `json:"has_pii"`
	Findings        []Finding `json:"findings,omitempty"`
	Action          string    `json:"action"`
	RedactedContent string    `json:"redacted_content,omitempty"`
}

// AITrafficScanStats holds scanning statistics.
type AITrafficScanStats struct {
	RequestsScanned  int64 `json:"requests_scanned"`
	ResponsesScanned int64 `json:"responses_scanned"`
	FindingsCount    int64 `json:"findings_count"`
	BlockedCount     int64 `json:"blocked_count"`
	RedactedCount    int64 `json:"redacted_count"`
}

// NewAITrafficScanner creates a new AI traffic scanner (no-op in open-source build).
func NewAITrafficScanner(config AITrafficScannerConfig) *AITrafficScanner {
	return &AITrafficScanner{config: config}
}

// ScanRequest returns a pass result (no-op in open-source build).
func (s *AITrafficScanner) ScanRequest(_ []byte, _, _ string) (*AITrafficScanResult, error) {
	return &AITrafficScanResult{Action: "pass"}, nil
}

// ScanResponse returns a pass result (no-op in open-source build).
func (s *AITrafficScanner) ScanResponse(_ []byte, _, _ string) (*AITrafficScanResult, error) {
	return &AITrafficScanResult{Action: "pass"}, nil
}

// Stats returns zero statistics (no-op in open-source build).
func (s *AITrafficScanner) Stats() AITrafficScanStats {
	return AITrafficScanStats{}
}

// JSONScanner walks JSON structures and scans string values for PII.
type JSONScanner struct{}

// NewJSONScanner creates a JSONScanner (no-op in open-source build).
func NewJSONScanner(_ *Scanner) *JSONScanner { return &JSONScanner{} }

// ScanJSON returns an empty result (no-op in open-source build).
func (js *JSONScanner) ScanJSON(body []byte, _ string) *ScanResult {
	return &ScanResult{ScannedSize: int64(len(body))}
}

// RedactJSON returns the body unchanged (no-op in open-source build).
func (js *JSONScanner) RedactJSON(body []byte, _ []Finding) ([]byte, error) {
	return body, nil
}

// LuaDetector runs a user-defined Lua script for custom PII detection.
type LuaDetector struct {
	name string
}

// NewLuaDetector creates a custom PII detector stub (no-op in open-source build).
func NewLuaDetector(name, _ string, _ interface{}) (*LuaDetector, error) {
	return &LuaDetector{name: name}, nil
}

func (d *LuaDetector) Type() DetectorType                        { return DetectorCustom }
func (d *LuaDetector) Detect(_ []byte, _ string) []Finding       { return nil }
func (d *LuaDetector) DetectTo(_ []byte, _ string, _ *[]Finding) {}
func (d *LuaDetector) Redact(_ string) string                    { return "[REDACTED-" + d.name + "]" }
func (d *LuaDetector) MatchesFlags(_ CandidateFlags) bool        { return false }
