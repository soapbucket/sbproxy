// Package pii detects and redacts personally identifiable information from request/response data.
package pii

import (
	"encoding/json"
	"log/slog"
	"strings"
	"sync/atomic"
)

// AITrafficScannerConfig configures PII scanning for AI traffic.
type AITrafficScannerConfig struct {
	Enabled         bool           `json:"enabled,omitempty"`
	ScanRequests    bool           `json:"scan_requests,omitempty"`    // Scan user prompts
	ScanResponses   bool           `json:"scan_responses,omitempty"`   // Scan AI responses
	Mode            string         `json:"mode,omitempty"`             // "block", "redact", "warn" (default: "warn")
	Detectors       []DetectorType `json:"detectors,omitempty"`        // Which PII types to scan for
	ExemptModels    []string       `json:"exempt_models,omitempty"`    // Models exempt from scanning
	ExemptProviders []string       `json:"exempt_providers,omitempty"` // Providers exempt from scanning
	MaxScanSize     int            `json:"max_scan_size,omitempty"`    // Max bytes to scan (default: 100KB)
}

// AITrafficScanner scans AI request/response bodies for PII.
type AITrafficScanner struct {
	config  AITrafficScannerConfig
	scanner *Scanner

	// Metrics
	requestsScanned  atomic.Int64
	responsesScanned atomic.Int64
	findingsCount    atomic.Int64
	blockedCount     atomic.Int64
	redactedCount    atomic.Int64
}

// AITrafficScanResult holds the result of scanning AI traffic.
type AITrafficScanResult struct {
	HasPII          bool      `json:"has_pii"`
	Findings        []Finding `json:"findings,omitempty"`
	Action          string    `json:"action"` // "pass", "block", "redact"
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

// NewAITrafficScanner creates a new AI traffic scanner. If no detectors are
// specified in the config, the default set (email, phone, SSN, credit card,
// API key) is used.
func NewAITrafficScanner(config AITrafficScannerConfig) *AITrafficScanner {
	if config.Mode == "" {
		config.Mode = "warn"
	}
	if config.MaxScanSize <= 0 {
		config.MaxScanSize = 100 * 1024 // 100KB
	}

	detectorTypes := config.Detectors
	if len(detectorTypes) == 0 {
		detectorTypes = []DetectorType{
			DetectorEmail,
			DetectorPhone,
			DetectorSSN,
			DetectorCreditCard,
			DetectorAPIKey,
		}
	}

	detectors := buildDetectors(detectorTypes)
	scanner := NewScanner(detectors, nil, int64(config.MaxScanSize))

	return &AITrafficScanner{
		config:  config,
		scanner: scanner,
	}
}

// buildDetectors creates Detector instances for the requested types using
// the existing factory functions in the pii package.
func buildDetectors(types []DetectorType) []Detector {
	var out []Detector
	seen := make(map[DetectorType]bool)
	for _, dt := range types {
		if seen[dt] {
			continue
		}
		seen[dt] = true
		d := detectorForType(dt)
		if d != nil {
			out = append(out, d)
		}
	}
	return out
}

// detectorForType returns the appropriate Detector for the given type.
func detectorForType(dt DetectorType) Detector {
	switch dt {
	case DetectorSSN:
		return NewSSNDetector()
	case DetectorCreditCard:
		return NewCreditCardDetector()
	case DetectorEmail:
		return NewEmailDetector()
	case DetectorPhone:
		return NewPhoneDetector()
	case DetectorIPAddress:
		return NewIPAddressDetector()
	case DetectorAPIKey:
		return NewAPIKeyDetector()
	case DetectorJWT:
		return NewJWTDetector()
	case DetectorAWSKey:
		return NewAWSKeyDetector()
	case DetectorPrivateKey:
		return NewPrivateKeyDetector()
	case DetectorDBConnectionString:
		return NewDBConnectionStringDetector()
	default:
		return nil
	}
}

// ScanRequest scans an AI request body for PII.
func (s *AITrafficScanner) ScanRequest(body []byte, model, provider string) (*AITrafficScanResult, error) {
	s.requestsScanned.Add(1)

	if !s.config.Enabled || !s.config.ScanRequests {
		return &AITrafficScanResult{Action: "pass"}, nil
	}

	if s.isExempt(model, provider) {
		return &AITrafficScanResult{Action: "pass"}, nil
	}

	content := extractTextContent(body)
	if len(content) == 0 {
		return &AITrafficScanResult{Action: "pass"}, nil
	}

	return s.scan(content)
}

// ScanResponse scans an AI response body for PII.
func (s *AITrafficScanner) ScanResponse(body []byte, model, provider string) (*AITrafficScanResult, error) {
	s.responsesScanned.Add(1)

	if !s.config.Enabled || !s.config.ScanResponses {
		return &AITrafficScanResult{Action: "pass"}, nil
	}

	if s.isExempt(model, provider) {
		return &AITrafficScanResult{Action: "pass"}, nil
	}

	content := extractTextContent(body)
	if len(content) == 0 {
		return &AITrafficScanResult{Action: "pass"}, nil
	}

	return s.scan(content)
}

// scan runs the underlying PII scanner and applies the configured action mode.
func (s *AITrafficScanner) scan(content []byte) (*AITrafficScanResult, error) {
	result := s.scanner.Scan(content, "")

	if len(result.Findings) == 0 {
		return &AITrafficScanResult{Action: "pass"}, nil
	}

	s.findingsCount.Add(int64(len(result.Findings)))

	scanResult := &AITrafficScanResult{
		HasPII:   true,
		Findings: result.Findings,
	}

	switch s.config.Mode {
	case "block":
		s.blockedCount.Add(1)
		scanResult.Action = "block"
		slog.Warn("ai traffic pii blocked",
			"findings", len(result.Findings))

	case "redact":
		s.redactedCount.Add(1)
		scanResult.Action = "redact"
		scanResult.RedactedContent = redactContent(string(content), result.Findings)
		slog.Info("ai traffic pii redacted",
			"findings", len(result.Findings))

	default: // "warn"
		scanResult.Action = "pass"
		slog.Warn("ai traffic pii detected",
			"findings", len(result.Findings),
			"mode", "warn")
	}

	return scanResult, nil
}

// isExempt returns true if the given model or provider is exempt from scanning.
func (s *AITrafficScanner) isExempt(model, provider string) bool {
	for _, m := range s.config.ExemptModels {
		if strings.EqualFold(m, model) {
			return true
		}
	}
	for _, p := range s.config.ExemptProviders {
		if strings.EqualFold(p, provider) {
			return true
		}
	}
	return false
}

// Stats returns scanning statistics.
func (s *AITrafficScanner) Stats() AITrafficScanStats {
	return AITrafficScanStats{
		RequestsScanned:  s.requestsScanned.Load(),
		ResponsesScanned: s.responsesScanned.Load(),
		FindingsCount:    s.findingsCount.Load(),
		BlockedCount:     s.blockedCount.Load(),
		RedactedCount:    s.redactedCount.Load(),
	}
}

// extractTextContent extracts user-visible text from a JSON AI request or
// response body. It looks for common fields: "content", "prompt",
// "messages[].content", and "choices[].message.content".
func extractTextContent(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		// Not JSON; scan raw body.
		return body
	}

	var parts []string

	// Direct "prompt" field.
	if p, ok := raw["prompt"]; ok {
		var s string
		if json.Unmarshal(p, &s) == nil && s != "" {
			parts = append(parts, s)
		}
	}

	// Direct "content" field.
	if c, ok := raw["content"]; ok {
		var s string
		if json.Unmarshal(c, &s) == nil && s != "" {
			parts = append(parts, s)
		}
	}

	// "messages" array.
	if m, ok := raw["messages"]; ok {
		var msgs []struct {
			Content string `json:"content"`
		}
		if json.Unmarshal(m, &msgs) == nil {
			for _, msg := range msgs {
				if msg.Content != "" {
					parts = append(parts, msg.Content)
				}
			}
		}
	}

	// "choices" array (response format).
	if ch, ok := raw["choices"]; ok {
		var choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(ch, &choices) == nil {
			for _, c := range choices {
				if c.Message.Content != "" {
					parts = append(parts, c.Message.Content)
				}
			}
		}
	}

	if len(parts) == 0 {
		return nil
	}

	return []byte(strings.Join(parts, "\n"))
}

// redactContent replaces PII findings in content with their redacted forms.
func redactContent(content string, findings []Finding) string {
	if len(findings) == 0 {
		return content
	}

	result := content
	// Process from end to start so offsets remain valid.
	// For simplicity and safety, use string replacement.
	for _, f := range findings {
		redacted := f.GetRedacted()
		if redacted == "" {
			redacted = "[REDACTED]"
		}
		result = strings.Replace(result, f.Value, redacted, 1)
	}
	return result
}
