// Package pii detects and redacts personally identifiable information from request/response data.
package pii

import (
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// JSONScanner walks JSON structures and scans string values for PII,
// tracking field paths for allowlist matching and redaction.
type JSONScanner struct {
	scanner *Scanner
}

// NewJSONScanner creates a JSONScanner wrapping the given Scanner.
func NewJSONScanner(scanner *Scanner) *JSONScanner {
	return &JSONScanner{scanner: scanner}
}

// ScanJSON scans a JSON body for PII, providing field-path context for each finding.
func (js *JSONScanner) ScanJSON(body []byte, requestPath string) *ScanResult {
	result := &ScanResult{
		ScannedSize: int64(len(body)),
	}

	if int64(len(body)) > js.scanner.maxSize {
		body = body[:js.scanner.maxSize]
		result.Truncated = true
		result.ScannedSize = js.scanner.maxSize
	}

	// Fast path: skip parsing if no candidate bytes exist in the whole body
	if !hasPIICandidateBytes(body) {
		return result
	}

	parsed := gjson.ParseBytes(body)
	if !parsed.IsObject() && !parsed.IsArray() {
		// Not structured JSON — fall back to raw scanning
		return js.scanner.Scan(body, requestPath)
	}

	var findings []Finding
	js.walkJSON(parsed, "", requestPath, &findings)
	result.Findings = findings
	return result
}

// walkJSON recursively traverses JSON and scans string values.
func (js *JSONScanner) walkJSON(value gjson.Result, prefix, requestPath string, findings *[]Finding) {
	switch {
	case value.IsObject():
		value.ForEach(func(key, val gjson.Result) bool {
			fieldPath := key.String()
			if prefix != "" {
				fieldPath = prefix + "." + fieldPath
			}
			js.walkJSON(val, fieldPath, requestPath, findings)
			return true
		})
	case value.IsArray():
		value.ForEach(func(_, val gjson.Result) bool {
			js.walkJSON(val, prefix, requestPath, findings)
			return true
		})
	default:
		// Scalar value — only scan strings
		if value.Type != gjson.String {
			return
		}
		
		// Fast pre-check: skip very short strings (minimum PII length is around 7-8)
		if len(value.Raw) < 5 {
			return
		}
		
		// Fast pre-check: skip strings with no candidate bytes
		// value.Raw includes quotes, so we can use it directly
		if !hasPIICandidateString(value.Raw) {
			return
		}

		// Optimization: gather hints once for this value
		hints := getScanHintsString(value.Raw)
		
		var raw string
		var data []byte
		var converted bool

		for _, d := range js.scanner.detectors {
			if js.scanner.allowlist != nil && js.scanner.allowlist.IsAllowed(prefix, d.Type(), requestPath) {
				continue
			}
			
			// Use hints to skip detectors
			if !d.MatchesFlags(hints) {
				continue
			}
			
			if !converted {
				raw = value.String()
				data = []byte(raw)
				converted = true
			}
			
			d.DetectTo(data, prefix, findings)
		}
	}
}

// RedactJSON replaces PII values in JSON body with their redacted forms.
// Returns the redacted body bytes.
func (js *JSONScanner) RedactJSON(body []byte, findings []Finding) ([]byte, error) {
	// Group findings by field path for efficient replacement
	pathRedactions := make(map[string][]Finding)
	for _, f := range findings {
		if f.FieldPath != "" {
			pathRedactions[f.FieldPath] = append(pathRedactions[f.FieldPath], f)
		}
	}

	result := body
	var err error

	for fieldPath, fieldFindings := range pathRedactions {
		current := gjson.GetBytes(result, fieldPath)
		if !current.Exists() || current.Type != gjson.String {
			continue
		}
		val := current.String()
		for _, f := range fieldFindings {
			val = replaceFirst(val, f.Value, f.GetRedacted())
		}
		result, err = sjson.SetBytes(result, fieldPath, val)
		if err != nil {
			return body, err
		}
	}

	return result, nil
}

// replaceFirst replaces the first occurrence of old with new in s.
func replaceFirst(s, old, replacement string) string {
	idx := indexOf(s, old)
	if idx < 0 {
		return s
	}
	return s[:idx] + replacement + s[idx+len(old):]
}

// indexOf returns the index of the first occurrence of substr in s, or -1.
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
