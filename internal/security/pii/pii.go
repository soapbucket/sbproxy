// Package pii provides top-level PII detection and redaction functions.
package pii

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// Redaction modes.
const (
	ModeMask   = "mask"   // Replace matched text with [REDACTED]
	ModeHash   = "hash"   // Replace with sha256: prefix + first 8 hex chars
	ModeRemove = "remove" // Delete matched text entirely
)

// Redact scans the input string for PII using the specified detectors and replaces
// matches according to the given mode. If detectors is nil or empty, DefaultDetectors
// is used.
func Redact(input string, detectors []string, mode string) string {
	if input == "" {
		return input
	}

	dets := resolveDetectors(detectors)
	if len(dets) == 0 {
		return input
	}

	scanner := NewScanner(dets, nil, int64(len(input)))
	result := scanner.Scan([]byte(input), "")
	if len(result.Findings) == 0 {
		return input
	}

	return applyRedactions(input, result.Findings, mode)
}

// RedactBytes is the []byte variant of Redact.
func RedactBytes(input []byte, detectors []string, mode string) []byte {
	if len(input) == 0 {
		return input
	}

	dets := resolveDetectors(detectors)
	if len(dets) == 0 {
		return input
	}

	scanner := NewScanner(dets, nil, int64(len(input)))
	result := scanner.Scan(input, "")
	if len(result.Findings) == 0 {
		return input
	}

	return []byte(applyRedactions(string(input), result.Findings, mode))
}

// resolveDetectors converts string detector names to Detector instances.
// If names is empty, DefaultDetectors plus the extended set is returned.
func resolveDetectors(names []string) []Detector {
	if len(names) == 0 {
		return AllDetectors()
	}

	var out []Detector
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		d := DetectorForName(name)
		if d != nil {
			out = append(out, d)
		}
	}
	return out
}

// DetectorForName returns a Detector for the given string name.
// Returns nil if the name is not recognized.
func DetectorForName(name string) Detector {
	return detectorForType(DetectorType(name))
}

// AllDetectors returns the full set of built-in PII detectors including
// the extended set (AWS key, private key, DB connection string).
func AllDetectors() []Detector {
	return []Detector{
		NewSSNDetector(),
		NewCreditCardDetector(),
		NewEmailDetector(),
		NewPhoneDetector(),
		NewAPIKeyDetector(),
		NewJWTDetector(),
		NewAWSKeyDetector(),
		NewPrivateKeyDetector(),
		NewDBConnectionStringDetector(),
	}
}

// applyRedactions replaces findings in content according to the mode.
// Processes from end to start so byte offsets remain valid.
func applyRedactions(content string, findings []Finding, mode string) string {
	if len(findings) == 0 {
		return content
	}

	// Process replacements using string.Replace from end to start
	result := content
	for i := len(findings) - 1; i >= 0; i-- {
		f := findings[i]
		replacement := redactValue(f.Value, mode, &f)
		result = strings.Replace(result, f.Value, replacement, 1)
	}
	return result
}

// redactValue produces the replacement string for a matched PII value.
func redactValue(value, mode string, f *Finding) string {
	switch mode {
	case ModeHash:
		h := sha256.Sum256([]byte(value))
		return fmt.Sprintf("sha256:%x", h[:4])
	case ModeRemove:
		return ""
	default: // ModeMask or unrecognized
		if f != nil && f.redactFn != nil {
			return f.redactFn(value)
		}
		return "[REDACTED]"
	}
}
