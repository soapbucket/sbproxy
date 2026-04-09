package pii

import (
	"testing"
	"time"
)

func TestLuaDetector(t *testing.T) {
	script := `
		function detect_pii(text, field_path)
			if string.find(text, "SECRET") then
				return {
					type = "custom_secret",
					value = "SECRET",
					redacted = "[CONFIDENTIAL]"
				}
			end
			return nil
		end
	`

	detector, err := NewLuaDetector("test", script, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to create lua detector: %v", err)
	}

	// Test Detect
	findings := detector.Detect([]byte("this is a SECRET message"), "body")
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	} else {
		if findings[0].Value != "SECRET" {
			t.Errorf("expected value SECRET, got %s", findings[0].Value)
		}
		if findings[0].Redacted != "[CONFIDENTIAL]" {
			t.Errorf("expected redacted [CONFIDENTIAL], got %s", findings[0].Redacted)
		}
	}

	// Test DetectTo
	var moreFindings []Finding
	detector.DetectTo([]byte("another SECRET here"), "body", &moreFindings)
	if len(moreFindings) != 1 {
		t.Errorf("expected 1 finding from DetectTo, got %d", len(moreFindings))
	}

	// Test MatchesFlags
	if !detector.MatchesFlags(0) {
		t.Errorf("expected MatchesFlags to return true")
	}

	// Test Redact
	redacted := detector.Redact("any")
	if redacted != "[REDACTED-test]" {
		t.Errorf("expected redacted [REDACTED-test], got %s", redacted)
	}
}

func TestLuaDetector_Multiple(t *testing.T) {
	script := `
		function detect_pii(text, field_path)
			local results = {}
			if string.find(text, "ONE") then
				table.insert(results, { type = "custom", value = "ONE" })
			end
			if string.find(text, "TWO") then
				table.insert(results, { type = "custom", value = "TWO" })
			end
			return results
		end
	`

	detector, err := NewLuaDetector("test", script, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to create lua detector: %v", err)
	}

	findings := detector.Detect([]byte("ONE and TWO"), "body")
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}
