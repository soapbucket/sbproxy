package pii

import (
	"encoding/json"
	"testing"
)

func TestAITrafficScanner_ScanRequest_DetectsPII(t *testing.T) {
	t.Parallel()

	scanner := NewAITrafficScanner(AITrafficScannerConfig{
		Enabled:      true,
		ScanRequests: true,
		Mode:         "warn",
		Detectors:    []DetectorType{DetectorEmail, DetectorPhone},
	})

	body, _ := json.Marshal(map[string]interface{}{
		"messages": []map[string]string{
			{"role": "user", "content": "Contact me at alice@example.com or 555-123-4567"},
		},
	})

	result, err := scanner.ScanRequest(body, "gpt-4", "openai")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasPII {
		t.Fatal("expected PII to be detected")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	foundEmail := false
	foundPhone := false
	for _, f := range result.Findings {
		if f.Type == DetectorEmail {
			foundEmail = true
		}
		if f.Type == DetectorPhone {
			foundPhone = true
		}
	}
	if !foundEmail {
		t.Error("expected email to be detected")
	}
	if !foundPhone {
		t.Error("expected phone to be detected")
	}

	// In warn mode, action should be "pass".
	if result.Action != "pass" {
		t.Errorf("expected action pass, got %s", result.Action)
	}
}

func TestAITrafficScanner_ScanResponse_Clean(t *testing.T) {
	t.Parallel()

	scanner := NewAITrafficScanner(AITrafficScannerConfig{
		Enabled:       true,
		ScanResponses: true,
		Mode:          "block",
	})

	body, _ := json.Marshal(map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message": map[string]string{
					"role":    "assistant",
					"content": "The weather today is sunny with a high of 72 degrees.",
				},
			},
		},
	})

	result, err := scanner.ScanResponse(body, "gpt-4", "openai")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasPII {
		t.Error("expected no PII in clean response")
	}
	if result.Action != "pass" {
		t.Errorf("expected action pass, got %s", result.Action)
	}
}

func TestAITrafficScanner_ExemptModel(t *testing.T) {
	t.Parallel()

	scanner := NewAITrafficScanner(AITrafficScannerConfig{
		Enabled:      true,
		ScanRequests: true,
		Mode:         "block",
		ExemptModels: []string{"internal-model"},
	})

	body, _ := json.Marshal(map[string]interface{}{
		"prompt": "My SSN is 123-45-6789",
	})

	result, err := scanner.ScanRequest(body, "internal-model", "openai")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasPII {
		t.Error("expected exempt model to skip scanning")
	}
	if result.Action != "pass" {
		t.Errorf("expected action pass for exempt model, got %s", result.Action)
	}
}

func TestAITrafficScanner_ModeBlock(t *testing.T) {
	t.Parallel()

	scanner := NewAITrafficScanner(AITrafficScannerConfig{
		Enabled:      true,
		ScanRequests: true,
		Mode:         "block",
		Detectors:    []DetectorType{DetectorEmail},
	})

	body, _ := json.Marshal(map[string]interface{}{
		"prompt": "Send it to alice@example.com please",
	})

	result, err := scanner.ScanRequest(body, "gpt-4", "openai")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasPII {
		t.Fatal("expected PII to be detected")
	}
	if result.Action != "block" {
		t.Errorf("expected action block, got %s", result.Action)
	}

	stats := scanner.Stats()
	if stats.BlockedCount != 1 {
		t.Errorf("expected 1 blocked, got %d", stats.BlockedCount)
	}
}

func TestAITrafficScanner_ModeRedact(t *testing.T) {
	t.Parallel()

	scanner := NewAITrafficScanner(AITrafficScannerConfig{
		Enabled:      true,
		ScanRequests: true,
		Mode:         "redact",
		Detectors:    []DetectorType{DetectorEmail},
	})

	body, _ := json.Marshal(map[string]interface{}{
		"prompt": "Contact alice@example.com for help",
	})

	result, err := scanner.ScanRequest(body, "gpt-4", "openai")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasPII {
		t.Fatal("expected PII to be detected")
	}
	if result.Action != "redact" {
		t.Errorf("expected action redact, got %s", result.Action)
	}
	if result.RedactedContent == "" {
		t.Error("expected redacted content to be set")
	}

	// The redacted content should not contain the original email.
	if containsString(result.RedactedContent, "alice@example.com") {
		t.Error("expected email to be redacted in content")
	}

	stats := scanner.Stats()
	if stats.RedactedCount != 1 {
		t.Errorf("expected 1 redacted, got %d", stats.RedactedCount)
	}
}

func TestAITrafficScanner_Disabled(t *testing.T) {
	t.Parallel()

	scanner := NewAITrafficScanner(AITrafficScannerConfig{
		Enabled:      false,
		ScanRequests: true,
		Mode:         "block",
	})

	body, _ := json.Marshal(map[string]interface{}{
		"prompt": "My SSN is 123-45-6789",
	})

	result, err := scanner.ScanRequest(body, "gpt-4", "openai")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Action != "pass" {
		t.Errorf("expected pass when disabled, got %s", result.Action)
	}
}

func TestAITrafficScanner_ExemptProvider(t *testing.T) {
	t.Parallel()

	scanner := NewAITrafficScanner(AITrafficScannerConfig{
		Enabled:         true,
		ScanRequests:    true,
		Mode:            "block",
		ExemptProviders: []string{"internal-provider"},
	})

	body, _ := json.Marshal(map[string]interface{}{
		"prompt": "My email is test@example.com",
	})

	result, err := scanner.ScanRequest(body, "gpt-4", "internal-provider")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Action != "pass" {
		t.Errorf("expected pass for exempt provider, got %s", result.Action)
	}
}

func TestExtractTextContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     map[string]interface{}
		wantText string
	}{
		{
			name:     "prompt field",
			body:     map[string]interface{}{"prompt": "hello world"},
			wantText: "hello world",
		},
		{
			name: "messages array",
			body: map[string]interface{}{
				"messages": []map[string]string{
					{"role": "user", "content": "tell me a joke"},
				},
			},
			wantText: "tell me a joke",
		},
		{
			name: "choices array",
			body: map[string]interface{}{
				"choices": []map[string]interface{}{
					{"message": map[string]string{"content": "response text"}},
				},
			},
			wantText: "response text",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.body)
			got := extractTextContent(b)
			if string(got) != tc.wantText {
				t.Errorf("expected %q, got %q", tc.wantText, string(got))
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && searchString(s, substr))
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
