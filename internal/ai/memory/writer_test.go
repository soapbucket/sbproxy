package memory

import (
	json "github.com/goccy/go-json"
	"testing"
)

func TestEntryMarshal(t *testing.T) {
	entry := &Entry{
		RequestID:      "req-123",
		Timestamp:      "2026-02-19T12:00:00.000Z",
		WorkspaceID:    "ws-abc",
		OriginID:       "origin-1",
		SessionID:      "sess-xyz",
		Provider:       "anthropic",
		Model:          "claude-sonnet-4-6",
		IsStreaming:    false,
		StopReason:     "stop",
		InputTokens:    100,
		OutputTokens:   50,
		TotalTokens:    150,
		CostUSD:        0.003,
		LatencyMS:      1200,
		SystemPrompt:   "You are a helpful assistant.",
		InputMessages:  `[{"role":"user","content":"Hello"}]`,
		OutputContent:  "Hi there! How can I help?",
		ToolsAvailable: []string{"search", "calculator"},
		ToolsCalled:    nil,
		HasToolUse:     false,
		CaptureScope:   "full",
		PromptHash:     "abc123",
		ResponseHash:   "def456",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Verify key fields are present
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	checks := map[string]interface{}{
		"request_id":    "req-123",
		"workspace_id":  "ws-abc",
		"provider":      "anthropic",
		"model":         "claude-sonnet-4-6",
		"capture_scope": "full",
	}
	for k, want := range checks {
		got, ok := m[k]
		if !ok {
			t.Errorf("missing key %q in marshaled JSON", k)
			continue
		}
		if got != want {
			t.Errorf("key %q = %v, want %v", k, got, want)
		}
	}

	// Verify tools_available is present as an array
	if _, ok := m["tools_available"]; !ok {
		t.Error("missing tools_available in marshaled JSON")
	}
}

func TestEntryMarshalOmitsEmptyFields(t *testing.T) {
	entry := &Entry{
		RequestID:   "req-456",
		Timestamp:   "2026-02-19T12:00:00.000Z",
		WorkspaceID: "ws-abc",
		SessionID:   "sess-xyz",
		Provider:    "openai",
		Model:       "gpt-4",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// These fields should be omitted when empty/zero
	shouldOmit := []string{"system_prompt", "error", "tools_available", "tools_called", "agent"}
	for _, k := range shouldOmit {
		if _, ok := m[k]; ok {
			t.Errorf("expected key %q to be omitted, but it was present", k)
		}
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := &MemoryConfig{Enabled: true}
	d := cfg.Defaults()

	if d.CaptureScope != ScopeFull {
		t.Errorf("CaptureScope = %q, want %q", d.CaptureScope, ScopeFull)
	}
	if d.SampleRate != 1.0 {
		t.Errorf("SampleRate = %f, want 1.0", d.SampleRate)
	}
	if !d.ShouldCaptureStreaming() {
		t.Error("ShouldCaptureStreaming() = false, want true")
	}
	if d.RetentionDays != 365 {
		t.Errorf("RetentionDays = %d, want 365", d.RetentionDays)
	}
	if d.MaxEntriesPerSession != 1000 {
		t.Errorf("MaxEntriesPerSession = %d, want 1000", d.MaxEntriesPerSession)
	}
}

func TestConfigShouldCaptureStreaming(t *testing.T) {
	f := false
	cfg := &MemoryConfig{CaptureStreaming: &f}
	if cfg.ShouldCaptureStreaming() {
		t.Error("ShouldCaptureStreaming() = true, want false when explicitly disabled")
	}

	tr := true
	cfg = &MemoryConfig{CaptureStreaming: &tr}
	if !cfg.ShouldCaptureStreaming() {
		t.Error("ShouldCaptureStreaming() = false, want true when explicitly enabled")
	}
}
