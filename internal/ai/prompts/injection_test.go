package prompts

import (
	json "github.com/goccy/go-json"
	"testing"
)

func makeMsg(role, content string) json.RawMessage {
	m := message{
		Role:    role,
		Content: json.RawMessage(`"` + content + `"`),
	}
	raw, _ := json.Marshal(m)
	return raw
}

func parseMessages(raw []json.RawMessage) []message {
	var msgs []message
	for _, r := range raw {
		var m message
		json.Unmarshal(r, &m)
		msgs = append(msgs, m)
	}
	return msgs
}

func TestApplySystemPrompt_PrependToExisting(t *testing.T) {
	msgs := []json.RawMessage{
		makeMsg("system", "Original system"),
		makeMsg("user", "Hello"),
	}
	cfg := &SystemPromptConfig{
		Prepend: "PREFIX",
	}
	result := cfg.ApplySystemPrompt(msgs)
	parsed := parseMessages(result)

	if len(parsed) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(parsed))
	}
	content := contentString(parsed[0].Content)
	if content != "PREFIX\nOriginal system" {
		t.Errorf("content = %q, want %q", content, "PREFIX\nOriginal system")
	}
}

func TestApplySystemPrompt_AppendToExisting(t *testing.T) {
	msgs := []json.RawMessage{
		makeMsg("system", "Original"),
		makeMsg("user", "Hello"),
	}
	cfg := &SystemPromptConfig{
		Append: "SUFFIX",
	}
	result := cfg.ApplySystemPrompt(msgs)
	parsed := parseMessages(result)

	content := contentString(parsed[0].Content)
	if content != "Original\nSUFFIX" {
		t.Errorf("content = %q, want %q", content, "Original\nSUFFIX")
	}
}

func TestApplySystemPrompt_BothPrependAndAppend(t *testing.T) {
	msgs := []json.RawMessage{
		makeMsg("system", "Middle"),
		makeMsg("user", "Hello"),
	}
	cfg := &SystemPromptConfig{
		Prepend: "TOP",
		Append:  "BOTTOM",
	}
	result := cfg.ApplySystemPrompt(msgs)
	parsed := parseMessages(result)

	content := contentString(parsed[0].Content)
	expected := "TOP\nMiddle\nBOTTOM"
	if content != expected {
		t.Errorf("content = %q, want %q", content, expected)
	}
}

func TestApplySystemPrompt_NoSystemMessage(t *testing.T) {
	msgs := []json.RawMessage{
		makeMsg("user", "Hello"),
		makeMsg("assistant", "Hi"),
	}
	cfg := &SystemPromptConfig{
		Prepend: "You are helpful",
		Append:  "Be concise",
	}
	result := cfg.ApplySystemPrompt(msgs)
	parsed := parseMessages(result)

	if len(parsed) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(parsed))
	}
	if parsed[0].Role != "system" {
		t.Errorf("first message role = %q, want system", parsed[0].Role)
	}
	content := contentString(parsed[0].Content)
	expected := "You are helpful\nBe concise"
	if content != expected {
		t.Errorf("content = %q, want %q", content, expected)
	}
	// Original messages should be preserved.
	if parsed[1].Role != "user" {
		t.Errorf("second message role = %q, want user", parsed[1].Role)
	}
}

func TestApplySystemPrompt_WithVariables(t *testing.T) {
	msgs := []json.RawMessage{
		makeMsg("user", "Hello"),
	}
	cfg := &SystemPromptConfig{
		Prepend:   "You are {{role}}",
		Append:    "Respond in {{language}}",
		Variables: map[string]string{"role": "a teacher", "language": "French"},
	}
	result := cfg.ApplySystemPrompt(msgs)
	parsed := parseMessages(result)

	if len(parsed) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(parsed))
	}
	content := contentString(parsed[0].Content)
	expected := "You are a teacher\nRespond in French"
	if content != expected {
		t.Errorf("content = %q, want %q", content, expected)
	}
}

func TestApplySystemPrompt_NilConfig(t *testing.T) {
	msgs := []json.RawMessage{
		makeMsg("user", "Hello"),
	}
	var cfg *SystemPromptConfig
	result := cfg.ApplySystemPrompt(msgs)
	if len(result) != 1 {
		t.Errorf("expected 1 message, got %d", len(result))
	}
}

func TestApplySystemPrompt_EmptyPrependAndAppend(t *testing.T) {
	msgs := []json.RawMessage{
		makeMsg("user", "Hello"),
	}
	cfg := &SystemPromptConfig{}
	result := cfg.ApplySystemPrompt(msgs)
	if len(result) != 1 {
		t.Errorf("expected 1 message unchanged, got %d", len(result))
	}
}

func TestApplySystemPrompt_DoesNotMutateOriginal(t *testing.T) {
	original := []json.RawMessage{
		makeMsg("system", "Original"),
		makeMsg("user", "Hello"),
	}
	cfg := &SystemPromptConfig{Prepend: "New"}
	_ = cfg.ApplySystemPrompt(original)

	// Check original is not mutated.
	parsed := parseMessages(original)
	content := contentString(parsed[0].Content)
	if content != "Original" {
		t.Errorf("original was mutated: %q", content)
	}
}
