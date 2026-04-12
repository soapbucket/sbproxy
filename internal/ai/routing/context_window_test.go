package routing

import (
	"strconv"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func makeRegistry(model string, contextWindow int) *ai.ProviderRegistry {
	return &ai.ProviderRegistry{
		Providers: map[string]ai.ProviderDef{
			"test-provider": {
				Models: map[string]ai.ModelDef{
					model: {ContextWindow: contextWindow},
				},
			},
		},
	}
}

func intPtr(n int) *int { return &n }

func textContent(s string) json.RawMessage {
	return json.RawMessage(strconv.Quote(s))
}

func TestContextWindowValidator_WithinWindow(t *testing.T) {
	reg := makeRegistry("gpt-4", 128000)
	v := NewContextWindowValidator(reg, 0.05)

	req := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: textContent("Hello, how are you?")},
		},
		MaxTokens: intPtr(100),
	}

	err := v.Validate(req, "gpt-4")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestContextWindowValidator_ExceedsWindow(t *testing.T) {
	// Tiny context window of 100 tokens
	reg := makeRegistry("tiny-model", 100)
	v := NewContextWindowValidator(reg, 0.05)

	// Create a large message that will exceed the window
	bigContent := make([]byte, 2000) // ~500 tokens at 4 chars/token
	for i := range bigContent {
		bigContent[i] = 'a'
	}

	req := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: textContent(string(bigContent))},
		},
		MaxTokens: intPtr(50),
	}

	err := v.Validate(req, "tiny-model")
	if err == nil {
		t.Fatal("expected ContextWindowError, got nil")
	}

	cwErr, ok := err.(*ai.ContextWindowError)
	if !ok {
		t.Fatalf("expected *ai.ContextWindowError, got %T", err)
	}
	if cwErr.Model != "tiny-model" {
		t.Errorf("expected model 'tiny-model', got %q", cwErr.Model)
	}
	if cwErr.ContextWindow != 100 {
		t.Errorf("expected context window 100, got %d", cwErr.ContextWindow)
	}
	if cwErr.RequestedOutput != 50 {
		t.Errorf("expected requested output 50, got %d", cwErr.RequestedOutput)
	}
	if cwErr.EstimatedInput < 400 {
		t.Errorf("expected estimated input >= 400 for 2000 chars, got %d", cwErr.EstimatedInput)
	}
}

func TestContextWindowValidator_UnknownModel(t *testing.T) {
	reg := makeRegistry("gpt-4", 128000)
	v := NewContextWindowValidator(reg, 0.05)

	req := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: textContent("Hello")},
		},
	}

	err := v.Validate(req, "unknown-model-xyz")
	if err != nil {
		t.Fatalf("expected nil for unknown model, got: %v", err)
	}
}

func TestContextWindowValidator_ZeroContextWindow(t *testing.T) {
	reg := makeRegistry("no-window-model", 0)
	v := NewContextWindowValidator(reg, 0.05)

	req := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: textContent("Hello")},
		},
	}

	err := v.Validate(req, "no-window-model")
	if err != nil {
		t.Fatalf("expected nil for zero context window, got: %v", err)
	}
}

func TestContextWindowValidator_SafetyMarginApplied(t *testing.T) {
	// Context window of 1000 tokens with 5% margin = effective 950
	reg := makeRegistry("test-model", 1000)
	v := NewContextWindowValidator(reg, 0.05)

	// Request that fits in 1000 but not in 950
	// ~3800 chars = ~950 tokens for content + 1 role + 4 framing = ~955 input
	// Plus 50 output = 1005 > 950 effective, so should fail
	content := make([]byte, 3780)
	for i := range content {
		content[i] = 'x'
	}

	req := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: textContent(string(content))},
		},
		MaxTokens: intPtr(50),
	}

	err := v.Validate(req, "test-model")
	if err == nil {
		t.Fatal("expected error due to safety margin, got nil")
	}

	// Now with 0% margin, same request should pass (955 + 50 = 1005 > 1000 still fails)
	// Use smaller content that fits in 1000 but not 950
	content2 := make([]byte, 3560) // ~890 tokens + 5 overhead = ~895 input + 50 output = 945 < 1000
	for i := range content2 {
		content2[i] = 'x'
	}

	req2 := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: textContent(string(content2))},
		},
		MaxTokens: intPtr(50),
	}

	vNoMargin := NewContextWindowValidator(reg, 0.0)
	err = vNoMargin.Validate(req2, "test-model")
	if err != nil {
		t.Fatalf("expected no error with 0%% margin, got: %v", err)
	}

	// Same request with 5% margin (effective 950): 895 + 50 = 945 < 950, should pass
	err = v.Validate(req2, "test-model")
	if err != nil {
		t.Fatalf("expected no error with 5%% margin (945 < 950), got: %v", err)
	}

	// Edge case: content that fits in 1000 but not in 950
	content3 := make([]byte, 3580) // ~895 tokens + 5 overhead = ~900 input + 50 = 950
	for i := range content3 {
		content3[i] = 'x'
	}

	req3 := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: textContent(string(content3))},
		},
		MaxTokens: intPtr(50),
	}

	// With 0% margin: 900 + 50 = 950 <= 1000, should pass
	err = vNoMargin.Validate(req3, "test-model")
	if err != nil {
		t.Fatalf("expected pass with 0%% margin, got: %v", err)
	}
}

func TestContextWindowValidator_VisionContent(t *testing.T) {
	reg := makeRegistry("gpt-4-vision", 128000)
	v := NewContextWindowValidator(reg, 0.05)

	// Build content parts with an image
	parts := []ai.ContentPart{
		{Type: "text", Text: "Describe this image"},
		{Type: "image_url", ImageURL: &ai.ImageURL{URL: "https://example.com/img.png"}},
	}
	partsJSON, _ := json.Marshal(parts)

	req := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: partsJSON},
		},
		MaxTokens: intPtr(100),
	}

	// Should pass (small request)
	err := v.Validate(req, "gpt-4-vision")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify image tokens are counted by checking estimate
	estimated := v.estimateInputTokens(req)
	// "Describe this image" = 19 chars / 4 = 4 tokens + 85 image tokens + 1 role + 4 framing = ~94
	if estimated < 85 {
		t.Errorf("expected at least 85 tokens (image cost), got %d", estimated)
	}
}

func TestContextWindowValidator_ToolDefinitions(t *testing.T) {
	reg := makeRegistry("gpt-4", 128000)
	v := NewContextWindowValidator(reg, 0.05)

	paramSchema := json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`)

	req := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: textContent("Search for something")},
		},
		Tools: []ai.Tool{
			{
				Type: "function",
				Function: ai.ToolFunction{
					Name:        "search",
					Description: "Search the web for information about a topic",
					Parameters:  paramSchema,
				},
			},
			{
				Type: "function",
				Function: ai.ToolFunction{
					Name:        "calculate",
					Description: "Perform mathematical calculations",
					Parameters:  paramSchema,
				},
			},
		},
		MaxTokens: intPtr(100),
	}

	// Should pass (well within window)
	err := v.Validate(req, "gpt-4")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify tools add tokens
	withTools := v.estimateInputTokens(req)

	reqNoTools := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: textContent("Search for something")},
		},
	}
	withoutTools := v.estimateInputTokens(reqNoTools)

	if withTools <= withoutTools {
		t.Errorf("expected more tokens with tools (%d) than without (%d)", withTools, withoutTools)
	}
}

func TestContextWindowValidator_EmptyRequest(t *testing.T) {
	reg := makeRegistry("gpt-4", 128000)
	v := NewContextWindowValidator(reg, 0.05)

	req := &ai.ChatCompletionRequest{}

	err := v.Validate(req, "gpt-4")
	if err != nil {
		t.Fatalf("expected no error for empty request, got: %v", err)
	}

	estimated := v.estimateInputTokens(req)
	// Should be just the framing tokens (4)
	if estimated != 4 {
		t.Errorf("expected 4 framing tokens for empty request, got %d", estimated)
	}
}

func TestContextWindowValidator_NilRegistry(t *testing.T) {
	v := NewContextWindowValidator(nil, 0.05)

	req := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: textContent("Hello")},
		},
	}

	err := v.Validate(req, "gpt-4")
	if err != nil {
		t.Fatalf("expected nil for nil registry, got: %v", err)
	}
}

func TestContextWindowValidator_DefaultMaxTokens(t *testing.T) {
	// When MaxTokens is not set, default 4096 output reservation is used
	reg := makeRegistry("small-model", 5000)
	v := NewContextWindowValidator(reg, 0.0)

	req := &ai.ChatCompletionRequest{
		Messages: []ai.Message{
			{Role: "user", Content: textContent("Hi")},
		},
		// MaxTokens not set - defaults to 4096
	}

	// Estimated input: 1 (role) + 0 (2 chars / 4 = 0) + 4 (framing) = 5
	// Total: 5 + 4096 = 4101 < 5000, should pass
	err := v.Validate(req, "small-model")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// With a model that is too small for default output reservation
	reg2 := makeRegistry("tiny-model", 4000)
	v2 := NewContextWindowValidator(reg2, 0.0)

	err = v2.Validate(req, "tiny-model")
	if err == nil {
		t.Fatal("expected error when default 4096 output exceeds context window")
	}
}

func TestContextWindowValidator_SafetyMarginClamping(t *testing.T) {
	reg := makeRegistry("gpt-4", 128000)

	// Negative margin should default to 0.05
	v1 := NewContextWindowValidator(reg, -0.1)
	if v1.safetyMargin != 0.05 {
		t.Errorf("expected 0.05 for negative margin, got %f", v1.safetyMargin)
	}

	// Over 0.5 should default to 0.05
	v2 := NewContextWindowValidator(reg, 0.8)
	if v2.safetyMargin != 0.05 {
		t.Errorf("expected 0.05 for >0.5 margin, got %f", v2.safetyMargin)
	}

	// Valid margins should be kept
	v3 := NewContextWindowValidator(reg, 0.10)
	if v3.safetyMargin != 0.10 {
		t.Errorf("expected 0.10, got %f", v3.safetyMargin)
	}
}

func BenchmarkContextWindowValidation(b *testing.B) {
	reg := makeRegistry("gpt-4", 128000)
	v := NewContextWindowValidator(reg, 0.05)

	// Build a typical request with 8 messages totaling ~500 tokens
	messages := []ai.Message{
		{Role: "system", Content: textContent("You are a helpful assistant that answers questions about programming and software development.")},
		{Role: "user", Content: textContent("Can you explain how goroutines work in Go?")},
		{Role: "assistant", Content: textContent("Goroutines are lightweight threads managed by the Go runtime. They allow concurrent execution of functions. You create one with the go keyword followed by a function call.")},
		{Role: "user", Content: textContent("How do channels work with goroutines?")},
		{Role: "assistant", Content: textContent("Channels are typed conduits for sending and receiving values between goroutines. They provide synchronization and communication. You create them with make(chan Type).")},
		{Role: "user", Content: textContent("What about select statements?")},
		{Role: "assistant", Content: textContent("The select statement lets a goroutine wait on multiple channel operations. It blocks until one of its cases can proceed, then executes that case. If multiple are ready, it picks one at random.")},
		{Role: "user", Content: textContent("Can you show me a simple producer-consumer pattern using channels and goroutines?")},
	}

	req := &ai.ChatCompletionRequest{
		Messages:  messages,
		MaxTokens: intPtr(1024),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = v.Validate(req, "gpt-4")
	}
}

func TestContextWindowError_ErrorMessage(t *testing.T) {
	err := &ai.ContextWindowError{
		Model:           "gpt-4",
		ContextWindow:   128000,
		EstimatedInput:  120000,
		RequestedOutput: 10000,
	}

	expected := "input too large for model gpt-4: estimated 120000 input tokens + 10000 max output tokens = 130000, context window is 128000"
	if err.Error() != expected {
		t.Errorf("unexpected error message:\ngot:  %s\nwant: %s", err.Error(), expected)
	}
}
