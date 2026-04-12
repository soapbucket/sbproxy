package ai

import (
	"strconv"
	"testing"

	json "github.com/goccy/go-json"
)

func TestComplexityScorer_SimpleRequest(t *testing.T) {
	scorer := NewComplexityScorer()

	req := &ChatCompletionRequest{
		Model: "gpt-4o",
		Messages: []Message{
			{Role: "user", Content: json.RawMessage(strconv.Quote("What is the capital of France?"))},
		},
	}

	level := scorer.Score(req)
	if level != ComplexityLow {
		t.Errorf("expected ComplexityLow, got %s", level)
	}
}

func TestComplexityScorer_CodeRequest(t *testing.T) {
	scorer := NewComplexityScorer()

	codeMsg := "Write a function:\n```go\nfunc add(a, b int) int {\n\treturn a + b\n}\n```"
	req := &ChatCompletionRequest{
		Model: "gpt-4o",
		Messages: []Message{
			{Role: "user", Content: json.RawMessage(strconv.Quote(codeMsg))},
		},
	}

	level := scorer.Score(req)
	if level != ComplexityCode {
		t.Errorf("expected ComplexityCode, got %s", level)
	}
}

func TestComplexityScorer_CodeKeywords(t *testing.T) {
	scorer := NewComplexityScorer()

	tests := []struct {
		name    string
		content string
		want    ComplexityLevel
	}{
		{"import statement", "import os\nimport sys\nprint('hello')", ComplexityCode},
		{"func keyword", "func main() {\n\tfmt.Println()\n}", ComplexityCode},
		{"class keyword", "class MyClass:\n    def __init__(self):\n        pass", ComplexityCode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ChatCompletionRequest{
				Messages: []Message{
					{Role: "user", Content: json.RawMessage(strconv.Quote(tt.content))},
				},
			}
			got := scorer.Score(req)
			if got != tt.want {
				t.Errorf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestComplexityScorer_ReasoningRequest(t *testing.T) {
	scorer := NewComplexityScorer()

	req := &ChatCompletionRequest{
		Model: "gpt-4o",
		Messages: []Message{
			{Role: "user", Content: json.RawMessage(strconv.Quote("Please analyze the pros and cons of microservices vs monoliths step by step"))},
		},
	}

	level := scorer.Score(req)
	if level != ComplexityHigh {
		t.Errorf("expected ComplexityHigh, got %s", level)
	}
}

func TestComplexityScorer_MediumLength(t *testing.T) {
	scorer := NewComplexityScorer()

	// Generate a medium-length message (~600 tokens / 2400 chars)
	longMsg := ""
	for i := 0; i < 100; i++ {
		longMsg += "This is a sentence about various topics. "
	}

	req := &ChatCompletionRequest{
		Model: "gpt-4o",
		Messages: []Message{
			{Role: "user", Content: json.RawMessage(strconv.Quote(longMsg))},
		},
	}

	level := scorer.Score(req)
	if level != ComplexityMedium {
		t.Errorf("expected ComplexityMedium, got %s", level)
	}
}

func TestComplexityScorer_NilRequest(t *testing.T) {
	scorer := NewComplexityScorer()

	if level := scorer.Score(nil); level != ComplexityLow {
		t.Errorf("expected ComplexityLow for nil request, got %s", level)
	}

	req := &ChatCompletionRequest{}
	if level := scorer.Score(req); level != ComplexityLow {
		t.Errorf("expected ComplexityLow for empty messages, got %s", level)
	}
}

func TestComplexityScorer_MultiStep(t *testing.T) {
	scorer := NewComplexityScorer()

	msg := `Please do the following:
1. Read the CSV file
2. Parse the headers
3. Filter rows where age > 30
4. Sort by name
5. Write to output`

	req := &ChatCompletionRequest{
		Messages: []Message{
			{Role: "user", Content: json.RawMessage(strconv.Quote(msg))},
		},
	}

	level := scorer.Score(req)
	if level != ComplexityHigh {
		t.Errorf("expected ComplexityHigh for multi-step, got %s", level)
	}
}

func TestRouteByComplexity(t *testing.T) {
	scorer := NewComplexityScorer()
	cfg := &ComplexityRoutingConfig{
		Low:    "gpt-4o-mini",
		Medium: "gpt-4o",
		High:   "o3",
		Code:   "claude-sonnet-4-20250514",
	}

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"simple", "Hi", "gpt-4o-mini"},
		{"code", "```python\nprint('hello')\n```", "claude-sonnet-4-20250514"},
		{"reasoning", "Analyze step by step the trade-offs", "o3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ChatCompletionRequest{
				Model: "default-model",
				Messages: []Message{
					{Role: "user", Content: json.RawMessage(strconv.Quote(tt.content))},
				},
			}
			got := RouteByComplexity(scorer, req, cfg)
			if got != tt.want {
				t.Errorf("expected model %q, got %q", tt.want, got)
			}
		})
	}
}

func TestRouteByComplexity_NilConfig(t *testing.T) {
	scorer := NewComplexityScorer()
	req := &ChatCompletionRequest{Model: "original"}

	got := RouteByComplexity(scorer, req, nil)
	if got != "original" {
		t.Errorf("expected original model, got %q", got)
	}
}

func BenchmarkComplexityScorer(b *testing.B) {
	scorer := NewComplexityScorer()

	req := &ChatCompletionRequest{
		Model: "gpt-4o",
		Messages: []Message{
			{Role: "system", Content: json.RawMessage(strconv.Quote("You are a helpful coding assistant."))},
			{Role: "user", Content: json.RawMessage(strconv.Quote("Write a function that calculates the Fibonacci sequence iteratively and explain the time complexity."))},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = scorer.Score(req)
	}
}

func TestRouteByComplexity_PartialConfig(t *testing.T) {
	scorer := NewComplexityScorer()
	cfg := &ComplexityRoutingConfig{
		Low: "gpt-4o-mini",
		// Medium, High, Code not set - should fall through to req.Model
	}

	req := &ChatCompletionRequest{
		Model: "default",
		Messages: []Message{
			{Role: "user", Content: json.RawMessage(strconv.Quote("Analyze step by step the implications"))},
		},
	}

	got := RouteByComplexity(scorer, req, cfg)
	if got != "default" {
		t.Errorf("expected fallback to 'default' for unmapped level, got %q", got)
	}
}
