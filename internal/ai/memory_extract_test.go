package ai

import (
	json "github.com/goccy/go-json"
	"testing"
)

func rawJSON(s string) json.RawMessage {
	return json.RawMessage(s)
}

func strPtr(s string) *string {
	return &s
}

func TestExtractSystemPrompt(t *testing.T) {
	tests := []struct {
		name     string
		messages []Message
		want     string
	}{
		{
			name:     "no messages",
			messages: nil,
			want:     "",
		},
		{
			name: "no system message",
			messages: []Message{
				{Role: "user", Content: rawJSON(`"Hello"`)},
			},
			want: "",
		},
		{
			name: "single system message",
			messages: []Message{
				{Role: "system", Content: rawJSON(`"You are a helpful assistant."`)},
				{Role: "user", Content: rawJSON(`"Hello"`)},
			},
			want: "You are a helpful assistant.",
		},
		{
			name: "multiple system messages",
			messages: []Message{
				{Role: "system", Content: rawJSON(`"System prompt 1"`)},
				{Role: "user", Content: rawJSON(`"Hello"`)},
				{Role: "system", Content: rawJSON(`"System prompt 2"`)},
			},
			want: "System prompt 1\nSystem prompt 2",
		},
		{
			name: "system message with multipart content",
			messages: []Message{
				{Role: "system", Content: rawJSON(`[{"type":"text","text":"Multi-part system"}]`)},
			},
			want: "Multi-part system",
		},
		{
			name: "empty content system message",
			messages: []Message{
				{Role: "system", Content: rawJSON(`""`)},
				{Role: "user", Content: rawJSON(`"Hello"`)},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractSystemPrompt(tt.messages)
			if got != tt.want {
				t.Errorf("ExtractSystemPrompt() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMarshalInputMessages(t *testing.T) {
	tests := []struct {
		name               string
		messages           []Message
		excludeSystem      bool
		excludeToolResults bool
		wantContains       string
		wantNotContains    string
	}{
		{
			name:         "empty messages",
			messages:     nil,
			wantContains: "[]",
		},
		{
			name: "excludes system messages",
			messages: []Message{
				{Role: "system", Content: rawJSON(`"System prompt"`)},
				{Role: "user", Content: rawJSON(`"Hello"`)},
			},
			excludeSystem:   true,
			wantContains:    `"role":"user"`,
			wantNotContains: `"system"`,
		},
		{
			name: "includes system messages when not excluded",
			messages: []Message{
				{Role: "system", Content: rawJSON(`"System prompt"`)},
				{Role: "user", Content: rawJSON(`"Hello"`)},
			},
			excludeSystem: false,
			wantContains:  `"system"`,
		},
		{
			name: "redacts tool results",
			messages: []Message{
				{Role: "user", Content: rawJSON(`"Hello"`)},
				{Role: "tool", Content: rawJSON(`"Long tool result data..."`)},
			},
			excludeToolResults: true,
			wantContains:       `[tool result]`,
			wantNotContains:    `Long tool result data`,
		},
		{
			name: "preserves tool results when not excluded",
			messages: []Message{
				{Role: "tool", Content: rawJSON(`"Tool result data"`)},
			},
			excludeToolResults: false,
			wantContains:       `Tool result data`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MarshalInputMessages(tt.messages, tt.excludeSystem, tt.excludeToolResults)
			if tt.wantContains != "" {
				if !containsSubstr(got, tt.wantContains) {
					t.Errorf("MarshalInputMessages() = %s, want to contain %q", got, tt.wantContains)
				}
			}
			if tt.wantNotContains != "" {
				if containsSubstr(got, tt.wantNotContains) {
					t.Errorf("MarshalInputMessages() = %s, should not contain %q", got, tt.wantNotContains)
				}
			}
		})
	}
}

func TestMarshalOutputContent(t *testing.T) {
	tests := []struct {
		name         string
		choices      []Choice
		want         string
		wantContains string
	}{
		{
			name:    "empty choices",
			choices: nil,
			want:    "",
		},
		{
			name: "single choice plain text",
			choices: []Choice{
				{
					Index:        0,
					Message:      Message{Role: "assistant", Content: rawJSON(`"Hello there!"`)},
					FinishReason: strPtr("stop"),
				},
			},
			want: "Hello there!",
		},
		{
			name: "single choice with tool calls",
			choices: []Choice{
				{
					Index: 0,
					Message: Message{
						Role:    "assistant",
						Content: rawJSON(`""`),
						ToolCalls: []ToolCall{
							{ID: "call_1", Type: "function", Function: ToolCallFunction{Name: "get_weather", Arguments: `{"city":"NYC"}`}},
						},
					},
					FinishReason: strPtr("tool_calls"),
				},
			},
			wantContains: `get_weather`,
		},
		{
			name: "multiple choices",
			choices: []Choice{
				{
					Index:        0,
					Message:      Message{Role: "assistant", Content: rawJSON(`"Option A"`)},
					FinishReason: strPtr("stop"),
				},
				{
					Index:        1,
					Message:      Message{Role: "assistant", Content: rawJSON(`"Option B"`)},
					FinishReason: strPtr("stop"),
				},
			},
			wantContains: "Option A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MarshalOutputContent(tt.choices)
			if tt.want != "" && got != tt.want {
				t.Errorf("MarshalOutputContent() = %q, want %q", got, tt.want)
			}
			if tt.wantContains != "" && !containsSubstr(got, tt.wantContains) {
				t.Errorf("MarshalOutputContent() = %q, want to contain %q", got, tt.wantContains)
			}
		})
	}
}

func TestExtractToolsAvailable(t *testing.T) {
	tests := []struct {
		name  string
		tools []Tool
		want  int
	}{
		{name: "no tools", tools: nil, want: 0},
		{
			name: "two tools",
			tools: []Tool{
				{Type: "function", Function: ToolFunction{Name: "get_weather"}},
				{Type: "function", Function: ToolFunction{Name: "search"}},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractToolsAvailable(tt.tools)
			if len(got) != tt.want {
				t.Errorf("ExtractToolsAvailable() returned %d names, want %d", len(got), tt.want)
			}
		})
	}
}

func TestExtractToolsCalled(t *testing.T) {
	tests := []struct {
		name    string
		choices []Choice
		want    int
	}{
		{name: "no choices", choices: nil, want: 0},
		{
			name:    "no tool calls",
			choices: []Choice{{Message: Message{Role: "assistant", Content: rawJSON(`"Hello"`)}}},
			want:    0,
		},
		{
			name: "with tool calls",
			choices: []Choice{
				{
					Message: Message{
						Role: "assistant",
						ToolCalls: []ToolCall{
							{Function: ToolCallFunction{Name: "get_weather"}},
							{Function: ToolCallFunction{Name: "search"}},
						},
					},
				},
			},
			want: 2,
		},
		{
			name: "deduplicates tool calls",
			choices: []Choice{
				{
					Message: Message{
						Role: "assistant",
						ToolCalls: []ToolCall{
							{Function: ToolCallFunction{Name: "search"}},
							{Function: ToolCallFunction{Name: "search"}},
						},
					},
				},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractToolsCalled(tt.choices)
			if len(got) != tt.want {
				t.Errorf("ExtractToolsCalled() = %v (len %d), want len %d", got, len(got), tt.want)
			}
		})
	}
}

func TestExtractStopReason(t *testing.T) {
	tests := []struct {
		name    string
		choices []Choice
		want    string
	}{
		{name: "no choices", choices: nil, want: ""},
		{name: "nil finish reason", choices: []Choice{{Message: Message{Role: "assistant"}}}, want: ""},
		{name: "stop reason", choices: []Choice{{FinishReason: strPtr("stop")}}, want: "stop"},
		{name: "tool_calls reason", choices: []Choice{{FinishReason: strPtr("tool_calls")}}, want: "tool_calls"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractStopReason(tt.choices)
			if got != tt.want {
				t.Errorf("ExtractStopReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStreamAccumulator(t *testing.T) {
	t.Run("accumulates text content", func(t *testing.T) {
		sa := NewStreamAccumulator()
		sa.AddChunk(&StreamChunk{
			Model:   "gpt-4",
			Choices: []StreamChoice{{Delta: StreamDelta{Content: strPtr("Hello")}}},
		})
		sa.AddChunk(&StreamChunk{
			Choices: []StreamChoice{{Delta: StreamDelta{Content: strPtr(" world")}}},
		})
		sa.AddChunk(&StreamChunk{
			Choices: []StreamChoice{{FinishReason: strPtr("stop")}},
		})

		if got := sa.BuildOutputContent(); got != "Hello world" {
			t.Errorf("BuildOutputContent() = %q, want %q", got, "Hello world")
		}
		if got := sa.ContentLen(); got != len("Hello world") {
			t.Errorf("ContentLen() = %d, want %d", got, len("Hello world"))
		}
		if sa.FinishReason != "stop" {
			t.Errorf("FinishReason = %q, want %q", sa.FinishReason, "stop")
		}
		if sa.Model != "gpt-4" {
			t.Errorf("Model = %q, want %q", sa.Model, "gpt-4")
		}
	})

	t.Run("accumulates tool calls", func(t *testing.T) {
		sa := NewStreamAccumulator()
		sa.AddChunk(&StreamChunk{
			Choices: []StreamChoice{{
				Delta: StreamDelta{
					ToolCalls: []ToolCallDelta{
						{Index: 0, ID: "call_1", Type: "function", Function: &ToolCallFunction{Name: "search", Arguments: ""}},
					},
				},
			}},
		})
		sa.AddChunk(&StreamChunk{
			Choices: []StreamChoice{{
				Delta: StreamDelta{
					ToolCalls: []ToolCallDelta{
						{Index: 0, Function: &ToolCallFunction{Arguments: `{"q":`}},
					},
				},
			}},
		})
		sa.AddChunk(&StreamChunk{
			Choices: []StreamChoice{{
				Delta: StreamDelta{
					ToolCalls: []ToolCallDelta{
						{Index: 0, Function: &ToolCallFunction{Arguments: `"test"}`}},
					},
				},
			}},
		})

		called := sa.StreamAccToolsCalled()
		if len(called) != 1 || called[0] != "search" {
			t.Errorf("StreamAccToolsCalled() = %v, want [search]", called)
		}
		output := sa.BuildOutputContent()
		if !containsSubstr(output, "search") {
			t.Errorf("BuildOutputContent() = %q, want to contain 'search'", output)
		}
	})
}

func containsSubstr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
