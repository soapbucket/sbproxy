// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	json "github.com/goccy/go-json"
	"strings"
)

// ExtractSystemPrompt finds and returns the content of system messages.
// If multiple system messages exist, they are joined with newlines.
func ExtractSystemPrompt(messages []Message) string {
	var b strings.Builder
	for _, m := range messages {
		if m.Role == "system" {
			content := m.ContentString()
			if content != "" {
				if b.Len() > 0 {
					b.WriteByte('\n')
				}
				b.WriteString(content)
			}
		}
	}
	return b.String()
}

// MarshalInputMessages serializes non-system messages to JSON.
// If excludeSystem is true, system messages are omitted.
// If excludeToolResults is true, tool message bodies are replaced with "[tool result]".
func MarshalInputMessages(messages []Message, excludeSystem, excludeToolResults bool) string {
	type slimMessage struct {
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content"`
		Name       string          `json:"name,omitempty"`
		ToolCalls  []ToolCall      `json:"tool_calls,omitempty"`
		ToolCallID string          `json:"tool_call_id,omitempty"`
	}

	var filtered []slimMessage
	for _, m := range messages {
		if excludeSystem && m.Role == "system" {
			continue
		}
		sm := slimMessage(m)
		// Replace tool result content with placeholder
		if excludeToolResults && m.Role == "tool" {
			sm.Content, _ = json.Marshal("[tool result]")
		}
		filtered = append(filtered, sm)
	}
	if len(filtered) == 0 {
		return "[]"
	}
	data, err := json.Marshal(filtered)
	if err != nil {
		return "[]"
	}
	return string(data)
}

// MarshalOutputContent serializes response choices to JSON.
func MarshalOutputContent(choices []Choice) string {
	if len(choices) == 0 {
		return ""
	}
	// For single choice, return just the message content
	if len(choices) == 1 {
		return marshalChoiceContent(choices[0])
	}
	// For multiple choices, return an array
	type choiceOutput struct {
		Index   int    `json:"index"`
		Content string `json:"content,omitempty"`
		Role    string `json:"role"`
	}
	out := make([]choiceOutput, len(choices))
	for i, c := range choices {
		out[i] = choiceOutput{
			Index:   c.Index,
			Content: c.Message.ContentString(),
			Role:    c.Message.Role,
		}
	}
	data, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(data)
}

// marshalChoiceContent serializes a single choice to a content string or JSON with tool calls.
func marshalChoiceContent(c Choice) string {
	// If there are tool calls, include them in the output
	if len(c.Message.ToolCalls) > 0 {
		type outputMsg struct {
			Role      string     `json:"role"`
			Content   string     `json:"content,omitempty"`
			ToolCalls []ToolCall `json:"tool_calls,omitempty"`
		}
		msg := outputMsg{
			Role:      c.Message.Role,
			Content:   c.Message.ContentString(),
			ToolCalls: c.Message.ToolCalls,
		}
		data, err := json.Marshal(msg)
		if err != nil {
			return c.Message.ContentString()
		}
		return string(data)
	}
	return c.Message.ContentString()
}

// ExtractToolsAvailable returns the function names of all available tools.
func ExtractToolsAvailable(tools []Tool) []string {
	if len(tools) == 0 {
		return nil
	}
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		if t.Function.Name != "" {
			names = append(names, t.Function.Name)
		}
	}
	return names
}

// ExtractToolsCalled returns the function names of all tool calls in the response choices.
func ExtractToolsCalled(choices []Choice) []string {
	seen := make(map[string]bool)
	var names []string
	for _, c := range choices {
		for _, tc := range c.Message.ToolCalls {
			if tc.Function.Name != "" && !seen[tc.Function.Name] {
				seen[tc.Function.Name] = true
				names = append(names, tc.Function.Name)
			}
		}
	}
	return names
}

// ExtractStopReason returns the finish_reason from the first choice.
func ExtractStopReason(choices []Choice) string {
	if len(choices) == 0 {
		return ""
	}
	if choices[0].FinishReason != nil {
		return *choices[0].FinishReason
	}
	return ""
}

// StreamAccumulator collects streamed chunks into a reconstructed response
// for memory capture after streaming completes.
type StreamAccumulator struct {
	// ToolCalls accumulates tool calls indexed by their stream index.
	ToolCalls map[int]*ToolCall

	// FinishReason from the final chunk.
	FinishReason string

	// Model from the first chunk.
	Model string

	contentBuilder strings.Builder
	contentLen     int
}

// NewStreamAccumulator creates a new StreamAccumulator.
func NewStreamAccumulator() *StreamAccumulator {
	return &StreamAccumulator{
		ToolCalls: make(map[int]*ToolCall),
	}
}

// AddChunk processes a streaming chunk and accumulates content.
func (sa *StreamAccumulator) AddChunk(chunk *StreamChunk) {
	if sa.Model == "" && chunk.Model != "" {
		sa.Model = chunk.Model
	}
	for _, choice := range chunk.Choices {
		if choice.Delta.Content != nil {
			sa.contentBuilder.WriteString(*choice.Delta.Content)
			sa.contentLen += len(*choice.Delta.Content)
		}
		if choice.FinishReason != nil {
			sa.FinishReason = *choice.FinishReason
		}
		for _, tc := range choice.Delta.ToolCalls {
			existing, ok := sa.ToolCalls[tc.Index]
			if !ok {
				toolCall := ToolCall{
					ID:   tc.ID,
					Type: tc.Type,
				}
				if tc.Function != nil {
					toolCall.Function = *tc.Function
				}
				sa.ToolCalls[tc.Index] = &toolCall
			} else {
				if tc.ID != "" {
					existing.ID = tc.ID
				}
				if tc.Function != nil {
					if tc.Function.Name != "" {
						existing.Function.Name = tc.Function.Name
					}
					existing.Function.Arguments += tc.Function.Arguments
				}
			}
		}
	}
}

// BuildOutputContent returns the accumulated output as a string suitable for storage.
func (sa *StreamAccumulator) BuildOutputContent() string {
	content := sa.contentBuilder.String()
	if len(sa.ToolCalls) == 0 {
		return content
	}
	// Build a structured output with content and tool calls
	type outputMsg struct {
		Role      string     `json:"role"`
		Content   string     `json:"content,omitempty"`
		ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	}
	var calls []ToolCall
	for i := 0; i < len(sa.ToolCalls); i++ {
		if tc, ok := sa.ToolCalls[i]; ok {
			calls = append(calls, *tc)
		}
	}
	msg := outputMsg{
		Role:      "assistant",
		Content:   content,
		ToolCalls: calls,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return content
	}
	return string(data)
}

// ContentLen returns the accumulated text length without forcing output reconstruction.
func (sa *StreamAccumulator) ContentLen() int {
	if sa == nil {
		return 0
	}
	return sa.contentLen
}

// StreamAccToolsCalled returns the names of tools called from accumulated data.
func (sa *StreamAccumulator) StreamAccToolsCalled() []string {
	if len(sa.ToolCalls) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var names []string
	for i := 0; i < len(sa.ToolCalls); i++ {
		if tc, ok := sa.ToolCalls[i]; ok {
			if tc.Function.Name != "" && !seen[tc.Function.Name] {
				seen[tc.Function.Name] = true
				names = append(names, tc.Function.Name)
			}
		}
	}
	return names
}
