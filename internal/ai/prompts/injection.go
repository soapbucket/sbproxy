// injection.go applies system prompt prepend/append injection to message arrays.
package prompts

import (
	json "github.com/goccy/go-json"
	"strconv"
	"strings"
)

// SystemPromptConfig configures system prompt injection.
type SystemPromptConfig struct {
	Prepend   string            `json:"prepend,omitempty"`
	Append    string            `json:"append,omitempty"`
	Variables map[string]string `json:"variables,omitempty"`
}

// message mirrors ai.Message for system prompt injection without importing the ai package.
type message struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	Name       string          `json:"name,omitempty"`
	ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
}

// ApplySystemPrompt applies system prompt injection to messages.
// If there is an existing system message, prepend/append to it.
// If there is no system message, create one with prepend + append.
// Variables in prepend/append are substituted before application.
func (c *SystemPromptConfig) ApplySystemPrompt(messages []json.RawMessage) []json.RawMessage {
	if c == nil {
		return messages
	}
	prepend := substituteVariables(c.Prepend, c.Variables)
	appendText := substituteVariables(c.Append, c.Variables)
	if prepend == "" && appendText == "" {
		return messages
	}

	// Find the first system message index.
	systemIdx := -1
	for i, raw := range messages {
		var m message
		if err := json.Unmarshal(raw, &m); err == nil && m.Role == "system" {
			systemIdx = i
			break
		}
	}

	if systemIdx >= 0 {
		// Modify the existing system message.
		var m message
		if err := json.Unmarshal(messages[systemIdx], &m); err != nil {
			return messages
		}
		existing := contentString(m.Content)
		updated := buildSystemContent(prepend, existing, appendText)
		m.Content = json.RawMessage(strconv.Quote(updated))
		raw, err := json.Marshal(m)
		if err != nil {
			return messages
		}
		result := make([]json.RawMessage, len(messages))
		copy(result, messages)
		result[systemIdx] = raw
		return result
	}

	// No system message exists - create one.
	combined := buildSystemContent(prepend, "", appendText)
	m := message{
		Role:    "system",
		Content: json.RawMessage(strconv.Quote(combined)),
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return messages
	}
	result := make([]json.RawMessage, 0, len(messages)+1)
	result = append(result, raw)
	result = append(result, messages...)
	return result
}

// buildSystemContent joins prepend, existing, and append with newlines.
func buildSystemContent(prepend, existing, appendText string) string {
	var parts []string
	if prepend != "" {
		parts = append(parts, prepend)
	}
	if existing != "" {
		parts = append(parts, existing)
	}
	if appendText != "" {
		parts = append(parts, appendText)
	}
	return strings.Join(parts, "\n")
}

// contentString extracts a plain string from JSON content (handles quoted strings).
func contentString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}
