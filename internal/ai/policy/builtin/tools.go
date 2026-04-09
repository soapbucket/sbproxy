package builtin

import (
	"context"
	"fmt"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// ToolCallDetector limits the number of tool calls in a request.
// Content should be a JSON array of tool calls, or a JSON object with a "tool_calls" field.
// Config fields:
//   - "max_calls" (int) - maximum number of tool calls allowed
//   - "allowed_tools" ([]string) - optional list of allowed tool names
//   - "blocked_tools" ([]string) - optional list of blocked tool names
type ToolCallDetector struct{}

// Detect checks tool calls against limits and allowlists.
func (d *ToolCallDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	maxCalls, hasMax := toInt(config.Config["max_calls"])
	allowedTools, _ := toStringSlice(config.Config["allowed_tools"])
	blockedTools, _ := toStringSlice(config.Config["blocked_tools"])

	toolCalls := extractToolCalls(content)
	callCount := len(toolCalls)

	var issues []string

	if hasMax && callCount > maxCalls {
		issues = append(issues, fmt.Sprintf("tool calls %d > max %d", callCount, maxCalls))
	}

	blockedSet := make(map[string]bool, len(blockedTools))
	for _, t := range blockedTools {
		blockedSet[t] = true
	}

	allowedSet := make(map[string]bool, len(allowedTools))
	for _, t := range allowedTools {
		allowedSet[t] = true
	}

	for _, name := range toolCalls {
		if blockedSet[name] {
			issues = append(issues, fmt.Sprintf("blocked tool: %s", name))
		}
		if len(allowedTools) > 0 && !allowedSet[name] {
			issues = append(issues, fmt.Sprintf("tool %s not in allowed list", name))
		}
	}

	if len(issues) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("tool call issues: %s", joinMax(issues, 5))
	}

	result.Latency = time.Since(start)
	return result, nil
}

// extractToolCalls parses tool call names from content.
func extractToolCalls(content string) []string {
	// Try as JSON array of objects with "name" or "function.name".
	var arr []map[string]any
	if err := json.Unmarshal([]byte(content), &arr); err == nil {
		var names []string
		for _, item := range arr {
			if name, ok := item["name"].(string); ok {
				names = append(names, name)
			} else if fn, ok := item["function"].(map[string]any); ok {
				if name, ok := fn["name"].(string); ok {
					names = append(names, name)
				}
			}
		}
		return names
	}

	// Try as object with "tool_calls" field.
	var obj map[string]any
	if err := json.Unmarshal([]byte(content), &obj); err == nil {
		if tc, ok := obj["tool_calls"].([]any); ok {
			var names []string
			for _, item := range tc {
				if m, ok := item.(map[string]any); ok {
					if name, ok := m["name"].(string); ok {
						names = append(names, name)
					} else if fn, ok := m["function"].(map[string]any); ok {
						if name, ok := fn["name"].(string); ok {
							names = append(names, name)
						}
					}
				}
			}
			return names
		}
	}

	return nil
}

// joinMax joins up to max strings with ", ".
func joinMax(ss []string, max int) string {
	if len(ss) <= max {
		return fmt.Sprintf("%s", joinStrings(ss))
	}
	return fmt.Sprintf("%s (and %d more)", joinStrings(ss[:max]), len(ss)-max)
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += "; "
		}
		result += s
	}
	return result
}
