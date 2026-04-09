package ai

import (
	"strings"

	json "github.com/goccy/go-json"
)

// isContentPolicyError returns true if the provider response indicates a content
// policy violation (as opposed to a normal client or server error). Each major
// provider signals this differently:
//
//   - OpenAI:    HTTP 400 with error.code "content_policy_violation"
//   - Azure:     HTTP 400 with error.code containing "content_filter"
//   - Anthropic: HTTP 400 with error.type "content_blocked" or type "invalid_request_error" with "content" in message
func isContentPolicyError(statusCode int, body []byte) bool {
	if statusCode != 400 {
		return false
	}
	if len(body) == 0 {
		return false
	}

	// Parse the error response to inspect provider-specific codes.
	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
		// Anthropic uses a top-level "type" field instead of error.type in some cases.
		Type    string `json:"type"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}

	// OpenAI: {"error": {"code": "content_policy_violation", ...}}
	if parsed.Error.Code == "content_policy_violation" {
		return true
	}

	// Azure: {"error": {"code": "content_filter", ...}} or code containing "content_filter"
	if strings.Contains(parsed.Error.Code, "content_filter") {
		return true
	}

	// Anthropic: {"error": {"type": "content_blocked", ...}} or top-level {"type": "error", "error": {"type": "..."}}
	if parsed.Error.Type == "content_blocked" {
		return true
	}

	// Anthropic alternate: top-level type "content_blocked"
	if parsed.Type == "content_blocked" {
		return true
	}

	return false
}

// isContentPolicyAIError checks an already-parsed AIError for content policy patterns.
// This is used in the retry loop where errors have already been unmarshalled.
func isContentPolicyAIError(err *AIError) bool {
	if err == nil || err.StatusCode != 400 {
		return false
	}

	// OpenAI
	if err.Code == "content_policy_violation" {
		return true
	}

	// Azure
	if strings.Contains(err.Code, "content_filter") {
		return true
	}

	// Anthropic
	if err.Type == "content_blocked" {
		return true
	}

	return false
}
