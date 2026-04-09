// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"net/http"
	"strings"
)

// APIFormat identifies the API format of a request.
type APIFormat string

const (
	// FormatOpenAI is the OpenAI chat completions format.
	FormatOpenAI APIFormat = "openai"
	// FormatAnthropic is the Anthropic Messages API format.
	FormatAnthropic APIFormat = "anthropic"
	// FormatUnknown is used when the format cannot be determined.
	FormatUnknown APIFormat = "unknown"
)

// DetectFormat determines the API format from the request path and headers.
// Path-based detection:
//   - /v1/chat/completions -> FormatOpenAI
//   - /v1/messages -> FormatAnthropic
//
// Header override: X-SB-Format: anthropic or X-SB-Format: openai
func DetectFormat(r *http.Request) APIFormat {
	// Header override takes priority
	if override := r.Header.Get("X-SB-Format"); override != "" {
		switch strings.ToLower(override) {
		case "anthropic":
			return FormatAnthropic
		case "openai":
			return FormatOpenAI
		}
	}

	// Path-based detection
	path := strings.TrimPrefix(r.URL.Path, "/")
	path = strings.TrimPrefix(path, "v1/")

	switch {
	case path == "messages":
		return FormatAnthropic
	case path == "chat/completions":
		return FormatOpenAI
	default:
		return FormatUnknown
	}
}
