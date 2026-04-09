// Package modifier provides request and response modification capabilities for header, body, and URL transformations.
package modifier

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

// TokenEstimationConfig configures request-side token estimation.
// Estimates tokens in the request body and optionally enforces a token budget.
type TokenEstimationConfig struct {
	Provider     string `json:"provider,omitempty"`      // "openai", "anthropic", "generic"
	MaxTokens    int    `json:"max_tokens,omitempty"`    // Token budget (0 = no limit)
	StatusCode   int    `json:"status_code,omitempty"`   // HTTP status when over budget (default: 413)
	HeaderPrefix string `json:"header_prefix,omitempty"` // Header prefix (default: "X-Estimated-Tokens")
}

func applyTokenEstimation(req *http.Request, cfg *TokenEstimationConfig) error {
	if req.Body == nil || req.ContentLength == 0 {
		return nil
	}

	// Only process JSON content types
	ct := parseMediaType(req.Header.Get("Content-Type"))
	if ct != "application/json" {
		return nil
	}

	// Read body
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(nil))
		return fmt.Errorf("token_estimation: failed to read body: %w", err)
	}

	if len(body) == 0 {
		req.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	// Estimate tokens from the request
	estimated := estimateRequestTokens(body, cfg.Provider)

	// Restore body
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	// Set header
	headerPrefix := cfg.HeaderPrefix
	if headerPrefix == "" {
		headerPrefix = "X-Estimated-Tokens"
	}
	req.Header.Set(headerPrefix, strconv.Itoa(estimated))

	// Enforce token budget
	if cfg.MaxTokens > 0 && estimated > cfg.MaxTokens {
		statusCode := cfg.StatusCode
		if statusCode == 0 {
			statusCode = http.StatusRequestEntityTooLarge
		}
		req.Header.Set("X-Token-Budget-Exceeded", "true")
		req.Header.Set("X-Token-Budget-Limit", strconv.Itoa(cfg.MaxTokens))
		req.Header.Set("X-Token-Budget-Reject", strconv.Itoa(statusCode))
	}

	return nil
}

// estimateRequestTokens estimates the token count from a request body.
func estimateRequestTokens(body []byte, provider string) int {
	total := 0

	switch provider {
	case "openai", "anthropic":
		// Extract messages array and estimate per message
		messages := gjson.GetBytes(body, "messages")
		if messages.IsArray() {
			messages.ForEach(func(_, msg gjson.Result) bool {
				content := msg.Get("content").String()
				role := msg.Get("role").String()
				// ~4 tokens for role/formatting overhead per message
				total += 4
				total += estimateTextTokens(content)
				_ = role
				return true
			})
		}
		// System prompt (OpenAI) or system field (Anthropic)
		if system := gjson.GetBytes(body, "system"); system.Exists() {
			if system.IsArray() {
				// Anthropic system blocks
				system.ForEach(func(_, block gjson.Result) bool {
					total += estimateTextTokens(block.Get("text").String())
					return true
				})
			} else {
				total += estimateTextTokens(system.String())
			}
		}
	default:
		// Generic: estimate from full body text
		total = estimateTextTokens(string(body))
	}

	return total
}

// estimateTextTokens provides a rough token count estimate for text.
// Approximation: ~1.3 tokens per word for English text.
func estimateTextTokens(text string) int {
	words := len(strings.Fields(text))
	if words == 0 {
		return len(text) / 4
	}
	return int(float64(words) * 1.3)
}
