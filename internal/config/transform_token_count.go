// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/tidwall/gjson"
)

func init() {
	transformLoaderFns[TransformTokenCount] = NewTokenCountTransform
}

// TokenCountTransformConfig is the runtime config for token counting.
type TokenCountTransformConfig struct {
	TokenCountTransform
}

// NewTokenCountTransform creates a new token count transformer.
func NewTokenCountTransform(data []byte) (TransformConfig, error) {
	cfg := &TokenCountTransformConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("token_count: %w", err)
	}

	if cfg.HeaderPrefix == "" {
		cfg.HeaderPrefix = "X-Token-Count"
	}

	if cfg.Provider == "" {
		cfg.Provider = "generic"
	}

	if cfg.ContentTypes == nil {
		cfg.ContentTypes = JSONContentTypes
	}

	cfg.tr = transformer.Func(cfg.count)

	return cfg, nil
}

func (c *TokenCountTransformConfig) count(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if len(body) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	// Try to extract usage from the response body (OpenAI/Anthropic format)
	usage := extractUsage(body, c.Provider)

	if usage.promptTokens > 0 {
		resp.Header.Set(c.HeaderPrefix+"-Prompt", strconv.Itoa(usage.promptTokens))
	}
	if usage.completionTokens > 0 {
		resp.Header.Set(c.HeaderPrefix+"-Completion", strconv.Itoa(usage.completionTokens))
	}
	if usage.totalTokens > 0 {
		resp.Header.Set(c.HeaderPrefix+"-Total", strconv.Itoa(usage.totalTokens))
	} else if usage.promptTokens > 0 || usage.completionTokens > 0 {
		resp.Header.Set(c.HeaderPrefix+"-Total", strconv.Itoa(usage.promptTokens+usage.completionTokens))
	}

	// If no usage object found, estimate from content
	if usage.totalTokens == 0 && usage.promptTokens == 0 && usage.completionTokens == 0 {
		content := extractResponseContent(body, c.Provider)
		if content != "" {
			estimated := estimateTokens(content)
			resp.Header.Set(c.HeaderPrefix+"-Estimated", strconv.Itoa(estimated))
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

type tokenUsage struct {
	promptTokens     int
	completionTokens int
	totalTokens      int
}

func extractUsage(body []byte, provider string) tokenUsage {
	var usage tokenUsage

	switch provider {
	case "openai":
		usage.promptTokens = int(gjson.GetBytes(body, "usage.prompt_tokens").Int())
		usage.completionTokens = int(gjson.GetBytes(body, "usage.completion_tokens").Int())
		usage.totalTokens = int(gjson.GetBytes(body, "usage.total_tokens").Int())
	case "anthropic":
		usage.promptTokens = int(gjson.GetBytes(body, "usage.input_tokens").Int())
		usage.completionTokens = int(gjson.GetBytes(body, "usage.output_tokens").Int())
		usage.totalTokens = usage.promptTokens + usage.completionTokens
	default:
		// Try OpenAI format first, then Anthropic
		usage.promptTokens = int(gjson.GetBytes(body, "usage.prompt_tokens").Int())
		usage.completionTokens = int(gjson.GetBytes(body, "usage.completion_tokens").Int())
		usage.totalTokens = int(gjson.GetBytes(body, "usage.total_tokens").Int())
		if usage.totalTokens == 0 {
			usage.promptTokens = int(gjson.GetBytes(body, "usage.input_tokens").Int())
			usage.completionTokens = int(gjson.GetBytes(body, "usage.output_tokens").Int())
			usage.totalTokens = usage.promptTokens + usage.completionTokens
		}
	}

	return usage
}

func extractResponseContent(body []byte, provider string) string {
	switch provider {
	case "openai":
		return gjson.GetBytes(body, "choices.0.message.content").String()
	case "anthropic":
		return gjson.GetBytes(body, "content.0.text").String()
	default:
		// Try both
		if content := gjson.GetBytes(body, "choices.0.message.content").String(); content != "" {
			return content
		}
		return gjson.GetBytes(body, "content.0.text").String()
	}
}

// estimateTokens provides a rough token count estimation.
// Approximation: ~4 characters per token for English text.
func estimateTokens(text string) int {
	// Count words as a rough proxy (avg 1.3 tokens per word)
	words := len(strings.Fields(text))
	if words == 0 {
		return len(text) / 4
	}
	return int(float64(words) * 1.3)
}
