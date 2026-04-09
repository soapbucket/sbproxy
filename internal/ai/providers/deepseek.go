// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("deepseek", NewDeepSeek)
}

// DeepSeek implements the Provider interface for the DeepSeek API.
// It reuses the OpenAI provider since DeepSeek exposes an OpenAI-compatible API.
type DeepSeek struct {
	OpenAI
}

// NewDeepSeek creates and initializes a new DeepSeek provider.
func NewDeepSeek(client *http.Client) ai.Provider {
	return &DeepSeek{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (d *DeepSeek) Name() string { return "deepseek" }
