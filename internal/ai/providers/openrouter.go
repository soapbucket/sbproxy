// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("openrouter", NewOpenRouter)
}

// OpenRouter implements the Provider interface for the OpenRouter API.
// It reuses the OpenAI provider since OpenRouter exposes an OpenAI-compatible API.
type OpenRouter struct {
	OpenAI
}

// NewOpenRouter creates and initializes a new OpenRouter provider.
func NewOpenRouter(client *http.Client) ai.Provider {
	return &OpenRouter{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (o *OpenRouter) Name() string { return "openrouter" }
