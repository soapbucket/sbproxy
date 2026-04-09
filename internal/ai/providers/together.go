// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("together", NewTogether)
}

// Together implements the Provider interface for the Together AI API.
// It reuses the OpenAI provider since Together exposes an OpenAI-compatible API.
type Together struct {
	OpenAI
}

// NewTogether creates and initializes a new Together provider.
func NewTogether(client *http.Client) ai.Provider {
	return &Together{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (t *Together) Name() string { return "together" }
