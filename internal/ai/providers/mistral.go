// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("mistral", NewMistral)
}

// Mistral implements the Provider interface for the Mistral AI API.
// It reuses the OpenAI provider since Mistral exposes an OpenAI-compatible API.
type Mistral struct {
	OpenAI
}

// NewMistral creates and initializes a new Mistral provider.
func NewMistral(client *http.Client) ai.Provider {
	return &Mistral{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (m *Mistral) Name() string { return "mistral" }
