// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("fireworks", NewFireworks)
}

// Fireworks implements the Provider interface for the Fireworks AI API.
// It reuses the OpenAI provider since Fireworks exposes an OpenAI-compatible API.
type Fireworks struct {
	OpenAI
}

// NewFireworks creates and initializes a new Fireworks AI provider.
func NewFireworks(client *http.Client) ai.Provider {
	return &Fireworks{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (f *Fireworks) Name() string { return "fireworks" }
