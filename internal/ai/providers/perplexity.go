// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("perplexity", NewPerplexity)
}

// Perplexity implements the Provider interface for the Perplexity API.
// It reuses the OpenAI provider since Perplexity exposes an OpenAI-compatible API.
type Perplexity struct {
	OpenAI
}

// NewPerplexity creates and initializes a new Perplexity provider.
func NewPerplexity(client *http.Client) ai.Provider {
	return &Perplexity{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (p *Perplexity) Name() string { return "perplexity" }
