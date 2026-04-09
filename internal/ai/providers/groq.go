// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("groq", NewGroq)
}

// Groq implements the Provider interface for the Groq API.
// It reuses the OpenAI provider since Groq exposes an OpenAI-compatible API.
type Groq struct {
	OpenAI
}

// NewGroq creates and initializes a new Groq provider.
func NewGroq(client *http.Client) ai.Provider {
	return &Groq{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (g *Groq) Name() string { return "groq" }
