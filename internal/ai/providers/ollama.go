// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("ollama", NewOllama)
}

// Ollama implements the Provider interface for Ollama's OpenAI-compatible API.
// Ollama serves models locally and does not require an API key.
type Ollama struct {
	OpenAI
}

// NewOllama creates and initializes a new Ollama provider.
func NewOllama(client *http.Client) ai.Provider {
	return &Ollama{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (o *Ollama) Name() string { return "ollama" }
