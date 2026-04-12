// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("xai", NewXAI)
}

// XAI implements the Provider interface for the xAI (Grok) API.
// It reuses the OpenAI provider since xAI exposes an OpenAI-compatible API.
type XAI struct {
	OpenAI
}

// NewXAI creates and initializes a new xAI provider.
func NewXAI(client *http.Client) ai.Provider {
	return &XAI{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (x *XAI) Name() string { return "xai" }
