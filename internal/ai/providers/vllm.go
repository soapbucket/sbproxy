// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("vllm", NewVLLM)
}

// VLLM implements the Provider interface for vLLM's OpenAI-compatible API.
// vLLM is a high-throughput serving engine for large language reqctx.
type VLLM struct {
	OpenAI
}

// NewVLLM creates and initializes a new VLLM provider.
func NewVLLM(client *http.Client) ai.Provider {
	return &VLLM{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (v *VLLM) Name() string { return "vllm" }
