// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("databricks", NewDatabricks)
}

// Databricks implements the Provider interface for the Databricks Model Serving API.
// It reuses the OpenAI provider since Databricks exposes an OpenAI-compatible API.
type Databricks struct {
	OpenAI
}

// NewDatabricks creates and initializes a new Databricks provider.
func NewDatabricks(client *http.Client) ai.Provider {
	return &Databricks{OpenAI: OpenAI{client: client}}
}

// Name returns the provider name.
func (d *Databricks) Name() string { return "databricks" }
