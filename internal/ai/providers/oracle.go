// Package providers contains AI provider implementations for routing requests to upstream LLM services.
package providers

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	ai.RegisterProvider("oracle", NewOracle)
}

// Oracle implements the Provider interface for Oracle Cloud Infrastructure (OCI) Generative AI.
// It wraps the Generic provider, using Bearer token authentication with a pre-generated
// OCI session token. The user sets api_key to their OCI session token and base_url to
// their regional OCI GenAI endpoint (e.g.,
// "https://inference.generativeai.us-chicago-1.oci.oraclecloud.com/20231130/actions").
type Oracle struct {
	Generic
}

// NewOracle creates and initializes a new Oracle provider.
func NewOracle(client *http.Client) ai.Provider {
	return &Oracle{Generic: Generic{OpenAI: OpenAI{client: client}}}
}

// Name returns the provider name.
func (o *Oracle) Name() string { return "oracle" }
