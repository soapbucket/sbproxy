package adapters

import (
	"fmt"

	"github.com/soapbucket/sbproxy/internal/ai/callbacks"
)

// NewCallback creates the appropriate callback adapter based on config.Type.
// Supported types: langfuse, langsmith, helicone, datadog, otel, webhook.
func NewCallback(config *callbacks.CallbackConfig) (callbacks.Callback, error) {
	switch config.Type {
	case "langfuse":
		if config.Endpoint == "" {
			return nil, fmt.Errorf("langfuse: endpoint is required")
		}
		return NewLangfuseCallback(config.Endpoint, config.APIKey, config.SecretKey), nil

	case "langsmith":
		if config.Endpoint == "" {
			return nil, fmt.Errorf("langsmith: endpoint is required")
		}
		return NewLangSmithCallback(config.Endpoint, config.APIKey), nil

	case "helicone":
		if config.Endpoint == "" {
			return nil, fmt.Errorf("helicone: endpoint is required")
		}
		return NewHeliconeCallback(config.Endpoint, config.APIKey), nil

	case "datadog":
		if config.Endpoint == "" {
			return nil, fmt.Errorf("datadog: endpoint is required")
		}
		return NewDataDogCallback(config.Endpoint, config.APIKey), nil

	case "otel":
		if config.Endpoint == "" {
			return nil, fmt.Errorf("otel: endpoint is required")
		}
		return NewOTELCallback(config.Endpoint), nil

	case "webhook":
		if config.Endpoint == "" {
			return nil, fmt.Errorf("webhook: endpoint is required")
		}
		headers := make(map[string]string)
		for k, v := range config.Tags {
			headers[k] = v
		}
		return NewWebhookCallback(config.Endpoint, config.SecretKey, headers), nil

	default:
		return nil, fmt.Errorf("unknown callback type: %q", config.Type)
	}
}
