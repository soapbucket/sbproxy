package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// PaloAltoAdapter integrates with Palo Alto Prisma AIRS.
// API: POST /v1/analyze
// Response: {"verdict": "malicious"/"suspicious"/"benign", "details": "..."}
type PaloAltoAdapter struct{}

// Detect sends content to Palo Alto Prisma AIRS and checks the verdict.
func (a *PaloAltoAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.prismacloud.io/v1/analyze"
	}
	apiKey := configString(config.Config, "api_key")

	body := map[string]any{"text": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("palo_alto: %w", err)
	}

	verdict, _ := resp["verdict"].(string)
	if verdict == "malicious" || verdict == "suspicious" {
		result.Triggered = true
		result.Details = fmt.Sprintf("Palo Alto AIRS verdict: %s", verdict)
	}

	result.Latency = time.Since(start)
	return result, nil
}
