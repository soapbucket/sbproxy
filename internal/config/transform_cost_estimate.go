// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/soapbucket/sbproxy/internal/ai/pricing"
	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/tidwall/gjson"
)

func init() {
	transformLoaderFns[TransformCostEstimate] = NewCostEstimateTransform
}

// CostEstimateTransformConfig is the runtime config for cost estimation.
type CostEstimateTransformConfig struct {
	CostEstimateTransform

	inputRate  float64 // $/million tokens
	outputRate float64 // $/million tokens
}

// NewCostEstimateTransform creates a new cost estimation transformer.
func NewCostEstimateTransform(data []byte) (TransformConfig, error) {
	cfg := &CostEstimateTransformConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("cost_estimate: %w", err)
	}

	if cfg.Currency == "" {
		cfg.Currency = "USD"
	}

	if cfg.ContentTypes == nil {
		cfg.ContentTypes = JSONContentTypes
	}

	// Resolve pricing: explicit pricing_map > pricing file > zero (unknown)
	if cfg.PricingMap != nil {
		cfg.inputRate = cfg.PricingMap["input"]
		cfg.outputRate = cfg.PricingMap["output"]
	} else if cfg.Model != "" {
		if ps := pricing.Global(); ps != nil {
			if mp := ps.GetPricing(cfg.Model); mp != nil {
				cfg.inputRate = mp.InputPerMToken
				cfg.outputRate = mp.OutputPerMToken
			}
		}
	}

	cfg.tr = transformer.Func(cfg.estimate)

	return cfg, nil
}

func (c *CostEstimateTransformConfig) estimate(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if len(body) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	// Extract token counts from response usage or headers
	inputTokens, outputTokens := c.getTokenCounts(resp, body)

	if inputTokens > 0 || outputTokens > 0 {
		inputCost := float64(inputTokens) * c.inputRate / 1_000_000
		outputCost := float64(outputTokens) * c.outputRate / 1_000_000
		totalCost := inputCost + outputCost

		resp.Header.Set("X-Estimated-Cost", fmt.Sprintf("%.6f", totalCost))
		resp.Header.Set("X-Estimated-Cost-Currency", c.Currency)
		resp.Header.Set("X-Estimated-Cost-Input", fmt.Sprintf("%.6f", inputCost))
		resp.Header.Set("X-Estimated-Cost-Output", fmt.Sprintf("%.6f", outputCost))
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

func (c *CostEstimateTransformConfig) getTokenCounts(resp *http.Response, body []byte) (int, int) {
	// Try headers first (set by token_count transform)
	if prompt := resp.Header.Get("X-Token-Count-Prompt"); prompt != "" {
		inputTokens, _ := strconv.Atoi(prompt)
		outputTokens, _ := strconv.Atoi(resp.Header.Get("X-Token-Count-Completion"))
		if inputTokens > 0 || outputTokens > 0 {
			return inputTokens, outputTokens
		}
	}

	// Try response body usage object
	switch c.Provider {
	case "openai":
		input := int(gjson.GetBytes(body, "usage.prompt_tokens").Int())
		output := int(gjson.GetBytes(body, "usage.completion_tokens").Int())
		return input, output
	case "anthropic":
		input := int(gjson.GetBytes(body, "usage.input_tokens").Int())
		output := int(gjson.GetBytes(body, "usage.output_tokens").Int())
		return input, output
	default:
		// Try both formats
		input := int(gjson.GetBytes(body, "usage.prompt_tokens").Int())
		output := int(gjson.GetBytes(body, "usage.completion_tokens").Int())
		if input > 0 || output > 0 {
			return input, output
		}
		input = int(gjson.GetBytes(body, "usage.input_tokens").Int())
		output = int(gjson.GetBytes(body, "usage.output_tokens").Int())
		return input, output
	}
}
