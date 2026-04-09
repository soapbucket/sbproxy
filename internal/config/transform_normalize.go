// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/request/classifier"
	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func init() {
	transformLoaderFns[TransformNormalize] = NewNormalizeTransform
}

// NormalizeTransformConfig normalizes prompt text via the classifier sidecar.
type NormalizeTransformConfig struct {
	NormalizeTransform
	configID string
}

// NormalizeTransform holds the user-facing configuration for text normalization.
type NormalizeTransform struct {
	BaseTransform
	ReplaceBody bool            `json:"replace_body,omitempty"`
	HeaderName  string          `json:"header_name,omitempty"`
	Rules       []NormalizeRule `json:"rules,omitempty"`
}

// NormalizeRule defines a regex find/replace rule for text normalization.
type NormalizeRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Replace string `json:"replace"`
}

// NewNormalizeTransform creates a new normalize transform from JSON config.
func NewNormalizeTransform(data []byte) (TransformConfig, error) {
	cfg := &NormalizeTransformConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("normalize: %w", err)
	}
	cfg.tr = transformer.Func(cfg.normalize)
	return cfg, nil
}

// Init registers normalization rules with the classifier sidecar.
func (c *NormalizeTransformConfig) Init(cfg *Config) error {
	c.configID = cfg.ID
	if err := c.BaseTransform.Init(cfg); err != nil {
		return err
	}
	// Register normalization rules as part of the tenant (via TenantSync)
	if ts := classifier.GlobalSync(); ts != nil && len(c.Rules) > 0 {
		normRules := make([]classifier.SidecarNormRule, len(c.Rules))
		for i, r := range c.Rules {
			normRules[i] = classifier.SidecarNormRule{
				Name:    r.Name,
				Pattern: r.Pattern,
				Replace: r.Replace,
			}
		}
		osc := &classifier.OriginSidecarConfig{NormRules: normRules}
		_ = ts.RegisterOrigin(c.configID, osc)
	}
	return nil
}

func (c *NormalizeTransformConfig) normalize(resp *http.Response) error {
	mc := classifier.Global()
	if mc == nil || !mc.IsAvailable() {
		return nil // fail open
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// Extract last user message content from AI request JSON
	text := extractUserMessage(body)
	if text == "" {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	// Classify to get normalized text
	result, cerr := mc.ClassifyForTenant(text, 1, c.configID)
	if cerr != nil {
		slog.Debug("normalize transform: sidecar error", "error", cerr)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil // fail open
	}

	normalized := result.Normalized
	if normalized == "" {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	if c.HeaderName != "" {
		resp.Request.Header.Set(c.HeaderName, normalized)
	}

	if c.ReplaceBody {
		body = replaceLastUserMessage(body, normalized)
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

// extractUserMessage extracts the content of the last user message from an OpenAI-format JSON body.
func extractUserMessage(body []byte) string {
	messages := gjson.GetBytes(body, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return ""
	}
	var lastUserContent string
	messages.ForEach(func(_, value gjson.Result) bool {
		if value.Get("role").String() == "user" {
			lastUserContent = value.Get("content").String()
		}
		return true
	})
	return lastUserContent
}

// replaceLastUserMessage patches the last user message content in the JSON body.
func replaceLastUserMessage(body []byte, newContent string) []byte {
	messages := gjson.GetBytes(body, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return body
	}
	lastIdx := -1
	idx := 0
	messages.ForEach(func(_, value gjson.Result) bool {
		if value.Get("role").String() == "user" {
			lastIdx = idx
		}
		idx++
		return true
	})
	if lastIdx < 0 {
		return body
	}
	path := fmt.Sprintf("messages.%d.content", lastIdx)
	result, err := sjson.SetBytes(body, path, newContent)
	if err != nil {
		return body
	}
	return result
}
