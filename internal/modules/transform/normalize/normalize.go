// Package normalize registers the normalize transform.
package normalize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/request/classifier"
	"github.com/soapbucket/sbproxy/pkg/plugin"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func init() {
	plugin.RegisterTransform("normalize", New)
}

// NormalizeRule defines a regex find/replace rule for text normalization.
type NormalizeRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Replace string `json:"replace"`
}

// Config holds configuration for the normalize transform.
type Config struct {
	Type        string          `json:"type"`
	ReplaceBody bool            `json:"replace_body,omitempty"`
	HeaderName  string          `json:"header_name,omitempty"`
	Rules       []NormalizeRule `json:"rules,omitempty"`
}

// normalizeTransform implements plugin.TransformHandler.
type normalizeTransform struct {
	replaceBody bool
	headerName  string
	rules       []NormalizeRule
	configID    string
}

// New creates a new normalize transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("normalize: %w", err)
	}
	return &normalizeTransform{
		replaceBody: cfg.ReplaceBody,
		headerName:  cfg.HeaderName,
		rules:       cfg.Rules,
	}, nil
}

// Provision implements plugin.Provisioner to register normalization rules with the classifier.
func (c *normalizeTransform) Provision(ctx plugin.PluginContext) error {
	c.configID = ctx.OriginID
	if ts := classifier.GlobalSync(); ts != nil && len(c.rules) > 0 {
		normRules := make([]classifier.SidecarNormRule, len(c.rules))
		for i, r := range c.rules {
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

func (c *normalizeTransform) Type() string { return "normalize" }
func (c *normalizeTransform) Apply(resp *http.Response) error {
	mc := classifier.Global()
	if mc == nil || !mc.IsAvailable() {
		return nil // fail open
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	text := extractUserMessage(body)
	if text == "" {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

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

	if c.headerName != "" {
		resp.Request.Header.Set(c.headerName, normalized)
	}

	if c.replaceBody {
		body = replaceLastUserMessage(body, normalized)
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

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
