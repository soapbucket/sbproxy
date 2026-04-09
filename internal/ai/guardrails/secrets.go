// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"regexp"
	"strings"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func init() {
	Register("secrets", NewSecretsGuardrail)
}

// SecretsConfig configures secrets detection.
type SecretsConfig struct {
	Action          string   `json:"action,omitempty"`
	MaskReplacement string   `json:"mask_replacement,omitempty"`
	CustomPatterns  []string `json:"custom_patterns,omitempty"`
}

// SecretsGuardrail detects API keys, passwords, and credentials in AI output.
type SecretsGuardrail struct {
	config   SecretsConfig
	patterns []*secretPattern
}

type secretPattern struct {
	re   *regexp.Regexp
	name string
}

// Precompiled secrets detection patterns.
var defaultSecretPatterns = []*secretPattern{
	{regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), "openai_key"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "aws_access_key"},
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36,}`), "github_pat"},
	{regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`), "private_key"},
	{regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*\S+`), "password_assignment"},
	{regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*["']?\S+`), "api_key_assignment"},
	{regexp.MustCompile(`[a-zA-Z0-9+/]{40,}={0,2}`), "base64_secret"},
	{regexp.MustCompile(`xox[bpras]-[a-zA-Z0-9-]+`), "slack_token"},
}

// NewSecretsGuardrail creates a secrets detection guardrail.
func NewSecretsGuardrail(config json.RawMessage) (Guardrail, error) {
	cfg := SecretsConfig{
		Action:          "mask",
		MaskReplacement: "[REDACTED]",
	}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}
	if cfg.Action == "" {
		cfg.Action = "mask"
	}
	if cfg.MaskReplacement == "" {
		cfg.MaskReplacement = "[REDACTED]"
	}

	patterns := make([]*secretPattern, len(defaultSecretPatterns))
	copy(patterns, defaultSecretPatterns)

	for _, p := range cfg.CustomPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid custom secret pattern %q: %w", p, err)
		}
		patterns = append(patterns, &secretPattern{re: re, name: "custom"})
	}

	return &SecretsGuardrail{config: cfg, patterns: patterns}, nil
}

// Name returns the guardrail identifier.
func (g *SecretsGuardrail) Name() string { return "secrets" }

// Phase returns when this guardrail runs.
func (g *SecretsGuardrail) Phase() Phase { return PhaseOutput }

// Check evaluates content for secrets.
func (g *SecretsGuardrail) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	var matchedTypes []string
	seen := map[string]bool{}

	for _, p := range g.patterns {
		if p.re.MatchString(text) {
			if !seen[p.name] {
				matchedTypes = append(matchedTypes, p.name)
				seen[p.name] = true
			}
		}
	}

	if len(matchedTypes) == 0 {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	action := ActionTransform
	if g.config.Action == "block" {
		action = ActionBlock
	}

	return &Result{
		Pass:   false,
		Action: action,
		Reason: "Secrets detected: " + strings.Join(matchedTypes, ", "),
		Score:  1.0,
		Details: map[string]any{
			"secret_types": matchedTypes,
			"action":       g.config.Action,
		},
	}, nil
}

// Transform replaces detected secrets with the mask replacement string.
func (g *SecretsGuardrail) Transform(_ context.Context, content *Content) (*Content, error) {
	out := &Content{
		Messages: make([]ai.Message, len(content.Messages)),
		Model:    content.Model,
	}
	copy(out.Messages, content.Messages)

	for i := range out.Messages {
		text := out.Messages[i].ContentString()
		if text == "" {
			continue
		}

		masked := text
		for _, p := range g.patterns {
			masked = p.re.ReplaceAllString(masked, g.config.MaskReplacement)
		}

		if masked != text {
			rawContent, _ := json.Marshal(masked)
			out.Messages[i].Content = rawContent
		}
	}

	if content.Text != "" {
		masked := content.Text
		for _, p := range g.patterns {
			masked = p.re.ReplaceAllString(masked, g.config.MaskReplacement)
		}
		out.Text = masked
	}

	return out, nil
}
