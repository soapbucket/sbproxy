// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/tidwall/gjson"
)

func init() {
	transformLoaderFns[TransformClassify] = NewClassifyTransform
}

// ClassifyTransformConfig is the runtime config for content classification.
type ClassifyTransformConfig struct {
	ClassifyTransform

	compiledRules []compiledClassifyRule
}

type compiledClassifyRule struct {
	name     string
	pattern  *regexp.Regexp // nil if no regex pattern
	jsonPath string         // gjson path
	celExpr  string         // CEL expression (for future use)
}

// NewClassifyTransform creates a new content classification transformer.
func NewClassifyTransform(data []byte) (TransformConfig, error) {
	cfg := &ClassifyTransformConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("classify: %w", err)
	}

	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("classify: at least one rule is required")
	}

	if cfg.HeaderName == "" {
		cfg.HeaderName = "X-Content-Class"
	}

	// Precompile rules
	for _, rule := range cfg.Rules {
		cr := compiledClassifyRule{
			name:     rule.Name,
			jsonPath: rule.JSONPath,
			celExpr:  rule.CELExpr,
		}

		if rule.Pattern != "" {
			if len(rule.Pattern) > 4096 {
				return nil, fmt.Errorf("classify: pattern in rule %q too long (%d chars, max 4096)", rule.Name, len(rule.Pattern))
			}
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("classify: invalid pattern in rule %q: %w", rule.Name, err)
			}
			cr.pattern = re
		}

		cfg.compiledRules = append(cfg.compiledRules, cr)
	}

	cfg.tr = transformer.Func(cfg.classify)

	return cfg, nil
}

func (c *ClassifyTransformConfig) classify(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	var matched []string

	for _, rule := range c.compiledRules {
		if c.matchRule(rule, body) {
			matched = append(matched, rule.name)
		}
	}

	if len(matched) > 0 {
		resp.Header.Set(c.HeaderName, strings.Join(matched, ","))
	}

	// Body is never modified — restore it
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

func (c *ClassifyTransformConfig) matchRule(rule compiledClassifyRule, body []byte) bool {
	// Regex pattern match against body
	if rule.pattern != nil {
		if rule.pattern.Match(body) {
			return true
		}
	}

	// JSONPath check: path must exist and have a truthy value
	if rule.jsonPath != "" {
		result := gjson.GetBytes(body, rule.jsonPath)
		if result.Exists() {
			// For boolean paths, check truthiness
			if result.Type == gjson.True {
				return true
			}
			// For string/number/array/object, existence is enough
			if result.Type != gjson.False && result.Type != gjson.Null {
				return true
			}
		}
	}

	return false
}
