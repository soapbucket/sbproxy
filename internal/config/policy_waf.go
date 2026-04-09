// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/config/waf"
)

// WAFPolicyConfig wraps WAFPolicy with runtime evaluation state.
// The open-source build provides a minimal pass-through implementation;
// the full rule engine lives in the enterprise module.
type WAFPolicyConfig struct {
	WAFPolicy
	config     *Config
	ruleEngine *waf.RuleEngine
}

// NewWAFPolicy creates a WAFPolicyConfig from raw JSON.
func NewWAFPolicy(data []byte) (interface{}, error) {
	var p WAFPolicyConfig
	if err := json.Unmarshal(data, &p.WAFPolicy); err != nil {
		return nil, fmt.Errorf("waf policy: %w", err)
	}
	p.PolicyType = "waf"
	return &p, nil
}

// Init initialises the WAF policy with the parent config.
// In the open-source build this stores the config reference but does not
// compile rules (enterprise feature).
func (p *WAFPolicyConfig) Init(cfg *Config) error {
	p.config = cfg
	if len(p.CustomRules) > 0 {
		engine, err := waf.NewRuleEngine(p.CustomRules)
		if err != nil {
			return fmt.Errorf("waf policy init: %w", err)
		}
		p.ruleEngine = engine
	}
	return nil
}

// Apply returns an http.Handler that evaluates incoming requests against the
// WAF rule set. The open-source stub passes all requests through when the
// policy is disabled or in test mode. When enabled with custom rules, it
// performs basic regex matching against REQUEST_URI for "block" actions.
func (p *WAFPolicyConfig) Apply(next http.Handler) http.Handler {
	if p.Disabled {
		return next
	}
	if p.TestMode {
		// Test mode: log but do not block.
		return next
	}

	ruleEngine := p.ruleEngine

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ruleEngine != nil {
			results, err := ruleEngine.EvaluateRequest(context.Background(), r)
			if err == nil {
				for _, res := range results {
					if res.Matched {
						http.Error(w, "Forbidden", http.StatusForbidden)
						return
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

