// Package forward defines forwarding rules that control how requests are routed to upstream targets.
package forward

import (
	"encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/middleware/rule"
)

// ForwardRule represents a forward rule.
type ForwardRule struct {
	Hostname string          `json:"hostname"`
	Origin   json.RawMessage `json:"origin,omitempty"`

	Rules rule.RequestRules `json:"rules,omitempty"`
}

// Match performs the match operation on the ForwardRule.
func (f ForwardRule) Match(req *http.Request) bool {
	if len(f.Rules) == 0 {
		return true
	}
	return f.Rules.Match(req)
}

// ForwardRules is a slice type for forward rules.
type ForwardRules []ForwardRule

// ApplyRule performs the apply rule operation on the ForwardRules.
func (f ForwardRules) ApplyRule(req *http.Request) *ForwardRule {
	for i := range f {
		if f[i].Match(req) {
			return &f[i]
		}
	}
	return nil
}

// Apply performs the apply operation on the ForwardRules.
func (f ForwardRules) Apply(req *http.Request) string {
	rule := f.ApplyRule(req)
	if rule != nil {
		return rule.Hostname
	}
	return ""
}
