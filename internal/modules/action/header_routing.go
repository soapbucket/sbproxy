// Package action contains action-level traffic management handlers.
package action

import (
	"net/http"
	"regexp"
)

// HeaderRouteConfig configures header-based routing rules.
type HeaderRouteConfig struct {
	Rules []HeaderRouteRule `json:"rules" yaml:"rules"`
}

// HeaderRouteRule matches a header value to an upstream.
type HeaderRouteRule struct {
	Header   string `json:"header" yaml:"header"`
	Value    string `json:"value,omitempty" yaml:"value"`       // exact match
	Pattern  string `json:"pattern,omitempty" yaml:"pattern"`   // regex match
	Upstream string `json:"upstream" yaml:"upstream"`           // target URL

	compiled *regexp.Regexp // lazily compiled regex
}

// MatchHeaderRoute finds the first matching rule for the request.
// It checks each rule in order and returns the upstream URL and true on the first match.
// If no rule matches, it returns ("", false).
func MatchHeaderRoute(r *http.Request, rules []HeaderRouteRule) (string, bool) {
	for i := range rules {
		rule := &rules[i]
		hv := r.Header.Get(rule.Header)
		if hv == "" {
			continue
		}

		// Exact match takes priority.
		if rule.Value != "" {
			if hv == rule.Value {
				return rule.Upstream, true
			}
			continue
		}

		// Regex match.
		if rule.Pattern != "" {
			re := rule.compiled
			if re == nil {
				var err error
				re, err = regexp.Compile(rule.Pattern)
				if err != nil {
					continue
				}
				rule.compiled = re
			}
			if re.MatchString(hv) {
				return rule.Upstream, true
			}
		}
	}

	return "", false
}
