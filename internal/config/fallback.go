// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/config/rule"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// FallbackOrigin configures an alternative origin that activates when the
// primary origin encounters specified error conditions.
type FallbackOrigin struct {
	Hostname       string            `json:"hostname"`
	Origin         json.RawMessage   `json:"origin,omitempty"`
	OnError        bool              `json:"on_error,omitempty"`
	OnTimeout      bool              `json:"on_timeout,omitempty"`
	OnStatus       []int             `json:"on_status,omitempty"`
	Timeout        reqctx.Duration   `json:"timeout,omitempty"`
	Rules          rule.RequestRules `json:"rules,omitempty"`
	MaxDepth       int               `json:"max_depth,omitempty"`
	AddDebugHeader bool              `json:"add_debug_header,omitempty"`
}

// ShouldTriggerOnError returns true if the fallback should activate for
// the given transport-level error. It checks both on_error and on_timeout
// conditions based on the error string patterns.
func (f *FallbackOrigin) ShouldTriggerOnError(err error) bool {
	if f == nil || err == nil {
		return false
	}
	errStr := err.Error()

	if f.OnTimeout {
		if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
			return true
		}
	}

	if f.OnError {
		// Match the same error classifications as ErrorHandler in config_proxy.go
		if strings.Contains(errStr, "connection") ||
			strings.Contains(errStr, "refused") ||
			strings.Contains(errStr, "certificate") ||
			strings.Contains(errStr, "TLS") ||
			strings.Contains(errStr, "unhealthy") ||
			strings.Contains(errStr, "reset") ||
			strings.Contains(errStr, "broken pipe") ||
			strings.Contains(errStr, "DNS") {
			return true
		}
	}

	return false
}

// ShouldTriggerOnStatus returns true if the fallback should activate for
// the given upstream response status code.
func (f *FallbackOrigin) ShouldTriggerOnStatus(statusCode int) bool {
	if f == nil {
		return false
	}
	for _, s := range f.OnStatus {
		if s == statusCode {
			return true
		}
	}
	return false
}

// MatchesRequest returns true if the request is eligible for fallback
// based on the configured rules. If no rules are set, all requests match.
func (f *FallbackOrigin) MatchesRequest(req *http.Request) bool {
	if f == nil {
		return false
	}
	if len(f.Rules) == 0 {
		return true
	}
	return f.Rules.Match(req)
}

// HasEmbeddedOrigin reports whether the FallbackOrigin has embedded origin.
func (f *FallbackOrigin) HasEmbeddedOrigin() bool {
	return f != nil && len(f.Origin) > 0
}
