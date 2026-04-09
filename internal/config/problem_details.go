// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"net/http"
)

// ProblemDetail represents an RFC 9457 problem details object.
type ProblemDetail struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// writeProblemDetail writes an RFC 9457 application/problem+json response.
func writeProblemDetail(w http.ResponseWriter, r *http.Request, statusCode int, detail string, cfg *ProblemDetailsConfig) {
	if cfg == nil || !cfg.Enable {
		http.Error(w, detail, statusCode)
		return
	}

	baseURI := cfg.BaseURI
	if baseURI == "" {
		baseURI = "about:blank"
	}

	pd := ProblemDetail{
		Type:     baseURI,
		Title:    http.StatusText(statusCode),
		Status:   statusCode,
		Detail:   detail,
		Instance: r.URL.Path,
	}

	body, err := json.Marshal(pd)
	if err != nil {
		http.Error(w, detail, statusCode)
		return
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(body)
}

// problemTypeForStatus returns the problem type URI for common proxy errors.
func problemTypeForStatus(statusCode int, baseURI string) string {
	if baseURI == "" || baseURI == "about:blank" {
		return "about:blank"
	}

	switch statusCode {
	case http.StatusBadGateway:
		return baseURI + "/bad-gateway"
	case http.StatusGatewayTimeout:
		return baseURI + "/gateway-timeout"
	case http.StatusServiceUnavailable:
		return baseURI + "/service-unavailable"
	case http.StatusMethodNotAllowed:
		return baseURI + "/method-not-allowed"
	case http.StatusTooManyRequests:
		return baseURI + "/rate-limit-exceeded"
	case http.StatusForbidden:
		return baseURI + "/forbidden"
	case http.StatusUnauthorized:
		return baseURI + "/unauthorized"
	case 425: // Too Early
		return baseURI + "/too-early"
	default:
		return baseURI
	}
}
