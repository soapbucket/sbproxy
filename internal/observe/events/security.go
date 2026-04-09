// Package events implements a publish-subscribe event bus for system observability and inter-component communication.
package events

// SecurityAuthFailure fires when authentication fails
type SecurityAuthFailure struct {
	EventBase
	IP       string `json:"ip"`
	Path     string `json:"path"`
	AuthType string `json:"auth_type"`
	Reason   string `json:"reason"`
}

// SecurityRateLimited fires when a request is throttled
type SecurityRateLimited struct {
	EventBase
	IP         string `json:"ip"`
	Path       string `json:"path"`
	PolicyName string `json:"policy_name"`
	Limit      int    `json:"limit"`
	Window     string `json:"window"`
}

// SecurityWAFBlocked fires when a WAF rule blocks a request
type SecurityWAFBlocked struct {
	EventBase
	IP       string `json:"ip"`
	Path     string `json:"path"`
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Category string `json:"category"`
}

// SecurityPIIDetected fires when PII is detected in content
type SecurityPIIDetected struct {
	EventBase
	IP       string   `json:"ip"`
	Path     string   `json:"path"`
	Entities []string `json:"entities"`
}
