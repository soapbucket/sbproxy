// failure_policy.go defines fail-open vs fail-closed behavior for AI
// gateway subsystems.
//
// The default policy is fail-open because rejecting all requests on a
// transient error is worse than briefly degraded enforcement. However,
// safety-critical subsystems (budget, guardrails, lua_hooks) default to
// fail-closed via [DefaultFailurePolicy] because allowing unbudgeted
// spend or unguarded content is a harder failure to recover from.
//
// Per-subsystem overrides allow fine-grained control. For example, an
// operator might set rate limiting to fail-closed in a high-security
// environment while keeping logging at fail-open.
package limits

import "log/slog"

// FailureMode determines behavior when a subsystem encounters an error.
type FailureMode string

const (
	FailOpen   FailureMode = "open"
	FailClosed FailureMode = "closed"
)

// FailurePolicy controls per-subsystem failure behavior.
type FailurePolicy struct {
	Default   FailureMode            `json:"failure_mode"`
	Overrides map[string]FailureMode `json:"failure_overrides,omitempty"`
}

// ShouldAllow returns true if the request should proceed despite a subsystem error.
// Logs the decision at appropriate level.
func (p *FailurePolicy) ShouldAllow(subsystem string, err error) bool {
	mode := p.modeFor(subsystem)
	if mode == FailOpen {
		slog.Warn("subsystem error, failing open",
			"subsystem", subsystem,
			"error", err,
		)
		return true
	}
	slog.Error("subsystem error, failing closed",
		"subsystem", subsystem,
		"error", err,
	)
	return false
}

// modeFor returns the failure mode for a subsystem, checking overrides first.
func (p *FailurePolicy) modeFor(subsystem string) FailureMode {
	if p == nil {
		return FailOpen // Default when no policy configured
	}
	if override, ok := p.Overrides[subsystem]; ok {
		return override
	}
	if p.Default == "" {
		return FailOpen
	}
	return p.Default
}

// DefaultFailurePolicy returns a sensible default policy.
func DefaultFailurePolicy() *FailurePolicy {
	return &FailurePolicy{
		Default: FailOpen,
		Overrides: map[string]FailureMode{
			"budget":     FailClosed,
			"guardrails": FailClosed,
			"lua_hooks":  FailClosed,
		},
	}
}
