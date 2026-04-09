// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ContractGovernanceConfig represents the top-level contract_governance field.
// This is a convenience alias — the same config can be used via the policies array
// with type "contract_governance".
type ContractGovernanceConfig struct {
	SpecFrom  string `json:"spec_from,omitempty"`
	SpecKey   string `json:"spec_key,omitempty"`
	SpecStore string `json:"spec_store,omitempty"`

	ValidateRequests  bool   `json:"validate_requests"`
	ValidateResponses bool   `json:"validate_responses,omitempty"`
	Enforcement       string `json:"enforcement,omitempty"`
	SampleRate        float64 `json:"sample_rate,omitempty"`

	RefreshInterval reqctx.Duration `json:"refresh_interval,omitempty"`

	RequestEnforcement  string `json:"request_enforcement,omitempty"`
	ResponseEnforcement string `json:"response_enforcement,omitempty"`
}
