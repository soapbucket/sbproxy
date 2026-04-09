// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"net/http"
)

var (
	// policyLoaderFns holds the policy config loader functions
	policyLoaderFns = make(map[string]PolicyConfigConstructorFn)
)

// PolicyConfig defines the interface for policy config operations.
type PolicyConfig interface {
	GetType() string
	Init(*Config) error

	// Apply wraps an http.Handler with policy enforcement
	// Returns a new handler that checks the policy before calling next
	Apply(http.Handler) http.Handler
}

type basePolicyAccessor interface {
	BasePolicyPtr() *BasePolicy
}

func policySupportsMessagePhase(policy PolicyConfig) bool {
	_, ok := policy.(MessagePolicyConfig)
	return ok
}

// GetType returns the policy type
func (b *BasePolicy) GetType() string {
	return b.PolicyType
}

// Init is a no-op base implementation
func (b *BasePolicy) Init(config *Config) error {
	return nil
}

// Apply is a no-op base implementation that just passes through to next
func (b *BasePolicy) Apply(next http.Handler) http.Handler {
	return next
}

// BasePolicyPtr performs the base policy ptr operation on the BasePolicy.
func (b *BasePolicy) BasePolicyPtr() *BasePolicy {
	return b
}

// PolicyConfigConstructorFn is a function type for policy config constructor fn callbacks.
type PolicyConfigConstructorFn func([]byte) (PolicyConfig, error)

// LoadPolicyConfig performs the load policy config operation.
// LoadPolicyConfig loads and creates a policy config from JSON data.
// It uses the global Registry if set, otherwise falls back to legacy init() maps.
func LoadPolicyConfig(data []byte) (PolicyConfig, error) {
	if r := globalRegistry; r != nil {
		return r.LoadPolicy(data)
	}
	// First, extract the type
	var typeExtractor struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &typeExtractor); err != nil {
		return nil, fmt.Errorf("failed to extract policy type: %w", err)
	}

	if typeExtractor.Type == "" {
		return nil, fmt.Errorf("policy type is required")
	}

	// Find the loader function
	loaderFn, ok := policyLoaderFns[typeExtractor.Type]
	if !ok {
		return nil, fmt.Errorf("unknown policy type: %s", typeExtractor.Type)
	}

	// Load the specific config
	return loaderFn(data)
}

// UnmarshalJSON implements json.Unmarshaler for Policy
func (s *Policy) UnmarshalJSON(data []byte) error {
	// Store the raw JSON
	*s = Policy(data)
	return nil
}

// MarshalJSON implements json.Marshaler for Policy
func (s Policy) MarshalJSON() ([]byte, error) {
	return []byte(s), nil
}
