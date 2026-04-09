// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"
)

func init() {
	policyLoaderFns[PolicyTypeFaultInjection] = NewFaultInjectionPolicy
}

// FaultInjectionPolicyConfig implements PolicyConfig for fault injection.
type FaultInjectionPolicyConfig struct {
	FaultInjectionPolicy
	config *Config
}

// NewFaultInjectionPolicy creates a new fault injection policy config.
func NewFaultInjectionPolicy(data []byte) (PolicyConfig, error) {
	cfg := &FaultInjectionPolicyConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Init initializes the policy config.
func (p *FaultInjectionPolicyConfig) Init(config *Config) error {
	p.config = config
	return nil
}

// Apply implements the middleware pattern for fault injection.
func (p *FaultInjectionPolicyConfig) Apply(next http.Handler) http.Handler {
	if p.Disabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If activation header is configured, only inject when present
		if p.ActivationHeader != "" && r.Header.Get(p.ActivationHeader) == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check abort first (no point delaying if we are going to abort)
		if p.Abort != nil && p.Abort.Percentage > 0 {
			if rand.Float64()*100 < p.Abort.Percentage {
				slog.Debug("fault injection: aborting request",
					"status", p.Abort.StatusCode,
					"percentage", p.Abort.Percentage)
				w.WriteHeader(p.Abort.StatusCode)
				if p.Abort.Body != "" {
					w.Write([]byte(p.Abort.Body))
				}
				return
			}
		}

		// Check delay
		if p.Delay != nil && p.Delay.Duration.Duration > 0 && p.Delay.Percentage > 0 {
			if rand.Float64()*100 < p.Delay.Percentage {
				slog.Debug("fault injection: delaying request",
					"duration", p.Delay.Duration.Duration,
					"percentage", p.Delay.Percentage)
				timer := time.NewTimer(p.Delay.Duration.Duration)
				select {
				case <-timer.C:
				case <-r.Context().Done():
					timer.Stop()
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}
