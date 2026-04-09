// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

func init() {
	policyLoaderFns[PolicyTypeGeoBlocking] = NewGeoBlockingPolicy
}

// GeoBlockingPolicyConfig implements PolicyConfig for geo-blocking
type GeoBlockingPolicyConfig struct {
	GeoBlockingPolicy

	// Internal
	config           *Config
	allowedCountries map[string]bool
	blockedCountries map[string]bool
}

// NewGeoBlockingPolicy creates a new geo-blocking policy config
func NewGeoBlockingPolicy(data []byte) (PolicyConfig, error) {
	cfg := &GeoBlockingPolicyConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Set defaults
	if cfg.Action == "" {
		cfg.Action = "block"
	}

	// Build country maps (case-insensitive)
	cfg.allowedCountries = make(map[string]bool, len(cfg.AllowedCountries))
	for _, country := range cfg.AllowedCountries {
		cfg.allowedCountries[strings.ToUpper(country)] = true
	}

	cfg.blockedCountries = make(map[string]bool, len(cfg.BlockedCountries))
	for _, country := range cfg.BlockedCountries {
		cfg.blockedCountries[strings.ToUpper(country)] = true
	}

	// Validate configuration
	if len(cfg.allowedCountries) > 0 && len(cfg.blockedCountries) > 0 {
		return nil, fmt.Errorf("geo-blocking policy cannot have both allowed and blocked countries")
	}

	return cfg, nil
}

// Init initializes the policy config
func (p *GeoBlockingPolicyConfig) Init(config *Config) error {
	p.config = config
	return nil
}

// Apply implements the middleware pattern for geo-blocking
func (p *GeoBlockingPolicyConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		// Get location data from request context
		requestData := reqctx.GetRequestData(r.Context())
		if requestData == nil || requestData.Location == nil {
			// If location data is not available, allow request (fail open)
			// In production, you might want to fail closed instead
			next.ServeHTTP(w, r)
			return
		}

		countryCode := strings.ToUpper(requestData.Location.CountryCode)
		if countryCode == "" {
			// No country code available, allow request
			next.ServeHTTP(w, r)
			return
		}

		// Check if country should be blocked/allowed
		shouldBlock := false

		// Check allowed countries (whitelist)
		if len(p.allowedCountries) > 0 {
			if !p.allowedCountries[countryCode] {
				shouldBlock = true
			}
		}

		// Check blocked countries (blacklist)
		if len(p.blockedCountries) > 0 {
			if p.blockedCountries[countryCode] {
				shouldBlock = true
			}
		}

		// Handle blocking/allowing
		if shouldBlock {
			// Record geo-blocking violation metric
			origin := "unknown"
			if p.config != nil {
				origin = p.config.ID
			}
			ipAddress := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ipAddress = strings.Split(forwarded, ",")[0]
			}
			metric.GeoBlockViolation(origin, countryCode, ipAddress)
			p.handleBlock(w, r, countryCode)
			return
		}

		// All checks passed, continue to next handler
		next.ServeHTTP(w, r)
	})
}

// handleBlock handles blocking based on action type
func (p *GeoBlockingPolicyConfig) handleBlock(w http.ResponseWriter, r *http.Request, countryCode string) {
	switch strings.ToLower(p.Action) {
	case "redirect":
		if p.RedirectURL != "" {
			http.Redirect(w, r, p.RedirectURL, http.StatusFound)
			return
		}
		// Fall through to block if redirect URL not set
		fallthrough
	case "block":
		reqctx.RecordPolicyViolation(r.Context(), "geo_block", fmt.Sprintf("Access denied for country: %s", countryCode))
		http.Error(w, fmt.Sprintf("Access denied for country: %s", countryCode), http.StatusForbidden)
		return
	case "log":
		// Log but allow request
		// In a real implementation, you'd log this event
		// For now, we'll just allow the request
		return
	default:
		reqctx.RecordPolicyViolation(r.Context(), "geo_block", fmt.Sprintf("Access denied for country: %s", countryCode))
		http.Error(w, fmt.Sprintf("Access denied for country: %s", countryCode), http.StatusForbidden)
		return
	}
}

