// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

var authLoaderFuns = map[string]AuthConfigConstructorFn{}

// AuthConfig defines the interface for auth config operations.
type AuthConfig interface {
	GetType() string
	Init(*Config) error
	Authenticate(http.Handler) http.Handler
}

var _ AuthConfig = (*BaseAuthConfig)(nil)

// GetType returns the type for the BaseAuthConfig.
func (s *BaseAuthConfig) GetType() string {
	return s.AuthType
}

// Init performs the init operation on the BaseAuthConfig.
func (b *BaseAuthConfig) Init(cfg *Config) error {
	b.cfg = cfg
	return nil
}

// Authenticate performs the authenticate operation on the BaseAuthConfig.
func (s *BaseAuthConfig) Authenticate(next http.Handler) http.Handler {
	if s.handler != nil && !s.Disabled {
		slog.Debug("Authenticating request", "auth_type", s.AuthType)
		return s.handler(next)
	}
	return next
}

// AuthConfigConstructorFn is a function type for auth config constructor fn callbacks.
type AuthConfigConstructorFn func([]byte) (AuthConfig, error)

// LoadAuthConfig performs the load auth config operation.
// LoadAuthConfig loads and creates an auth config from JSON data.
// It uses the global Registry if set, otherwise falls back to legacy init() maps.
func LoadAuthConfig(data []byte) (AuthConfig, error) {
	if r := globalRegistry; r != nil {
		return r.LoadAuth(data)
	}
	var obj BaseAuthConfig
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}

	loaderFn, ok := authLoaderFuns[obj.AuthType]
	if !ok {
		return nil, fmt.Errorf("unknown security type: %s", obj.AuthType)
	}
	return loaderFn(data)
}

// UnmarshalJSON implements json.Unmarshaler for Auth
func (a *Auth) UnmarshalJSON(data []byte) error {
	// Store the raw JSON
	*a = Auth(data)
	return nil
}

// MarshalJSON implements json.Marshaler for Auth
func (a Auth) MarshalJSON() ([]byte, error) {
	return []byte(a), nil
}
