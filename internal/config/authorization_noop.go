// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

func init() {
	authLoaderFuns[AuthTypeNone] = NewNoopSecurityConfig
	authLoaderFuns[AuthTypeNoop] = NewNoopSecurityConfig
}

// NoopAuthConfig is a variable for noop auth config.
var NoopAuthConfig = &noopSecurityConfig{
	BaseAuthConfig: BaseAuthConfig{
		AuthType: AuthTypeNoop,
	},
}

type noopSecurityConfig struct {
	BaseAuthConfig
}

// NewNoopSecurityConfig creates and initializes a new NoopSecurityConfig.
func NewNoopSecurityConfig([]byte) (AuthConfig, error) {
	return NoopAuthConfig, nil
}
