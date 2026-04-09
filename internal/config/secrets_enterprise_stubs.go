// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"fmt"
	"time"
)

// AWSSecretsConfig is a stub for the AWS Secrets Manager provider.
// This type exists to satisfy type assertions; a full implementation
// can be linked in by providing a Load method via build-time injection.
type AWSSecretsConfig struct {
	BaseSecretsConfig
}

// Load is a no-op stub; not available in this build.
func (a *AWSSecretsConfig) Load(_ context.Context) (map[string]string, error) {
	return nil, fmt.Errorf("aws secrets provider is not available in this build")
}

// SetCacheDuration sets the cache duration on the base config.
func (a *AWSSecretsConfig) SetCacheDuration(d time.Duration) {
	a.CacheDuration = d
}

// GCPSecretsConfig is a stub for the GCP Secret Manager provider.
type GCPSecretsConfig struct {
	BaseSecretsConfig
}

// Load is a no-op stub; not available in this build.
func (g *GCPSecretsConfig) Load(_ context.Context) (map[string]string, error) {
	return nil, fmt.Errorf("gcp secrets provider is not available in this build")
}

// SetCacheDuration sets the cache duration on the base config.
func (g *GCPSecretsConfig) SetCacheDuration(d time.Duration) {
	g.CacheDuration = d
}

// CallbackSecretsConfig is a stub for the callback-based secrets provider.
type CallbackSecretsConfig struct {
	BaseSecretsConfig
}

// Load is a no-op stub; not available in this build.
func (c *CallbackSecretsConfig) Load(_ context.Context) (map[string]string, error) {
	return nil, fmt.Errorf("callback secrets provider is not available in this build")
}

// SetCacheDuration sets the cache duration on the base config.
func (c *CallbackSecretsConfig) SetCacheDuration(d time.Duration) {
	c.CacheDuration = d
}
