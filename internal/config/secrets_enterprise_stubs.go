// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"fmt"
	"time"
)

// AWSSecretsConfig is a stub for the enterprise AWS Secrets Manager provider.
// In the open-source build this type exists only to satisfy type assertions;
// the actual implementation lives in the enterprise module.
type AWSSecretsConfig struct {
	BaseSecretsConfig
}

// Load is a no-op stub; enterprise builds replace this.
func (a *AWSSecretsConfig) Load(_ context.Context) (map[string]string, error) {
	return nil, fmt.Errorf("aws secrets provider is an enterprise feature")
}

// SetCacheDuration sets the cache duration on the base config.
func (a *AWSSecretsConfig) SetCacheDuration(d time.Duration) {
	a.CacheDuration = d
}

// GCPSecretsConfig is a stub for the enterprise GCP Secret Manager provider.
type GCPSecretsConfig struct {
	BaseSecretsConfig
}

// Load is a no-op stub; enterprise builds replace this.
func (g *GCPSecretsConfig) Load(_ context.Context) (map[string]string, error) {
	return nil, fmt.Errorf("gcp secrets provider is an enterprise feature")
}

// SetCacheDuration sets the cache duration on the base config.
func (g *GCPSecretsConfig) SetCacheDuration(d time.Duration) {
	g.CacheDuration = d
}

// CallbackSecretsConfig is a stub for the enterprise callback-based secrets provider.
type CallbackSecretsConfig struct {
	BaseSecretsConfig
}

// Load is a no-op stub; enterprise builds replace this.
func (c *CallbackSecretsConfig) Load(_ context.Context) (map[string]string, error) {
	return nil, fmt.Errorf("callback secrets provider is an enterprise feature")
}

// SetCacheDuration sets the cache duration on the base config.
func (c *CallbackSecretsConfig) SetCacheDuration(d time.Duration) {
	c.CacheDuration = d
}
