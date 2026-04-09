// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"log/slog"
)

// SetupCookieJar configures cookie jar support for this config
// This should be called after config is loaded to avoid import cycles
func (c *Config) SetupCookieJar(cookieJarFn CookieJarFn) {
	if cookieJarFn == nil {
		return
	}
	
	c.CookieJarFn = cookieJarFn
	
	// Wrap action transport with cookie jar transport if action is a proxy
	if c.action != nil && c.action.IsProxy() {
		c.wrapActionTransportWithCookieJar()
	}
	
	slog.Info("session cookie jar configured",
		"config_id", c.ID,
		"hostname", c.Hostname)
}

