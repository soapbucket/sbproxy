// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package reqctx

import (
	"fmt"
	"net/url"
	"strings"
)

// Settings represents configuration settings for storage and caching backends
type Settings struct {
	Driver string            `json:"driver"`
	DSN    string            `json:"dsn"`
	Path   string            `json:"path"` // File path for file-based backends
	Params map[string]string `json:"params"`
}

// NewSettingsFromDSN parses a DSN string and creates a Settings instance
// DSN format: driver://[host[:port]]/[database][?param1=value1&param2=value2]
func NewSettingsFromDSN(dsn string) (*Settings, error) {
	if dsn == "" {
		return nil, fmt.Errorf("empty DSN")
	}

	// Parse the URL
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DSN: %w", err)
	}

	settings := &Settings{
		Driver: u.Scheme,
		DSN:    dsn,
		Params: make(map[string]string),
	}

	// Parse query parameters
	for key, values := range u.Query() {
		if len(values) > 0 {
			settings.Params[key] = values[0]
		}
	}

	// Handle special cases
	if u.Host != "" {
		settings.Params["host"] = u.Host
	}
	if u.Path != "" && u.Path != "/" {
		settings.Path = u.Path
		settings.Params["database"] = strings.TrimPrefix(u.Path, "/")
	}
	if u.User != nil {
		if username := u.User.Username(); username != "" {
			settings.Params["username"] = username
		}
		if password, ok := u.User.Password(); ok {
			settings.Params["password"] = password
		}
	}

	return settings, nil
}
