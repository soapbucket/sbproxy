// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func init() {
	loaderFns[TypeStatic] = LoadStaticConfig
}

// StaticTypedConfig represents the static content configuration
type StaticTypedConfig struct {
	StaticConfig
}

// LoadStaticConfig loads a static content configuration
func LoadStaticConfig(data []byte) (ActionConfig, error) {
	slog.Debug("loading static config")

	cfg := new(StaticTypedConfig)
	if err := json.Unmarshal(data, &cfg); err != nil {
		slog.Error("failed to unmarshal static config", "error", err)
		return nil, err
	}

	cfg.tr = http.RoundTripper(StaticTransportFn(&cfg.StaticConfig))

	slog.Debug("static config loaded", "status_code", cfg.StatusCode)
	return cfg, nil
}
