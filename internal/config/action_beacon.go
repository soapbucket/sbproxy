// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"net/http"
)

func init() {
	loaderFns[TypeBeacon] = LoadBeaconConfig
}

var _ ActionConfig = (*BeaconActionConfig)(nil)

// BeaconActionConfig holds configuration for beacon action.
type BeaconActionConfig struct {
	BeaconConfig
}

// LoadBeaconConfig performs the load beacon config operation.
func LoadBeaconConfig(data []byte) (ActionConfig, error) {
	cfg := &BeaconActionConfig{}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// If EmptyGIF is true, set the body to a 1x1 transparent GIF
	if cfg.EmptyGIF {
		if cfg.BodyBase64 == "" {
			cfg.BodyBase64 = EmptyGIF1x1
		}
		if cfg.ContentType == "" {
			cfg.ContentType = "image/gif"
		}
		if cfg.StatusCode == 0 {
			cfg.StatusCode = http.StatusOK
		}
	}

	cfg.tr = http.RoundTripper(StaticTransportFn(&cfg.StaticConfig))

	return cfg, nil
}
