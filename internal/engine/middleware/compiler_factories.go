// compiler_factories.go registers bot detection and threat protection middleware factories.
package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/config"
)

func init() {
	config.BotDetectionMiddlewareFactory = botDetectionFactory
	config.ThreatProtectionMiddlewareFactory = threatProtectionFactory
}

func botDetectionFactory(cfg json.RawMessage) (func(http.Handler) http.Handler, error) {
	var botCfg BotDetectionConfig
	if err := json.Unmarshal(cfg, &botCfg); err != nil {
		return nil, err
	}
	if !botCfg.Enabled {
		return nil, nil
	}
	return BotDetectionMiddleware(&botCfg), nil
}

func threatProtectionFactory(cfg json.RawMessage) (func(http.Handler) http.Handler, error) {
	var tpCfg ThreatProtectionConfig
	if err := json.Unmarshal(cfg, &tpCfg); err != nil {
		return nil, err
	}
	if !tpCfg.Enabled {
		return nil, nil
	}
	return ThreatProtectionMiddleware(&tpCfg), nil
}
