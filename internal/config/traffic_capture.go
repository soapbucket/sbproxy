// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

const (
	// DefaultCaptureMaxBodySize is the default maximum body size to capture (10KB).
	DefaultCaptureMaxBodySize = 10 * 1024

	// DefaultCaptureRetention is the default retention period for captured exchanges.
	DefaultCaptureRetention = 24 * time.Hour

	// DefaultCaptureMaxCount is the default maximum number of exchanges per site.
	DefaultCaptureMaxCount = 100000

	// DefaultCaptureSampleRate is the default capture sample rate (100%).
	DefaultCaptureSampleRate = 1.0

	// DefaultCaptureBufferSize is the default channel buffer size for non-blocking writes.
	DefaultCaptureBufferSize = 4096
)

// ParsedTrafficCaptureConfig holds parsed values from reqctx.TrafficCaptureConfig.
type ParsedTrafficCaptureConfig struct {
	Enabled     bool
	SampleRate  float64
	Filter      string
	MaxBodySize int64
	Retention   time.Duration
	MaxCount    int
}

// ParseTrafficCaptureConfig parses a reqctx.TrafficCaptureConfig into usable values.
func ParseTrafficCaptureConfig(cfg *reqctx.TrafficCaptureConfig) ParsedTrafficCaptureConfig {
	if cfg == nil {
		return ParsedTrafficCaptureConfig{}
	}

	parsed := ParsedTrafficCaptureConfig{
		Enabled:     cfg.Enabled,
		SampleRate:  cfg.SampleRate,
		Filter:      cfg.Filter,
		MaxBodySize: parseSizeToInt64(cfg.MaxBodySize, DefaultCaptureMaxBodySize),
		MaxCount:    cfg.MaxCount,
	}

	// Default sample rate: only apply default if not explicitly set
	// A SampleRate of 0.0 means no JSON field was set (Go zero value), so use default.
	// To explicitly set 0%, disable capture instead.
	if parsed.SampleRate == 0 {
		parsed.SampleRate = DefaultCaptureSampleRate
	}
	if parsed.SampleRate > 1.0 {
		parsed.SampleRate = 1.0
	}
	if parsed.SampleRate < 0 {
		parsed.SampleRate = 0
	}

	// Default max count
	if parsed.MaxCount <= 0 {
		parsed.MaxCount = DefaultCaptureMaxCount
	}

	// Parse retention duration
	if cfg.Retention != "" {
		expanded := expandDurationDays(cfg.Retention)
		if d, err := time.ParseDuration(expanded); err == nil {
			parsed.Retention = d
		} else {
			parsed.Retention = DefaultCaptureRetention
		}
	} else {
		parsed.Retention = DefaultCaptureRetention
	}

	return parsed
}

// expandDurationDays expands "d" suffix in duration strings (e.g., "7d" -> "168h").
func expandDurationDays(s string) string {
	// Reuse the pattern from models/duration.go
	return reqctx.ExpandDays(s)
}
