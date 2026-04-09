// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import "time"

// OutputConfig defines a log output destination.
type OutputConfig struct {
	Type       string               `mapstructure:"type" json:"type"`               // "stderr" | "clickhouse"
	ClickHouse *ClickHouseOutputConfig `mapstructure:"clickhouse" json:"clickhouse,omitempty"`
}

// ClickHouseOutputConfig configures direct ClickHouse HTTP ingestion.
type ClickHouseOutputConfig struct {
	Host          string        `mapstructure:"host" json:"host"`
	Database      string        `mapstructure:"database" json:"database"`
	Table         string        `mapstructure:"table" json:"table"`
	BatchSize     int           `mapstructure:"batch_size" json:"batch_size"`
	MaxBatchBytes int64         `mapstructure:"max_batch_bytes" json:"max_batch_bytes"`
	FlushInterval time.Duration `mapstructure:"flush_interval" json:"flush_interval"`
	Timeout       time.Duration `mapstructure:"timeout" json:"timeout"`
	AsyncInsert   bool          `mapstructure:"async_insert" json:"async_insert"`
}

// FieldsConfig controls which optional field groups are included in request logs.
type FieldsConfig struct {
	Timestamps      bool `mapstructure:"timestamps" json:"timestamps"`
	Headers         bool `mapstructure:"headers" json:"headers"`
	ForwardedHeaders bool `mapstructure:"forwarded_headers" json:"forwarded_headers"`
	QueryString     bool `mapstructure:"query_string" json:"query_string"`
	Cookies         bool `mapstructure:"cookies" json:"cookies"`
	Fingerprint     bool `mapstructure:"fingerprint" json:"fingerprint"`
	OriginalRequest bool `mapstructure:"original_request" json:"original_request"`
	CacheInfo       bool `mapstructure:"cache_info" json:"cache_info"`
	AuthInfo        bool `mapstructure:"auth_info" json:"auth_info"`
	AppVersion      bool `mapstructure:"app_version" json:"app_version"`
	Location        bool `mapstructure:"location" json:"location"`
}

// SamplingConfig controls request log sampling.
type SamplingConfig struct {
	Enabled bool `mapstructure:"enabled" json:"enabled"`
	Rate    int  `mapstructure:"rate" json:"rate"` // Log 1 in N requests (errors always logged)
}

// RequestLoggingConfig configures the request logger.
type RequestLoggingConfig struct {
	Enabled              bool           `mapstructure:"enabled" json:"enabled"`
	Level                string         `mapstructure:"level" json:"level"`
	Outputs              []OutputConfig `mapstructure:"outputs" json:"outputs"`
	Fields               FieldsConfig   `mapstructure:"fields" json:"fields"`
	Sampling             SamplingConfig `mapstructure:"sampling" json:"sampling"`
	SlowRequestThreshold time.Duration  `mapstructure:"slow_request_threshold" json:"slow_request_threshold"`
	ErrorDetailLevel     string         `mapstructure:"error_detail_level" json:"error_detail_level"`
}

// ApplicationLoggingConfig configures the application logger.
type ApplicationLoggingConfig struct {
	Level   string         `mapstructure:"level" json:"level"`
	Outputs []OutputConfig `mapstructure:"outputs" json:"outputs"`
}

// SecurityLoggingConfig configures the security logger.
type SecurityLoggingConfig struct {
	Level   string         `mapstructure:"level" json:"level"`
	Outputs []OutputConfig `mapstructure:"outputs" json:"outputs"`
}

// DefaultRequestLoggingConfig returns the default request logging configuration.
func DefaultRequestLoggingConfig() RequestLoggingConfig {
	return RequestLoggingConfig{
		Enabled: true,
		Level:   "info",
		Outputs: []OutputConfig{{Type: "stderr"}},
		Fields: FieldsConfig{
			Timestamps:       true,
			Headers:          false,
			ForwardedHeaders: true,
			QueryString:      true,
			Cookies:          false,
			Fingerprint:      true,
			OriginalRequest:  false,
			CacheInfo:        true,
			AuthInfo:         true,
			AppVersion:       false,
			Location:         false,
		},
		Sampling:             SamplingConfig{Enabled: false, Rate: 100},
		SlowRequestThreshold: 5 * time.Second,
		ErrorDetailLevel:     "standard",
	}
}

// DefaultApplicationLoggingConfig returns the default application logging configuration.
func DefaultApplicationLoggingConfig() ApplicationLoggingConfig {
	return ApplicationLoggingConfig{
		Level:   "info",
		Outputs: []OutputConfig{{Type: "stderr"}},
	}
}

// DefaultSecurityLoggingConfig returns the default security logging configuration.
func DefaultSecurityLoggingConfig() SecurityLoggingConfig {
	return SecurityLoggingConfig{
		Level:   "info",
		Outputs: []OutputConfig{{Type: "stderr"}},
	}
}
