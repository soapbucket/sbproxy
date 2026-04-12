// config.go defines system-level cache configuration limits for origin caches.
package origincache

import "time"

// CacheSystemConfig defines system-level cache limits configured in sb.yml.
type CacheSystemConfig struct {
	EncryptionKey      string        `yaml:"encryption_key" json:"encryption_key"`
	MaxSizePerOriginMB int           `yaml:"max_size_per_origin_mb" json:"max_size_per_origin_mb"`
	MaxTotalMB         int           `yaml:"max_total_mb" json:"max_total_mb"`
	DefaultTTL         time.Duration `yaml:"default_ttl" json:"default_ttl"`
	MaxTTL             time.Duration `yaml:"max_ttl" json:"max_ttl"`
	MaxKeySizeBytes    int           `yaml:"max_key_size_bytes" json:"max_key_size_bytes"`
	MaxValueSizeBytes  int           `yaml:"max_value_size_bytes" json:"max_value_size_bytes"`
}

func (c CacheSystemConfig) withDefaults() CacheSystemConfig {
	if c.MaxSizePerOriginMB <= 0 {
		c.MaxSizePerOriginMB = 64
	}
	if c.MaxTotalMB <= 0 {
		c.MaxTotalMB = 2048
	}
	if c.DefaultTTL <= 0 {
		c.DefaultTTL = 5 * time.Minute
	}
	if c.MaxTTL <= 0 {
		c.MaxTTL = time.Hour
	}
	if c.MaxKeySizeBytes <= 0 {
		c.MaxKeySizeBytes = 1024
	}
	if c.MaxValueSizeBytes <= 0 {
		c.MaxValueSizeBytes = 1048576 // 1MB
	}
	return c
}
