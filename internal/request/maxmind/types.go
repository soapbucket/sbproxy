// Package maxmind integrates MaxMind GeoIP databases for geographic request metadata.
package maxmind

import (
	"fmt"
	"io"
	"net"
	"time"
)

// Manager defines the interface for manager operations.
type Manager interface {
	Lookup(net.IP) (*Result, error)

	Driver() string
	io.Closer
}

// IPInfoResult represents IP information from the IPInfo database
type Result struct {
	Country       string `json:"country"`
	CountryCode   string `json:"country_code"`
	Continent     string `json:"continent"`
	ContinentCode string `json:"continent_code"`
	ASN           string `json:"asn"`
	ASName        string `json:"as_name"`
	ASDomain      string `json:"as_domain"`
}

// String returns a human-readable representation of the Result.
func (r *Result) String() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("country=%s,asn=%s,as_name=%s", r.CountryCode, r.ASN, r.ASName)
}

// Settings holds configuration parameters for this component.
type Settings struct {
	Driver string            `json:"driver" yaml:"driver" mapstructure:"driver"`
	Params map[string]string `json:"params" yaml:"params" mapstructure:"params"`

	// Observability flags
	EnableMetrics bool          `json:"enable_metrics,omitempty" yaml:"enable_metrics" mapstructure:"enable_metrics"`
	EnableTracing bool          `json:"enable_tracing,omitempty" yaml:"enable_tracing" mapstructure:"enable_tracing"`
	EnableCaching bool          `json:"enable_caching,omitempty" yaml:"enable_caching" mapstructure:"enable_caching"`
	CacheDuration time.Duration `json:"cache_duration,omitempty" yaml:"cache_duration" mapstructure:"cache_duration"`
}
