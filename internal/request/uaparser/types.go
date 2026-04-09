// Package uaparser parses User-Agent strings to extract browser, OS, and device information.
package uaparser

import (
	"fmt"
	"io"
	"time"

	"github.com/ua-parser/uap-go/uaparser"
)

// Manager defines the interface for manager operations.
type Manager interface {
	Parse(userAgent string) (*Result, error)

	Driver() string

	io.Closer
}

// Result represents parsed user agent information
type Result struct {
	UserAgent *uaparser.UserAgent `json:"user_agent"`
	OS        *uaparser.Os        `json:"os"`
	Device    *uaparser.Device    `json:"device"`
}

// String returns a human-readable representation of the Result.
func (r *Result) String() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("user_agent=%s,os=%s,device=%s", r.UserAgent, r.OS, r.Device)
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
