// Package maxmind integrates MaxMind GeoIP databases for geographic request metadata.
package maxmind

import "time"

const (
	// DriverNoop is a constant for driver noop.
	DriverNoop    = "noop"
	// DriverMaxMind is a constant for driver max mind.
	DriverMaxMind = "maxmind"

	// ParamPath is a constant for param path.
	ParamPath = "path"

	// DefaultCacheDuration is the default value for cache duration.
	DefaultCacheDuration = 5 * time.Minute
)
