// Package geoip provides GeoIP database integration for geographic request metadata.
package geoip

import "time"

const (
	// DriverNoop is a constant for driver noop.
	DriverNoop  = "noop"
	// DriverGeoIP is a constant for the geoip driver.
	DriverGeoIP = "geoip"

	// ParamPath is a constant for param path.
	ParamPath = "path"

	// DefaultCacheDuration is the default value for cache duration.
	DefaultCacheDuration = 5 * time.Minute
)
