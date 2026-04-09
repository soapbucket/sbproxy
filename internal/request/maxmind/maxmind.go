// Package maxmind integrates MaxMind GeoIP databases for geographic request metadata.
//
// The maxmind driver requires the enterprise build. In the core build, configuring
// driver: "maxmind" will return ErrNotAvailable.
package maxmind

import "fmt"

// ErrNotAvailable is returned when the maxmind driver is configured but the
// enterprise dependency is not compiled in.
var ErrNotAvailable = fmt.Errorf("maxmind: driver not available in core build (requires enterprise dependency)")

func init() {
	Register(DriverMaxMind, func(s Settings) (Manager, error) {
		return nil, ErrNotAvailable
	})
}
