// Package geoip provides GeoIP database integration for geographic request metadata.
//
// The geoip driver requires an MMDB database file provided via the
// geoip.params.path config option. Configuring driver: "geoip" without
// a database path will return ErrNotAvailable.
package geoip

import "fmt"

// ErrNotAvailable is returned when the geoip driver is configured but
// no database has been loaded.
var ErrNotAvailable = fmt.Errorf("geoip: driver not available (no database compiled in; provide a path via geoip.params.path)")

func init() {
	Register(DriverGeoIP, func(s Settings) (Manager, error) {
		return nil, ErrNotAvailable
	})
}
