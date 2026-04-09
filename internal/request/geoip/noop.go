// Package geoip provides GeoIP database integration for geographic request metadata.
package geoip

import (
	"log/slog"
	"net"
)

// NoopManager is a variable for noop manager.
var NoopManager Manager = &noop{driver: DriverNoop}

type noop struct {
	driver string
}

// Lookup performs the lookup operation on the noop.
func (m *noop) Lookup(ip net.IP) (*Result, error) {
	slog.Debug("looking up IP", "ip", ip)
	return &Result{}, nil
}

// Close releases resources held by the noop.
func (m *noop) Close() error {
	slog.Debug("closing noop geoip manager")
	return nil
}

// Driver performs the driver operation on the noop.
func (m *noop) Driver() string {
	return m.driver
}

func init() {
	Register(DriverNoop, func(Settings) (Manager, error) {
		return NoopManager, nil
	})
}
