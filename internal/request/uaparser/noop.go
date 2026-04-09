// Package uaparser parses User-Agent strings to extract browser, OS, and device information.
package uaparser

import (
	"log/slog"
)

// NoopManager is a variable for noop manager.
var NoopManager Manager = &noop{driver: DriverNoop}

type noop struct {
	driver string
}

// Parse performs the parse operation on the noop.
func (m *noop) Parse(userAgent string) (*Result, error) {
	slog.Debug("parsing user agent", "user_agent", userAgent)
	return &Result{}, nil
}

// Close releases resources held by the noop.
func (m *noop) Close() error {
	slog.Debug("closing noop uaparser manager")
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
