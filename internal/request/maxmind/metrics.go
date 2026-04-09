// Package maxmind integrates MaxMind GeoIP databases for geographic request metadata.
package maxmind

import (
	"net"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// MetricsManager wraps a Manager with metrics collection
type MetricsManager struct {
	Manager
	driver string
}

// NewMetricsManager creates a new metrics manager wrapper
func NewMetricsManager(manager Manager, driver string) Manager {
	if manager == nil {
		return nil
	}
	return &MetricsManager{
		Manager: manager,
		driver:  driver,
	}
}

// Lookup wraps the Lookup operation with metrics
func (mm *MetricsManager) Lookup(ip net.IP) (*Result, error) {
	startTime := time.Now()

	result, err := mm.Manager.Lookup(ip)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.MaxMindOperationError(mm.driver, "lookup", "error")
		metric.MaxMindOperation(mm.driver, "lookup", "error", duration)
		return nil, err
	}

	// Determine IP version for metrics
	ipVersion := "unknown"
	if ip != nil {
		if ip.To4() != nil {
			ipVersion = "ipv4"
		} else if ip.To16() != nil {
			ipVersion = "ipv6"
		}
	}

	// Get country code for metrics
	countryCode := "unknown"
	if result != nil && result.CountryCode != "" {
		countryCode = result.CountryCode
	}

	// Record lookup metrics
	metric.MaxMindLookup(mm.driver, ipVersion, countryCode, duration)
	metric.MaxMindOperation(mm.driver, "lookup", "success", duration)

	return result, nil
}

// Close wraps the Close operation with metrics
func (mm *MetricsManager) Close() error {
	startTime := time.Now()

	err := mm.Manager.Close()
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.MaxMindOperationError(mm.driver, "close", "error")
		metric.MaxMindOperation(mm.driver, "close", "error", duration)
		return err
	}

	metric.MaxMindOperation(mm.driver, "close", "success", duration)
	return nil
}
