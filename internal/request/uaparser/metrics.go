// Package uaparser parses User-Agent strings to extract browser, OS, and device information.
package uaparser

import (
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

// Parse wraps the Parse operation with metrics
func (mm *MetricsManager) Parse(userAgent string) (*Result, error) {
	startTime := time.Now()

	result, err := mm.Manager.Parse(userAgent)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.UAParserOperationError(mm.driver, "parse", "error")
		metric.UAParserOperation(mm.driver, "parse", "error", duration)
		return nil, err
	}

	// Extract browser, OS, and device families for metrics
	browserFamily := "unknown"
	osFamily := "unknown"
	deviceFamily := "unknown"

	if result != nil {
		if result.UserAgent != nil {
			browserFamily = result.UserAgent.Family
		}
		if result.OS != nil {
			osFamily = result.OS.Family
		}
		if result.Device != nil {
			deviceFamily = result.Device.Family
		}
	}

	// Record parse metrics
	metric.UAParserParse(mm.driver, browserFamily, osFamily, deviceFamily, duration)
	metric.UAParserOperation(mm.driver, "parse", "success", duration)

	return result, nil
}

// Close wraps the Close operation with metrics
func (mm *MetricsManager) Close() error {
	startTime := time.Now()

	err := mm.Manager.Close()
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.UAParserOperationError(mm.driver, "close", "error")
		metric.UAParserOperation(mm.driver, "close", "error", duration)
		return err
	}

	metric.UAParserOperation(mm.driver, "close", "success", duration)
	return nil
}
