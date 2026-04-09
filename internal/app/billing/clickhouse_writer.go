// Package billing tracks and reports usage metrics for metered billing.
//
// The ClickHouse writer requires the enterprise build. In the core build,
// NewClickHouseWriter returns ErrNotAvailable.
package billing

import (
	"context"
	"fmt"
)

// ErrClickHouseNotAvailable is returned when the ClickHouse writer is requested
// but the enterprise dependency is not compiled in.
var ErrClickHouseNotAvailable = fmt.Errorf("billing: ClickHouse writer not available in core build (requires enterprise dependency)")

// ClickHouseWriter writes metrics to ClickHouse.
// In the core build this is a stub that always returns an error on creation.
type ClickHouseWriter struct{}

// NewClickHouseWriter creates a new ClickHouse metrics writer.
// Returns ErrClickHouseNotAvailable in the core build.
func NewClickHouseWriter(_ context.Context, _ string) (*ClickHouseWriter, error) {
	return nil, ErrClickHouseNotAvailable
}

// Write is a no-op stub.
func (chw *ClickHouseWriter) Write(_ context.Context, _ []UsageMetric) error {
	return ErrClickHouseNotAvailable
}

// Close is a no-op stub.
func (chw *ClickHouseWriter) Close() error {
	return nil
}
