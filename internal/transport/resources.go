// resources.go implements Envoy-style resource-threshold circuit breaking with atomic counters.
package transport

import "sync/atomic"

// ResourceLimitsConfig defines the thresholds for resource-based circuit breaking.
// A zero value for any field means that dimension is unlimited.
type ResourceLimitsConfig struct {
	MaxConnections     int64
	MaxPendingRequests int64
	MaxRequests        int64
	MaxRetries         int64
}

// ResourceLimits provides Envoy-style resource-threshold circuit breaking using
// atomic counters. Each dimension (connections, pending requests, active requests,
// retries) is tracked independently and checked by Allow().
type ResourceLimits struct {
	cfg         ResourceLimitsConfig
	connections atomic.Int64
	pending     atomic.Int64
	requests    atomic.Int64
	retries     atomic.Int64
}

// NewResourceLimits creates a ResourceLimits with the given thresholds.
func NewResourceLimits(cfg ResourceLimitsConfig) *ResourceLimits {
	return &ResourceLimits{cfg: cfg}
}

// Allow reports whether all resource dimensions are within their configured limits.
// Dimensions with a zero limit are treated as unlimited.
func (rl *ResourceLimits) Allow() bool {
	if rl.cfg.MaxConnections > 0 && rl.connections.Load() >= rl.cfg.MaxConnections {
		return false
	}
	if rl.cfg.MaxPendingRequests > 0 && rl.pending.Load() >= rl.cfg.MaxPendingRequests {
		return false
	}
	if rl.cfg.MaxRequests > 0 && rl.requests.Load() >= rl.cfg.MaxRequests {
		return false
	}
	if rl.cfg.MaxRetries > 0 && rl.retries.Load() >= rl.cfg.MaxRetries {
		return false
	}
	return true
}

// AddConnection increments the active connection count.
func (rl *ResourceLimits) AddConnection() { rl.connections.Add(1) }

// RemoveConnection decrements the active connection count.
func (rl *ResourceLimits) RemoveConnection() { rl.connections.Add(-1) }

// AddRequest increments the active request count.
func (rl *ResourceLimits) AddRequest() { rl.requests.Add(1) }

// RemoveRequest decrements the active request count.
func (rl *ResourceLimits) RemoveRequest() { rl.requests.Add(-1) }

// AddPending increments the pending request count.
func (rl *ResourceLimits) AddPending() { rl.pending.Add(1) }

// RemovePending decrements the pending request count.
func (rl *ResourceLimits) RemovePending() { rl.pending.Add(-1) }

// AddRetry increments the active retry count.
func (rl *ResourceLimits) AddRetry() { rl.retries.Add(1) }

// RemoveRetry decrements the active retry count.
func (rl *ResourceLimits) RemoveRetry() { rl.retries.Add(-1) }
