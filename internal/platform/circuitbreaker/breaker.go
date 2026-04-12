// Package circuitbreaker implements the circuit breaker pattern for fault tolerance
package circuitbreaker

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

// State represents the state of a circuit breaker
type State int

const (
	// StateClosed is a constant for state closed.
	StateClosed State = iota // Normal operation
	// StateOpen is a constant for state open.
	StateOpen // Failing, reject calls
	// StateHalfOpen is a constant for state half open.
	StateHalfOpen // Testing recovery
)

// String returns a human-readable representation of the State.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// CircuitBreaker prevents cascading failures by stopping calls to failing services
type CircuitBreaker struct {
	name             string
	state            State
	failureCount     atomic.Uint32
	successCount     atomic.Uint32
	lastFailTime     atomic.Int64 // Unix nanoseconds
	failureThreshold uint32
	successThreshold uint32
	timeout          time.Duration
	transitioning    atomic.Uint32 // 0=not transitioning, 1=transitioning (prevents thundering herd)
	halfOpenInFlight atomic.Int32  // number of probe requests currently in flight during half-open state
	mu               sync.RWMutex
	stateChangeTime  time.Time
}

// Config contains configuration for a circuit breaker
type Config struct {
	Name             string        // Unique identifier for this breaker
	FailureThreshold uint32        // Failures before opening (default: 5)
	SuccessThreshold uint32        // Successes before closing (default: 3)
	Timeout          time.Duration // Time in open state before trying half-open (default: 30s)
}

// New creates a new circuit breaker
func New(config Config) *CircuitBreaker {
	if config.FailureThreshold == 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold == 0 {
		config.SuccessThreshold = 3
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &CircuitBreaker{
		name:             config.Name,
		state:            StateClosed,
		failureThreshold: config.FailureThreshold,
		successThreshold: config.SuccessThreshold,
		timeout:          config.Timeout,
		stateChangeTime:  time.Now(),
	}
}

// Call executes the given function, applying circuit breaker logic
// Returns ErrCircuitOpen if circuit is open and timeout has not elapsed
func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.RLock()
	state := cb.state
	cb.mu.RUnlock()

	switch state {
	case StateClosed:
		return cb.callInClosedState(fn)
	case StateOpen:
		return cb.callInOpenState(fn)
	case StateHalfOpen:
		return cb.callInHalfOpenState(fn)
	default:
		return fmt.Errorf("unknown circuit breaker state: %v", state)
	}
}

// callInClosedState executes fn and records result
func (cb *CircuitBreaker) callInClosedState(fn func() error) error {
	err := fn()
	cb.recordResult(err == nil)
	return err
}

// callInOpenState checks if timeout elapsed to transition to half-open
func (cb *CircuitBreaker) callInOpenState(fn func() error) error {
	cb.mu.RLock()
	lastFailNs := cb.lastFailTime.Load()
	cb.mu.RUnlock()

	if lastFailNs > 0 {
		lastFailTime := time.Unix(0, lastFailNs)
		if time.Since(lastFailTime) > cb.timeout {
			// Timeout elapsed, try to recover
			// Prevent thundering herd: only one goroutine can transition to half-open
			if !cb.transitioning.CompareAndSwap(0, 1) {
				// Another goroutine is already transitioning, reject this call
				return ErrCircuitOpen
			}
			defer cb.transitioning.Store(0)

			cb.mu.Lock()
			cb.state = StateHalfOpen
			cb.successCount.Store(0)
			cb.failureCount.Store(0)
			cb.halfOpenInFlight.Store(0)
			cb.mu.Unlock()

			// Try once
			err := fn()
			cb.recordResult(err == nil)
			return err
		}
	}

	return ErrCircuitOpen
}

// callInHalfOpenState tests if service is recovered.
// Only successThreshold concurrent probe requests are allowed through.
// Additional requests fail fast with ErrCircuitOpen to prevent a thundering herd.
func (cb *CircuitBreaker) callInHalfOpenState(fn func() error) error {
	// Limit concurrent probes to successThreshold
	current := cb.halfOpenInFlight.Add(1)
	if current > int32(cb.successThreshold) {
		cb.halfOpenInFlight.Add(-1)
		return ErrCircuitOpen
	}
	defer cb.halfOpenInFlight.Add(-1)

	err := fn()
	cb.recordResult(err == nil)
	return err
}

// recordResult processes the outcome of a call
func (cb *CircuitBreaker) recordResult(success bool) {
	cb.mu.Lock()
	oldState := cb.state

	if success {
		_ = cb.failureCount.Swap(0)
		succCount := cb.successCount.Add(1)

		// In half-open state, close after threshold successes
		if cb.state == StateHalfOpen && succCount >= cb.successThreshold {
			cb.state = StateClosed
			cb.stateChangeTime = time.Now()
		}
	} else {
		_ = cb.successCount.Swap(0)
		failCount := cb.failureCount.Add(1)

		// In closed state, open after threshold failures
		if cb.state == StateClosed && failCount >= cb.failureThreshold {
			cb.state = StateOpen
			cb.lastFailTime.Store(time.Now().UnixNano())
			cb.stateChangeTime = time.Now()
		}
	}

	newState := cb.state
	cb.mu.Unlock()

	// Emit state change event
	if oldState != newState {
		cb.emitStateChangeEvent(oldState, newState)
	}
}

// emitStateChangeEvent publishes a state change event
func (cb *CircuitBreaker) emitStateChangeEvent(oldState, newState State) {
	eventType := events.EventCircuitBreakerStateChange

	// Also emit specific events for important transitions
	if newState == StateOpen {
		eventType = events.EventCircuitBreakerOpen
	} else if newState == StateClosed {
		eventType = events.EventCircuitBreakerClosed
	} else if newState == StateHalfOpen {
		eventType = events.EventCircuitBreakerHalfOpen
	}

	event := events.SystemEvent{
		Type:      eventType,
		Severity:  events.SeverityWarning,
		Timestamp: time.Now(),
		Source:    "circuit_breaker",
		Data: map[string]interface{}{
			"service":   cb.name,
			"old_state": oldState.String(),
			"new_state": newState.String(),
		},
	}

	_ = events.Publish(event)
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetStats returns current statistics
func (cb *CircuitBreaker) GetStats() Stats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return Stats{
		State:                cb.state.String(),
		FailureCount:         cb.failureCount.Load(),
		SuccessCount:         cb.successCount.Load(),
		FailureThreshold:     cb.failureThreshold,
		SuccessThreshold:     cb.successThreshold,
		TimeSinceStateChange: time.Since(cb.stateChangeTime),
	}
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateClosed
	cb.failureCount.Store(0)
	cb.successCount.Store(0)
	cb.halfOpenInFlight.Store(0)
	cb.lastFailTime.Store(0)
	cb.stateChangeTime = time.Now()
}

// Stats contains circuit breaker statistics
type Stats struct {
	State                string
	FailureCount         uint32
	SuccessCount         uint32
	FailureThreshold     uint32
	SuccessThreshold     uint32
	TimeSinceStateChange time.Duration
}

// ErrCircuitOpen is returned when the circuit breaker is open
var ErrCircuitOpen = fmt.Errorf("circuit breaker is open")
