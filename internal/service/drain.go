// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Drainer manages graceful connection draining during config reloads or
// shutdown. It tracks in-flight requests and blocks until all active requests
// complete or a timeout is reached.
type Drainer struct {
	active   atomic.Int64
	draining atomic.Bool
	done     chan struct{}
	mu       sync.Mutex
}

// NewDrainer creates a Drainer ready to track in-flight requests.
func NewDrainer() *Drainer {
	return &Drainer{
		done: make(chan struct{}),
	}
}

// Increment marks the start of a new in-flight request. It should be called
// when a request begins processing.
func (d *Drainer) Increment() {
	d.active.Add(1)
}

// Decrement marks the completion of an in-flight request. If the drainer is
// in draining mode and the active count reaches zero, the drain is signalled
// as complete.
func (d *Drainer) Decrement() {
	n := d.active.Add(-1)
	if n <= 0 && d.draining.Load() {
		d.mu.Lock()
		defer d.mu.Unlock()
		// Double-check under lock to avoid closing an already-closed channel
		select {
		case <-d.done:
			// Already closed
		default:
			close(d.done)
		}
	}
}

// ActiveCount returns the number of currently in-flight requests.
func (d *Drainer) ActiveCount() int64 {
	return d.active.Load()
}

// StartDrain begins the draining process. It blocks until all active requests
// complete or the timeout expires. Returns nil if all requests drained
// successfully, or an error if the timeout was reached or the context was
// cancelled.
func (d *Drainer) StartDrain(ctx context.Context, timeout time.Duration) error {
	d.draining.Store(true)

	// If there are no active requests, return immediately
	if d.active.Load() <= 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-d.done:
		return nil
	case <-ctx.Done():
		remaining := d.active.Load()
		if remaining > 0 {
			return errors.New("drain timeout: " + ctx.Err().Error() + " with active connections remaining")
		}
		return nil
	}
}

// IsDraining returns true if the drainer is currently in draining mode.
func (d *Drainer) IsDraining() bool {
	return d.draining.Load()
}
