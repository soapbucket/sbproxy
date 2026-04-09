// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"net/http"
	"sync"
	"time"
)

// ConnectionLimiter limits concurrent connections using a counter with mutex
// This is more efficient than channel-based limiting for high-throughput scenarios
type ConnectionLimiter struct {
	http.RoundTripper

	maxConnections int
	activeCount    int
	mutex          sync.Mutex
	zeroCond       *sync.Cond
}

// NewConnectionLimiter creates a new connection limiter
func NewConnectionLimiter(tr http.RoundTripper, maxConnections int) http.RoundTripper {
	if maxConnections <= 0 {
		return tr // No limiting if maxConnections is 0 or negative
	}

	cl := &ConnectionLimiter{
		RoundTripper:   tr,
		maxConnections: maxConnections,
	}
	cl.zeroCond = sync.NewCond(&cl.mutex)
	return cl
}

// RoundTrip implements the connection limiting logic
func (cl *ConnectionLimiter) RoundTrip(req *http.Request) (*http.Response, error) {
	// Try to acquire a connection slot
	if !cl.tryAcquireConnection() {
		// Connection limit reached, return 503 Service Unavailable
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     make(http.Header),
			Request:    req,
			Body:       http.NoBody,
		}, nil
	}

	// Ensure we release the connection when done
	defer cl.releaseConnection()

	// Make the actual request
	return cl.RoundTripper.RoundTrip(req)
}

// tryAcquireConnection attempts to acquire a connection slot
// Returns true if successful, false if limit reached
func (cl *ConnectionLimiter) tryAcquireConnection() bool {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()

	if cl.activeCount >= cl.maxConnections {
		return false
	}

	cl.activeCount++
	return true
}

// releaseConnection releases a connection slot
func (cl *ConnectionLimiter) releaseConnection() {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()

	cl.activeCount--
	if cl.activeCount == 0 {
		cl.zeroCond.Broadcast()
	}
}

// GetActiveConnections returns the current number of active connections
func (cl *ConnectionLimiter) GetActiveConnections() int {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	return cl.activeCount
}

// GetMaxConnections returns the maximum number of connections allowed
func (cl *ConnectionLimiter) GetMaxConnections() int {
	return cl.maxConnections
}

// WaitForAllConnections waits for all active connections to complete
// This is useful for graceful shutdown
func (cl *ConnectionLimiter) WaitForAllConnections() {
	cl.mutex.Lock()
	for cl.activeCount > 0 {
		cl.zeroCond.Wait()
	}
	cl.mutex.Unlock()
}

// WaitForAllConnectionsWithTimeout waits for all active connections to complete
// with a timeout
func (cl *ConnectionLimiter) WaitForAllConnectionsWithTimeout(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		cl.WaitForAllConnections()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}
