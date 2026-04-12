// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/soapbucket/sbproxy/internal/loader/settings"
)

// CoalescingConfig configures request coalescing behavior
type CoalescingConfig struct {
	Enabled         bool          // Enable request coalescing
	MaxInflight     int           // Maximum in-flight coalesced requests (default: 1000)
	CoalesceWindow  time.Duration // Time window for coalescing (default: 100ms)
	KeyFunc         CoalesceKeyFunc // Function to generate coalesce key
	MaxWaiters      int           // Maximum waiters per request (default: 100)
	CleanupInterval time.Duration // Cleanup interval for stale entries (default: 30s)
}

// CoalesceKeyFunc generates a key for request coalescing
// Returns empty string to disable coalescing for this request
type CoalesceKeyFunc func(req *http.Request) string

// DefaultCoalesceKey generates a key from method + URL + headers.
// It hashes incrementally via xxhash.Digest to avoid building a temporary string.
func DefaultCoalesceKey(req *http.Request) string {
	h := xxhash.New()

	// Include method and URL
	_, _ = h.WriteString(req.Method)
	_, _ = h.WriteString(" ")
	_, _ = h.WriteString(req.URL.String())

	// Include relevant headers (e.g., Authorization, Accept)
	if auth := req.Header.Get("Authorization"); auth != "" {
		_, _ = h.WriteString("|auth:")
		_, _ = h.WriteString(auth)
	}
	if accept := req.Header.Get("Accept"); accept != "" {
		_, _ = h.WriteString("|accept:")
		_, _ = h.WriteString(accept)
	}

	// Include body hash for non-idempotent methods
	if req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH" {
		if req.GetBody != nil {
			reader, err := req.GetBody()
			if err == nil {
				defer reader.Close()
				bodyHasher := xxhash.New()
				limited := io.LimitReader(reader, 1024*1024+1)
				n, copyErr := io.Copy(bodyHasher, limited)
				if copyErr == nil && n > 0 && n <= 1024*1024 {
					_, _ = h.WriteString("|body:")
					_, _ = h.WriteString(strconv.FormatUint(bodyHasher.Sum64(), 16))
				}
			}
		}
	}

	return strconv.FormatUint(h.Sum64(), 16)
}

// MethodURLKey generates a key from method + URL only (no headers or body).
// Hashes incrementally to avoid intermediate string allocation.
func MethodURLKey(req *http.Request) string {
	h := xxhash.New()
	_, _ = h.WriteString(req.Method)
	_, _ = h.WriteString(" ")
	_, _ = h.WriteString(req.URL.String())
	return strconv.FormatUint(h.Sum64(), 16)
}

// CoalescingTransport wraps a transport with request coalescing
type CoalescingTransport struct {
	base     http.RoundTripper
	config   CoalescingConfig
	inflight sync.Map // key -> *coalesceGroup

	// Cleanup goroutine
	stopCleanup chan struct{}
	cleanupDone sync.WaitGroup

	// Metrics
	inflightCount int64
	inflightMu    sync.RWMutex
}

// coalesceGroup represents a group of coalesced requests
type coalesceGroup struct {
	mu         sync.Mutex
	waiters    []chan *coalesceResult
	maxWaiters int
	inProgress bool
	result     *coalesceResult
	createdAt  time.Time
}

type coalesceResult struct {
	resp *http.Response
	body []byte
	err  error
}

// NewCoalescingTransport creates a new coalescing transport
func NewCoalescingTransport(base http.RoundTripper, config CoalescingConfig) *CoalescingTransport {
	if config.KeyFunc == nil {
		config.KeyFunc = DefaultCoalesceKey
	}
	if config.MaxInflight == 0 {
		config.MaxInflight = 1000
	}
	if config.CoalesceWindow == 0 {
		config.CoalesceWindow = 100 * time.Millisecond
	}
	if config.MaxWaiters == 0 {
		config.MaxWaiters = 100
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 30 * time.Second
	}

	ct := &CoalescingTransport{
		base:        base,
		config:      config,
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup goroutine
	ct.cleanupDone.Add(1)
	go ct.cleanupStaleEntries()

	return ct
}

// RoundTrip implements http.RoundTripper
func (ct *CoalescingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !ct.config.Enabled {
		return ct.base.RoundTrip(req)
	}

	// Check max inflight limit
	ct.inflightMu.RLock()
	currentInflight := ct.inflightCount
	ct.inflightMu.RUnlock()

	if currentInflight >= int64(ct.config.MaxInflight) {
		// Too many in-flight requests, execute directly
		return ct.base.RoundTrip(req)
	}

	// Generate coalesce key
	key := ct.config.KeyFunc(req)
	if key == "" {
		// No coalescing for this request
		return ct.base.RoundTrip(req)
	}

	// Check if request is already in flight
	group, loaded := ct.inflight.LoadOrStore(key, &coalesceGroup{
		maxWaiters: ct.config.MaxWaiters,
		createdAt:  time.Now(),
	})

	cg := group.(*coalesceGroup)

	if loaded {
		// Request already in flight, wait for result
		resp, err := ct.waitForResult(cg, req.Context())
		if err != nil {
			// If waiting failed (e.g., context cancelled), execute directly
			return ct.base.RoundTrip(req)
		}
		return resp, err
	}

	// Increment inflight count
	ct.inflightMu.Lock()
	ct.inflightCount++
	ct.inflightMu.Unlock()

	// We're the first request, execute it
	resp, err := ct.executeRequest(cg, req)

	// Decrement inflight count
	ct.inflightMu.Lock()
	ct.inflightCount--
	ct.inflightMu.Unlock()

	return resp, err
}

// waitForResult waits for the in-flight request to complete
func (ct *CoalescingTransport) waitForResult(cg *coalesceGroup, ctx context.Context) (*http.Response, error) {
	cg.mu.Lock()

	// Check if result is already available
	if cg.result != nil {
		result := cg.result
		cg.mu.Unlock()
		return ct.cloneResponseWithBody(result.resp, result.body), result.err
	}

	// Check if we can join (not too many waiters)
	if len(cg.waiters) >= cg.maxWaiters {
		cg.mu.Unlock()
		// Too many waiters, return error so caller can execute directly
		return nil, fmt.Errorf("coalescing: max waiters exceeded")
	}

	// Create channel to wait for result
	resultChan := make(chan *coalesceResult, 1)
	cg.waiters = append(cg.waiters, resultChan)
	cg.mu.Unlock()

	// Wait for result with context timeout
	select {
	case result, ok := <-resultChan:
		if !ok || result == nil {
			return nil, fmt.Errorf("coalescing: result channel closed")
		}
		return ct.cloneResponseWithBody(result.resp, result.body), result.err
	case <-ctx.Done():
		// Context cancelled, remove from waiters
		cg.mu.Lock()
		for i, ch := range cg.waiters {
			if ch == resultChan {
				cg.waiters = append(cg.waiters[:i], cg.waiters[i+1:]...)
				break
			}
		}
		cg.mu.Unlock()
		return nil, ctx.Err()
	}
}

// executeRequest executes the request and broadcasts result to waiters
func (ct *CoalescingTransport) executeRequest(cg *coalesceGroup, req *http.Request) (*http.Response, error) {
	// Mark as in progress
	cg.mu.Lock()
	cg.inProgress = true
	cg.mu.Unlock()

	// Execute request
	resp, err := ct.base.RoundTrip(req)

	// Read body if present (needed for cloning) with size limit
	var bodyBytes []byte
	if resp != nil && resp.Body != nil && err == nil {
		limitedBody := io.LimitReader(resp.Body, settings.Global.MaxCoalesceBodyBytes)
		bodyBytes, err = io.ReadAll(limitedBody)
		if err == nil {
			// Restore body for original response
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		} else {
			// Read failed, but we still have a response
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(nil))
		}
	}

	// Create result
	result := &coalesceResult{
		resp: ct.cloneResponseWithoutBody(resp),
		body: bodyBytes,
		err:  err,
	}

	// Store result and broadcast to waiters
	cg.mu.Lock()
	cg.result = result
	cg.inProgress = false
	waiters := cg.waiters
	cg.waiters = nil // Clear waiters
	cg.mu.Unlock()

	// Broadcast result to all waiters
	for _, ch := range waiters {
		ch <- result
	}

	return resp, err
}

// cloneResponseWithBody clones a response with pre-read body bytes
func (ct *CoalescingTransport) cloneResponseWithBody(resp *http.Response, bodyBytes []byte) *http.Response {
	if resp == nil {
		return nil
	}
	cloned := ct.cloneResponseWithoutBody(resp)
	cloned.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return cloned
}

// cloneResponseWithoutBody clones a response without body
func (ct *CoalescingTransport) cloneResponseWithoutBody(resp *http.Response) *http.Response {
	if resp == nil {
		return nil
	}
	// Clone response
	cloned := &http.Response{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Proto:      resp.Proto,
		ProtoMajor: resp.ProtoMajor,
		ProtoMinor: resp.ProtoMinor,
		Header:     make(http.Header),
		Body:       nil,
		Request:    resp.Request,
		Trailer:    resp.Trailer,
	}

	// Copy headers
	for k, v := range resp.Header {
		cloned.Header[k] = v
	}

	// Copy trailers
	if resp.Trailer != nil {
		cloned.Trailer = make(http.Header)
		for k, v := range resp.Trailer {
			cloned.Trailer[k] = v
		}
	}

	return cloned
}

// maxGroupLifetime is the maximum time a coalesce group can exist before
// being forcibly cleaned up. This prevents leaks if an upstream never responds.
const maxGroupLifetime = 2 * time.Minute

// cleanupStaleEntries periodically removes stale coalesce groups
func (ct *CoalescingTransport) cleanupStaleEntries() {
	defer ct.cleanupDone.Done()

	ticker := time.NewTicker(ct.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			ct.inflight.Range(func(key, value interface{}) bool {
				cg := value.(*coalesceGroup)
				cg.mu.Lock()
				age := now.Sub(cg.createdAt)
				stale := !cg.inProgress && cg.result != nil &&
					age > ct.config.CoalesceWindow*2
				// Force-evict groups that have been alive too long (upstream hang protection).
				// If a group is still in-progress past maxGroupLifetime, the upstream is
				// likely hung. Evict the entry so the sync.Map does not grow unbounded.
				expired := age > maxGroupLifetime
				waiters := cg.waiters
				if expired && cg.inProgress {
					cg.waiters = nil
				}
				cg.mu.Unlock()

				if stale || expired {
					ct.inflight.Delete(key)
					// Wake any blocked waiters with an error so they can retry directly.
					if expired {
						errResult := &coalesceResult{
							err: fmt.Errorf("coalescing: group expired after %v", maxGroupLifetime),
						}
						for _, ch := range waiters {
							ch <- errResult
						}
					}
				}
				return true
			})
		case <-ct.stopCleanup:
			return
		}
	}
}

// Close stops the cleanup goroutine
func (ct *CoalescingTransport) Close() {
	close(ct.stopCleanup)
	ct.cleanupDone.Wait()
}

// GetInflightCount returns the current number of in-flight coalesced requests
func (ct *CoalescingTransport) GetInflightCount() int64 {
	ct.inflightMu.RLock()
	defer ct.inflightMu.RUnlock()
	return ct.inflightCount
}

