// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultShadowTimeout       = 500 * time.Millisecond
	defaultShadowMaxConcurrent = 100
	defaultShadowMaxBodySize   = 1 * 1024 * 1024 // 1MB

	// Circuit breaker defaults for shadow
	defaultShadowCBFailureThreshold = 5
	defaultShadowCBSuccessThreshold = 2
	defaultShadowCBTimeout          = 30 * time.Second
)

// ShadowTransport manages asynchronous traffic mirroring with circuit breaking.
type ShadowTransport struct {
	client       *http.Client
	targetURL    *url.URL
	sampleRate   float64
	ignoreErrors bool
	headersOnly  bool
	maxBodySize  int64
	modifiers    []ShadowModifier
	sem          chan struct{} // Bounded concurrency

	// Circuit breaker state
	cbMu               sync.Mutex
	cbState            string // "closed", "open", "half_open"
	cbFailures         int
	cbSuccesses        int
	cbFailureThreshold int
	cbSuccessThreshold int
	cbOpenUntil        time.Time
	cbTimeout          time.Duration

	// Metrics
	sent    atomic.Int64
	dropped atomic.Int64
	errors  atomic.Int64
	cbTrips atomic.Int64
}

// ShadowModifier modifies shadow requests (header set/remove).
type ShadowModifier struct {
	HeadersSet    map[string]string
	HeadersRemove []string
}

// ShadowConfig holds the parsed configuration for the shadow transport.
type ShadowConfig struct {
	UpstreamURL  string
	SampleRate   float64
	IgnoreErrors bool
	HeadersOnly  bool // If true, shadow only headers (no body) to save bandwidth
	Timeout      time.Duration
	MaxConcurrent int
	MaxBodySize  int64
	Modifiers    []ShadowModifier

	// Circuit breaker
	CBFailureThreshold int
	CBSuccessThreshold int
	CBTimeout          time.Duration
}

// NewShadowTransport creates a new shadow transport.
func NewShadowTransport(cfg ShadowConfig) (*ShadowTransport, error) {
	target, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, err
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = defaultShadowTimeout
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = defaultShadowMaxConcurrent
	}
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = defaultShadowMaxBodySize
	}
	if cfg.SampleRate == 0 {
		cfg.SampleRate = 1.0
	}
	if cfg.CBFailureThreshold == 0 {
		cfg.CBFailureThreshold = defaultShadowCBFailureThreshold
	}
	if cfg.CBSuccessThreshold == 0 {
		cfg.CBSuccessThreshold = defaultShadowCBSuccessThreshold
	}
	if cfg.CBTimeout == 0 {
		cfg.CBTimeout = defaultShadowCBTimeout
	}

	client := &http.Client{
		Timeout: cfg.Timeout,
		// Don't follow redirects for shadow requests
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	st := &ShadowTransport{
		client:             client,
		targetURL:          target,
		sampleRate:         cfg.SampleRate,
		ignoreErrors:       cfg.IgnoreErrors,
		headersOnly:        cfg.HeadersOnly,
		maxBodySize:        cfg.MaxBodySize,
		modifiers:          cfg.Modifiers,
		sem:                make(chan struct{}, cfg.MaxConcurrent),
		cbState:            "closed",
		cbFailureThreshold: cfg.CBFailureThreshold,
		cbSuccessThreshold: cfg.CBSuccessThreshold,
		cbTimeout:          cfg.CBTimeout,
	}

	slog.Info("shadow transport initialized",
		"target", cfg.UpstreamURL,
		"sample_rate", cfg.SampleRate,
		"timeout", cfg.Timeout,
		"max_concurrent", cfg.MaxConcurrent)

	return st, nil
}

// Shadow sends a cloned request to the shadow target asynchronously.
// It reads and buffers the body, then dispatches the shadow request in a goroutine.
// The original request's body is reconstructed for the primary handler.
func (st *ShadowTransport) Shadow(req *http.Request) {
	// Sampling
	if st.sampleRate < 1.0 && rand.Float64() > st.sampleRate {
		return
	}

	// Check body size
	if req.ContentLength > st.maxBodySize {
		slog.Debug("shadow: body too large, skipping",
			"content_length", req.ContentLength,
			"max_body_size", st.maxBodySize)
		st.dropped.Add(1)
		return
	}

	// Check circuit breaker
	if !st.cbAllow() {
		st.dropped.Add(1)
		return
	}

	// Read body into buffer for cloning (skip body in headers-only mode)
	var bodyBuf []byte
	if !st.headersOnly && req.Body != nil && req.ContentLength != 0 {
		var err error
		bodyBuf, err = io.ReadAll(io.LimitReader(req.Body, st.maxBodySize+1))
		if err != nil {
			slog.Debug("shadow: failed to read body", "error", err)
			st.dropped.Add(1)
			return
		}

		// Check if body exceeds limit
		if int64(len(bodyBuf)) > st.maxBodySize {
			// Reconstruct body for primary handler but skip shadow
			req.Body = io.NopCloser(bytes.NewReader(bodyBuf))
			st.dropped.Add(1)
			return
		}

		// Reconstruct body for primary handler
		req.Body = io.NopCloser(bytes.NewReader(bodyBuf))
	}

	// Build shadow request
	shadowURL := *st.targetURL
	shadowURL.Path = req.URL.Path
	shadowURL.RawQuery = req.URL.RawQuery

	// Use context.WithoutCancel so shadow survives client disconnect
	shadowCtx := context.WithoutCancel(req.Context())

	var shadowBody io.Reader
	if len(bodyBuf) > 0 {
		shadowBody = bytes.NewReader(bodyBuf)
	}
	shadowReq, err := http.NewRequestWithContext(shadowCtx, req.Method, shadowURL.String(), shadowBody)
	if err != nil {
		slog.Debug("shadow: failed to create request", "error", err)
		st.dropped.Add(1)
		return
	}

	// Copy headers
	for k, vv := range req.Header {
		for _, v := range vv {
			shadowReq.Header.Add(k, v)
		}
	}

	// Apply modifiers
	for _, mod := range st.modifiers {
		for _, h := range mod.HeadersRemove {
			shadowReq.Header.Del(h)
		}
		for k, v := range mod.HeadersSet {
			shadowReq.Header.Set(k, v)
		}
	}

	// Dispatch asynchronously with bounded concurrency
	select {
	case st.sem <- struct{}{}:
		go func() {
			defer func() { <-st.sem }()
			st.sendShadow(shadowReq)
		}()
	default:
		// Worker pool full — drop
		st.dropped.Add(1)
		slog.Debug("shadow: worker pool full, dropping request")
	}
}

// sendShadow executes the shadow request.
func (st *ShadowTransport) sendShadow(req *http.Request) {
	resp, err := st.client.Do(req)
	if err != nil {
		st.errors.Add(1)
		st.cbRecordFailure()

		if !st.ignoreErrors {
			slog.Error("shadow request failed",
				"url", req.URL.String(),
				"error", err)
		}
		return
	}

	// Drain and close response body
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 500 {
		st.cbRecordFailure()
		st.errors.Add(1)

		if !st.ignoreErrors {
			slog.Warn("shadow request returned error",
				"url", req.URL.String(),
				"status", resp.StatusCode)
		}
	} else {
		st.cbRecordSuccess()
		st.sent.Add(1)
	}
}

// Circuit breaker methods

func (st *ShadowTransport) cbAllow() bool {
	st.cbMu.Lock()
	defer st.cbMu.Unlock()

	switch st.cbState {
	case "closed":
		return true
	case "open":
		if time.Now().After(st.cbOpenUntil) {
			st.cbState = "half_open"
			st.cbSuccesses = 0
			slog.Info("shadow circuit breaker: half-open",
				"target", st.targetURL.String())
			return true
		}
		return false
	case "half_open":
		return true
	default:
		return true
	}
}

func (st *ShadowTransport) cbRecordFailure() {
	st.cbMu.Lock()
	defer st.cbMu.Unlock()

	st.cbFailures++

	switch st.cbState {
	case "closed":
		if st.cbFailures >= st.cbFailureThreshold {
			st.cbState = "open"
			st.cbOpenUntil = time.Now().Add(st.cbTimeout)
			st.cbTrips.Add(1)
			slog.Warn("shadow circuit breaker: OPEN",
				"target", st.targetURL.String(),
				"failures", st.cbFailures,
				"retry_after", st.cbTimeout)
		}
	case "half_open":
		st.cbState = "open"
		st.cbOpenUntil = time.Now().Add(st.cbTimeout)
		st.cbTrips.Add(1)
		slog.Warn("shadow circuit breaker: OPEN (half-open failed)",
			"target", st.targetURL.String())
	}
}

func (st *ShadowTransport) cbRecordSuccess() {
	st.cbMu.Lock()
	defer st.cbMu.Unlock()

	switch st.cbState {
	case "half_open":
		st.cbSuccesses++
		if st.cbSuccesses >= st.cbSuccessThreshold {
			st.cbState = "closed"
			st.cbFailures = 0
			slog.Info("shadow circuit breaker: CLOSED",
				"target", st.targetURL.String())
		}
	case "closed":
		// Reset failure count on success
		if st.cbFailures > 0 {
			st.cbFailures = 0
		}
	}
}

// Metrics returns shadow transport metrics.
type ShadowMetrics struct {
	Sent    int64  `json:"sent"`
	Dropped int64  `json:"dropped"`
	Errors  int64  `json:"errors"`
	CBTrips int64  `json:"circuit_breaker_trips"`
	CBState string `json:"circuit_breaker_state"`
}

// Metrics performs the metrics operation on the ShadowTransport.
func (st *ShadowTransport) Metrics() ShadowMetrics {
	st.cbMu.Lock()
	state := st.cbState
	st.cbMu.Unlock()

	return ShadowMetrics{
		Sent:    st.sent.Load(),
		Dropped: st.dropped.Load(),
		Errors:  st.errors.Load(),
		CBTrips: st.cbTrips.Load(),
		CBState: state,
	}
}
