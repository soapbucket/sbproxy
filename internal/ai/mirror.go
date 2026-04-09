// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	mathrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// TrafficMirror sends a copy of AI requests to a secondary model for comparison,
// quality assurance, or migration testing. Mirrored requests are fire-and-forget
// and never affect the primary request path.
type TrafficMirror struct {
	targetModel string
	sampleRate  float64
	executor    RequestExecutorFunc
	rng         *mathrand.Rand
	mu          sync.Mutex

	// Metrics
	mirrored atomic.Int64
	errors   atomic.Int64
}

// NewTrafficMirror creates a TrafficMirror with the given config and executor.
func NewTrafficMirror(cfg MirrorConfig, exec RequestExecutorFunc) *TrafficMirror {
	if !cfg.Enabled || cfg.SampleRate <= 0 {
		return nil
	}

	var seed [8]byte
	_, _ = rand.Read(seed[:])
	src := mathrand.NewPCG(binary.LittleEndian.Uint64(seed[:]), 0)

	return &TrafficMirror{
		targetModel: cfg.TargetModel,
		sampleRate:  cfg.SampleRate,
		executor:    exec,
		rng:         mathrand.New(src),
	}
}

// MaybeMirror asynchronously sends a copy of the request to the mirror target
// if the sample rate check passes. This method never blocks the caller.
func (m *TrafficMirror) MaybeMirror(ctx context.Context, req *ChatCompletionRequest) {
	if m == nil || !m.shouldSample() {
		return
	}

	// Copy the request to avoid data races with the primary path
	mirrorReq := *req
	mirrorReq.Stream = nil
	mirrorReq.StreamOptions = nil
	if m.targetModel != "" {
		mirrorReq.Model = m.targetModel
	}

	// Fire-and-forget with a detached context and timeout
	mirrorCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	go func() {
		defer cancel()
		m.mirrored.Add(1)

		_, err := m.executor(mirrorCtx, &mirrorReq, "", mirrorReq.Model)
		if err != nil {
			m.errors.Add(1)
			slog.Debug("traffic mirror error",
				"model", mirrorReq.Model,
				"error", err)
		}
	}()
}

// shouldSample returns true if this request should be mirrored based on sample rate.
func (m *TrafficMirror) shouldSample() bool {
	if m.sampleRate >= 1.0 {
		return true
	}
	m.mu.Lock()
	v := m.rng.Float64()
	m.mu.Unlock()
	return v < m.sampleRate
}

// Mirrored returns the total number of mirrored requests.
func (m *TrafficMirror) Mirrored() int64 {
	if m == nil {
		return 0
	}
	return m.mirrored.Load()
}

// Errors returns the total number of mirror errors.
func (m *TrafficMirror) Errors() int64 {
	if m == nil {
		return 0
	}
	return m.errors.Load()
}
