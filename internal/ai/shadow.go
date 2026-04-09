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

// ShadowConfig configures shadow mode for AI traffic.
type ShadowConfig struct {
	Enabled        bool    `json:"enabled"`
	ShadowProvider string  `json:"shadow_provider"`
	ShadowModel    string  `json:"shadow_model,omitempty"`
	SampleRate     float64 `json:"sample_rate"`
	AsyncCompare   bool    `json:"async_compare"`
	LogDiffs       bool    `json:"log_diffs"`
}

// ShadowResult holds the comparison between primary and shadow responses.
type ShadowResult struct {
	PrimaryProvider string        `json:"primary_provider"`
	ShadowProvider  string        `json:"shadow_provider"`
	PrimaryModel    string        `json:"primary_model"`
	ShadowModel     string        `json:"shadow_model"`
	PrimaryLatency  time.Duration `json:"primary_latency_ms"`
	ShadowLatency   time.Duration `json:"shadow_latency_ms"`
	PrimaryTokens   int           `json:"primary_tokens"`
	ShadowTokens    int           `json:"shadow_tokens"`
	PrimaryStatus   int           `json:"primary_status"`
	ShadowStatus    int           `json:"shadow_status"`
	ContentMatch    bool          `json:"content_match"`
	Timestamp       time.Time     `json:"timestamp"`
}

// ShadowMetrics tracks aggregate shadow execution statistics.
type ShadowMetrics struct {
	TotalShadowed  atomic.Int64
	ContentMatches atomic.Int64
	ShadowErrors   atomic.Int64
	AvgLatencyDiff atomic.Int64 // In microseconds
}

// RequestExecutorFunc executes a ChatCompletionRequest and returns a response.
// The provider and model parameters allow overriding the target for the request.
type RequestExecutorFunc func(ctx context.Context, req *ChatCompletionRequest, provider string, model string) (*ChatCompletionResponse, error)

// ShadowExecutor runs shadow requests alongside primary requests.
type ShadowExecutor struct {
	config  ShadowConfig
	exec    RequestExecutorFunc
	results chan ShadowResult
	metrics ShadowMetrics
	rng     *mathrand.Rand
	mu      sync.Mutex
}

// NewShadowExecutor creates a new ShadowExecutor with the given config and executor function.
func NewShadowExecutor(config ShadowConfig, exec RequestExecutorFunc) *ShadowExecutor {
	var seed [8]byte
	_, _ = rand.Read(seed[:])
	src := mathrand.NewPCG(binary.LittleEndian.Uint64(seed[:]), 0)

	return &ShadowExecutor{
		config:  config,
		exec:    exec,
		results: make(chan ShadowResult, 256),
		rng:     mathrand.New(src),
	}
}

// Execute runs the primary request and optionally shadows it.
// Always returns the primary response, never the shadow response.
func (se *ShadowExecutor) Execute(ctx context.Context, req *ChatCompletionRequest, primaryProvider string, primaryModel string) (*ChatCompletionResponse, error) {
	if !se.config.Enabled || !se.shouldSample() {
		return se.exec(ctx, req, primaryProvider, primaryModel)
	}

	// Run primary and shadow concurrently
	type result struct {
		resp    *ChatCompletionResponse
		err     error
		latency time.Duration
	}

	primaryCh := make(chan result, 1)
	shadowCh := make(chan result, 1)

	// Primary request
	go func() {
		start := time.Now()
		resp, err := se.exec(ctx, req, primaryProvider, primaryModel)
		primaryCh <- result{resp: resp, err: err, latency: time.Since(start)}
	}()

	// Shadow request (uses a detached context so primary cancellation does not kill it)
	shadowModel := se.config.ShadowModel
	if shadowModel == "" {
		shadowModel = primaryModel
	}
	shadowCtx, shadowCancel := context.WithTimeout(context.Background(), 30*time.Second)
	go func() {
		defer shadowCancel()
		start := time.Now()
		resp, err := se.exec(shadowCtx, req, se.config.ShadowProvider, shadowModel)
		shadowCh <- result{resp: resp, err: err, latency: time.Since(start)}
	}()

	// Wait for primary
	primaryResult := <-primaryCh

	se.metrics.TotalShadowed.Add(1)

	if se.config.AsyncCompare {
		// Compare asynchronously
		go func() {
			shadowResult := <-shadowCh
			shadowCancel()
			se.compare(primaryProvider, primaryModel, shadowModel, primaryResult, shadowResult)
		}()
	} else {
		// Wait for shadow and compare inline
		shadowResult := <-shadowCh
		shadowCancel()
		se.compare(primaryProvider, primaryModel, shadowModel, primaryResult, shadowResult)
	}

	return primaryResult.resp, primaryResult.err
}

// Results returns the channel of shadow comparison results.
func (se *ShadowExecutor) Results() <-chan ShadowResult {
	return se.results
}

// Metrics returns current shadow metrics.
func (se *ShadowExecutor) Metrics() *ShadowMetrics {
	return &se.metrics
}

// shouldSample returns true if this request should be shadowed based on sample rate.
func (se *ShadowExecutor) shouldSample() bool {
	if se.config.SampleRate <= 0 {
		return false
	}
	if se.config.SampleRate >= 1.0 {
		return true
	}
	se.mu.Lock()
	v := se.rng.Float64()
	se.mu.Unlock()
	return v < se.config.SampleRate
}

// compare builds a ShadowResult and sends it to the results channel.
func (se *ShadowExecutor) compare(primaryProvider, primaryModel, shadowModel string, primary, shadow struct {
	resp    *ChatCompletionResponse
	err     error
	latency time.Duration
}) {
	sr := ShadowResult{
		PrimaryProvider: primaryProvider,
		ShadowProvider:  se.config.ShadowProvider,
		PrimaryModel:    primaryModel,
		ShadowModel:     shadowModel,
		PrimaryLatency:  primary.latency,
		ShadowLatency:   shadow.latency,
		Timestamp:       time.Now(),
	}

	if primary.err == nil {
		sr.PrimaryStatus = 200
	} else {
		sr.PrimaryStatus = 500
	}

	if shadow.err != nil {
		se.metrics.ShadowErrors.Add(1)
		sr.ShadowStatus = 500
	} else {
		sr.ShadowStatus = 200
	}

	if primary.resp != nil && primary.resp.Usage != nil {
		sr.PrimaryTokens = primary.resp.Usage.TotalTokens
	}
	if shadow.resp != nil && shadow.resp.Usage != nil {
		sr.ShadowTokens = shadow.resp.Usage.TotalTokens
	}

	// Content comparison
	sr.ContentMatch = se.contentMatch(primary.resp, shadow.resp)
	if sr.ContentMatch {
		se.metrics.ContentMatches.Add(1)
	}

	// Update average latency diff
	if primary.latency > 0 && shadow.latency > 0 {
		diff := shadow.latency - primary.latency
		se.metrics.AvgLatencyDiff.Store(diff.Microseconds())
	}

	if se.config.LogDiffs && !sr.ContentMatch {
		slog.Info("shadow content mismatch",
			"primary_provider", sr.PrimaryProvider,
			"shadow_provider", sr.ShadowProvider,
			"primary_model", sr.PrimaryModel,
			"shadow_model", sr.ShadowModel,
			"primary_tokens", sr.PrimaryTokens,
			"shadow_tokens", sr.ShadowTokens,
		)
	}

	// Non-blocking send to results channel
	select {
	case se.results <- sr:
	default:
		// Channel full, drop result
	}
}

// contentMatch returns true if both responses have the same first choice content.
func (se *ShadowExecutor) contentMatch(primary, shadow *ChatCompletionResponse) bool {
	if primary == nil || shadow == nil {
		return primary == nil && shadow == nil
	}
	pContent := responseContent(primary)
	sContent := responseContent(shadow)
	return pContent == sContent
}

// responseContent extracts the text content from the first choice of a response.
func responseContent(resp *ChatCompletionResponse) string {
	if resp == nil || len(resp.Choices) == 0 {
		return ""
	}
	return resp.Choices[0].Message.ContentString()
}
