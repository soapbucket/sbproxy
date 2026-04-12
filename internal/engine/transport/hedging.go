// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// HedgingConfig configures request hedging behavior
type HedgingConfig struct {
	Enabled bool `json:"enabled"`

	// Delay before sending hedge request
	Delay time.Duration `json:"delay"`

	// Maximum number of hedge requests (1-3 typical)
	MaxHedges int `json:"max_hedges"`

	// Percentile threshold - only hedge if request is slower than this percentile
	// Example: 0.95 means hedge if request is slower than 95% of historical requests
	PercentileThreshold float64 `json:"percentile_threshold,omitempty"`

	// Only hedge on specific HTTP methods
	Methods []string `json:"methods,omitempty"`

	// Cost tracking - warn if hedging is too expensive
	MaxCostRatio float64 `json:"max_cost_ratio,omitempty"` // Max ratio of hedged/total requests
}

// HedgingTransport implements request hedging to reduce tail latency
type HedgingTransport struct {
	base   http.RoundTripper
	config HedgingConfig
	stats  HedgingStats
}

// HedgingStats tracks hedging statistics
type HedgingStats struct {
	TotalRequests   uint64 // Total requests
	HedgedRequests  uint64 // Requests that triggered hedging
	HedgeWins       uint64 // Times hedge request won
	PrimaryWins     uint64 // Times primary request won
	TotalTimeSaved  int64  // Total milliseconds saved (can be negative)
	HedgeCanceled   uint64 // Hedge requests canceled
	PrimaryCanceled uint64 // Primary requests canceled (hedge won)
}

// NewHedgingTransport creates a new hedging transport
func NewHedgingTransport(base http.RoundTripper, config HedgingConfig) (*HedgingTransport, error) {
	if base == nil {
		return nil, fmt.Errorf("base transport cannot be nil")
	}

	// Validate config
	if config.Delay == 0 {
		config.Delay = 100 * time.Millisecond // Default 100ms
	}
	if config.MaxHedges == 0 {
		config.MaxHedges = 1 // Default to 1 hedge request
	}
	if config.MaxHedges > 3 {
		config.MaxHedges = 3 // Cap at 3 to prevent excessive requests
	}
	if config.MaxCostRatio == 0 {
		config.MaxCostRatio = 0.2 // Default: max 20% hedged requests
	}

	return &HedgingTransport{
		base:   base,
		config: config,
	}, nil
}

// RoundTrip implements http.RoundTripper with request hedging
func (t *HedgingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddUint64(&t.stats.TotalRequests, 1)

	if !t.config.Enabled {
		return t.base.RoundTrip(req)
	}

	// Check if method is eligible for hedging
	if len(t.config.Methods) > 0 && !t.isMethodAllowed(req.Method) {
		return t.base.RoundTrip(req)
	}

	// Check cost ratio - if too many hedged requests, skip hedging
	if t.shouldSkipDueToCost() {
		slog.Debug("hedging: skipping due to cost ratio",
			"max_ratio", t.config.MaxCostRatio,
			"current_ratio", t.getCurrentCostRatio())
		return t.base.RoundTrip(req)
	}

	// Hedging requires replayable request bodies.
	if req.Body != nil && req.GetBody == nil {
		return t.base.RoundTrip(req)
	}

	// Execute hedged request
	return t.executeWithHedging(req)
}

func cloneRequestWithContext(req *http.Request, ctx context.Context) (*http.Request, error) {
	cloned := req.Clone(ctx)
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		cloned.Body = body
	}
	return cloned, nil
}

func (t *HedgingTransport) executeWithHedging(req *http.Request) (*http.Response, error) {
	atomic.AddUint64(&t.stats.HedgedRequests, 1)

	// Create contexts for cancellation
	primaryCtx, primaryCancel := context.WithCancel(req.Context())
	hedgeCtx, hedgeCancel := context.WithCancel(req.Context())

	defer primaryCancel()
	defer hedgeCancel()

	primaryReq, err := cloneRequestWithContext(req, primaryCtx)
	if err != nil {
		return nil, err
	}

	type result struct {
		resp      *http.Response
		err       error
		isPrimary bool
		duration  time.Duration
	}

	results := make(chan result, t.config.MaxHedges+1)
	var wg sync.WaitGroup

	primaryStart := time.Now()

	// Send primary request
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := t.base.RoundTrip(primaryReq)
		duration := time.Since(primaryStart)

		select {
		case results <- result{resp: resp, err: err, isPrimary: true, duration: duration}:
			slog.Debug("hedging: primary request completed",
				"duration", duration,
				"status", getHedgeStatusCode(resp))
		case <-primaryCtx.Done():
			// Primary was canceled (hedge won)
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			slog.Debug("hedging: primary request canceled", "duration", duration)
		}
	}()

	// Start hedge requests after configured delay
	hedgeCount := 0
	hedgeTimer := time.NewTimer(t.config.Delay)
	defer hedgeTimer.Stop()

	// Variables to track which request wins
	var firstResult result
	var once sync.Once

	// Goroutine to send hedge requests
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Panic recovery to prevent goroutine panics from crashing the proxy
		defer func() {
			if r := recover(); r != nil {
				slog.Error("hedging: hedge dispatcher goroutine panicked",
					"panic", r)
			}
		}()

		select {
		case <-hedgeTimer.C:
		case <-primaryCtx.Done():
			return
		case <-hedgeCtx.Done():
			return
		}

		for hedgeCount < t.config.MaxHedges {
			// Check if primary has already completed
			select {
			case <-primaryCtx.Done():
				return
			default:
			}

			hedgeCount++
			hedgeStart := time.Now()

			wg.Add(1)
			go func(hedgeNum int) {
				defer wg.Done()
				// Panic recovery to prevent goroutine panics from crashing the proxy
				defer func() {
					if r := recover(); r != nil {
						slog.Error("hedging goroutine panicked",
							"hedge_num", hedgeNum,
							"panic", r)
						select {
						case results <- result{resp: nil, err: fmt.Errorf("hedge goroutine panic: %v", r), isPrimary: false, duration: 0}:
						case <-hedgeCtx.Done():
						}
					}
				}()

				hedgeReq, err := cloneRequestWithContext(req, hedgeCtx)
				if err != nil {
					select {
					case results <- result{resp: nil, err: err, isPrimary: false, duration: 0}:
					case <-hedgeCtx.Done():
					}
					return
				}

				slog.Debug("hedging: sending hedge request",
					"hedge_num", hedgeNum,
					"delay", time.Since(primaryStart))

				resp, err := t.base.RoundTrip(hedgeReq)
				duration := time.Since(hedgeStart)

				select {
				case results <- result{resp: resp, err: err, isPrimary: false, duration: duration}:
					slog.Debug("hedging: hedge request completed",
						"hedge_num", hedgeNum,
						"duration", duration,
						"status", getHedgeStatusCode(resp))
				case <-hedgeCtx.Done():
					// Hedge was canceled (primary won)
					if resp != nil && resp.Body != nil {
						resp.Body.Close()
					}
					slog.Debug("hedging: hedge request canceled",
						"hedge_num", hedgeNum,
						"duration", duration)
				}
			}(hedgeCount)

			// Wait for next hedge delay (exponential backoff), context-aware
			if hedgeCount < t.config.MaxHedges {
				select {
				case <-time.After(t.config.Delay):
				case <-hedgeCtx.Done():
					return
				case <-primaryCtx.Done():
					return
				}
			}
		}
	}()

	// Wait for first successful result
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results as they arrive
	for res := range results {
		// Only use the first successful result
		once.Do(func() {
			firstResult = res

			// Cancel all other requests
			if res.isPrimary {
				hedgeCancel()
				atomic.AddUint64(&t.stats.PrimaryWins, 1)
				atomic.AddUint64(&t.stats.HedgeCanceled, uint64(hedgeCount))

				slog.Info("hedging: primary won",
					"duration", res.duration,
					"hedges_sent", hedgeCount)
			} else {
				primaryCancel()
				atomic.AddUint64(&t.stats.HedgeWins, 1)
				atomic.AddUint64(&t.stats.PrimaryCanceled, 1)

				// Calculate time saved
				timeSaved := time.Since(primaryStart) - res.duration
				atomic.AddInt64(&t.stats.TotalTimeSaved, timeSaved.Milliseconds())

				slog.Info("hedging: hedge won",
					"duration", res.duration,
					"time_saved", timeSaved,
					"primary_duration_so_far", time.Since(primaryStart))
			}
		})

		// Close any additional responses
		if res.resp != nil && res.resp.Body != nil && res != firstResult {
			res.resp.Body.Close()
		}
	}

	return firstResult.resp, firstResult.err
}

func (t *HedgingTransport) isMethodAllowed(method string) bool {
	for _, m := range t.config.Methods {
		if m == method {
			return true
		}
	}
	return false
}

func (t *HedgingTransport) shouldSkipDueToCost() bool {
	ratio := t.getCurrentCostRatio()
	return ratio > t.config.MaxCostRatio
}

func (t *HedgingTransport) getCurrentCostRatio() float64 {
	total := atomic.LoadUint64(&t.stats.TotalRequests)
	if total == 0 {
		return 0.0
	}
	hedged := atomic.LoadUint64(&t.stats.HedgedRequests)
	return float64(hedged) / float64(total)
}

// GetStats returns hedging statistics
func (t *HedgingTransport) GetStats() HedgingStats {
	return HedgingStats{
		TotalRequests:   atomic.LoadUint64(&t.stats.TotalRequests),
		HedgedRequests:  atomic.LoadUint64(&t.stats.HedgedRequests),
		HedgeWins:       atomic.LoadUint64(&t.stats.HedgeWins),
		PrimaryWins:     atomic.LoadUint64(&t.stats.PrimaryWins),
		TotalTimeSaved:  atomic.LoadInt64(&t.stats.TotalTimeSaved),
		HedgeCanceled:   atomic.LoadUint64(&t.stats.HedgeCanceled),
		PrimaryCanceled: atomic.LoadUint64(&t.stats.PrimaryCanceled),
	}
}

// String returns a formatted string representation of stats
func (s HedgingStats) String() string {
	if s.TotalRequests == 0 {
		return "No requests"
	}

	hedgedPct := float64(s.HedgedRequests) / float64(s.TotalRequests) * 100
	hedgeWinRate := float64(0)
	if s.HedgedRequests > 0 {
		hedgeWinRate = float64(s.HedgeWins) / float64(s.HedgedRequests) * 100
	}
	avgTimeSaved := float64(0)
	if s.HedgeWins > 0 {
		avgTimeSaved = float64(s.TotalTimeSaved) / float64(s.HedgeWins)
	}

	return fmt.Sprintf(
		"Total: %d, Hedged: %d (%.1f%%), Hedge Wins: %d (%.1f%%), Primary Wins: %d, Avg Time Saved: %.0fms, Total Time Saved: %dms",
		s.TotalRequests,
		s.HedgedRequests, hedgedPct,
		s.HedgeWins, hedgeWinRate,
		s.PrimaryWins,
		avgTimeSaved,
		s.TotalTimeSaved,
	)
}

// EffectiveLatencyReduction calculates the effective latency reduction percentage
func (s HedgingStats) EffectiveLatencyReduction() float64 {
	if s.HedgeWins == 0 {
		return 0.0
	}
	// Estimate: if hedges save time, what's the average reduction?
	// This is a simplified calculation
	avgTimeSaved := float64(s.TotalTimeSaved) / float64(s.HedgeWins)
	// Assume average request time is 100ms + time saved
	estimatedAvgRequest := 100.0 + avgTimeSaved
	if estimatedAvgRequest <= 0 {
		return 0.0
	}
	return (avgTimeSaved / estimatedAvgRequest) * 100.0
}

// CostMultiplier calculates the cost multiplier (how many extra requests)
func (s HedgingStats) CostMultiplier() float64 {
	if s.TotalRequests == 0 {
		return 1.0
	}
	// Total requests sent = TotalRequests + HedgeWins (hedge completed) + HedgeCanceled (hedge canceled)
	totalSent := s.TotalRequests + s.HedgeWins + s.HedgeCanceled
	return float64(totalSent) / float64(s.TotalRequests)
}

func getHedgeStatusCode(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}
