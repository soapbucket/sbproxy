package policy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	json "github.com/goccy/go-json"
)

// circuitState represents the state of a circuit breaker.
type circuitState int32

const (
	circuitClosed   circuitState = 0
	circuitOpen     circuitState = 1
	circuitHalfOpen circuitState = 2
)

const (
	// circuitBreakerThreshold is the number of consecutive failures before opening.
	circuitBreakerThreshold = 5
	// circuitBreakerCooldown is how long the circuit stays open before transitioning to half-open.
	circuitBreakerCooldown = 30 * time.Second
	// maxResponseBody limits how much of the response body we read.
	maxResponseBody = 1 << 20 // 1 MB
)

// CircuitBreaker tracks consecutive failures and prevents calls when open.
type CircuitBreaker struct {
	state           atomic.Int32
	consecutiveFails atomic.Int64
	lastFailTime    atomic.Int64 // unix nano
	mu              sync.Mutex
}

// NewCircuitBreaker creates a new circuit breaker in the closed state.
func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{}
}

// Allow checks whether a request is allowed through the circuit breaker.
// Returns true if the request should proceed.
func (cb *CircuitBreaker) Allow() bool {
	state := circuitState(cb.state.Load())
	switch state {
	case circuitClosed:
		return true
	case circuitOpen:
		// Check if cooldown has elapsed.
		lastFail := time.Unix(0, cb.lastFailTime.Load())
		if time.Since(lastFail) >= circuitBreakerCooldown {
			cb.mu.Lock()
			defer cb.mu.Unlock()
			// Transition to half-open (only one goroutine wins).
			if circuitState(cb.state.Load()) == circuitOpen {
				cb.state.Store(int32(circuitHalfOpen))
			}
			return true
		}
		return false
	case circuitHalfOpen:
		// Allow a single probe request.
		return true
	default:
		return true
	}
}

// RecordSuccess records a successful call and resets the circuit breaker.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.consecutiveFails.Store(0)
	cb.state.Store(int32(circuitClosed))
}

// RecordFailure records a failed call. Opens the circuit after the threshold is reached.
func (cb *CircuitBreaker) RecordFailure() {
	fails := cb.consecutiveFails.Add(1)
	cb.lastFailTime.Store(time.Now().UnixNano())
	if fails >= int64(circuitBreakerThreshold) {
		cb.state.Store(int32(circuitOpen))
	}
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() circuitState {
	return circuitState(cb.state.Load())
}

// ExternalGuardrail is a generic HTTP-based guardrail detector.
// It sends content to a configured URL and checks the response for a flagged field.
type ExternalGuardrail struct {
	client  *http.Client
	breaker *CircuitBreaker
}

// NewExternalGuardrail creates a new external guardrail detector.
func NewExternalGuardrail() *ExternalGuardrail {
	return &ExternalGuardrail{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		breaker: NewCircuitBreaker(),
	}
}

// Detect sends content to the external service and checks for flagging.
func (eg *ExternalGuardrail) Detect(ctx context.Context, config *GuardrailConfig, content string) (*GuardrailResult, error) {
	start := time.Now()
	result := &GuardrailResult{
		GuardrailID: config.ID,
		Name:        config.Name,
		Action:      config.Action,
		Async:       config.Async,
	}

	// Check circuit breaker.
	if !eg.breaker.Allow() {
		result.Latency = time.Since(start)
		result.Details = "circuit breaker open, skipping external guardrail"
		return result, nil
	}

	url, _ := config.Config["url"].(string)
	if url == "" {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("external guardrail %q: missing url in config", config.ID)
	}

	apiKey, _ := config.Config["api_key"].(string)
	method, _ := config.Config["method"].(string)
	if method == "" {
		method = http.MethodPost
	}

	// Build request body.
	body, err := json.Marshal(map[string]string{"text": content})
	if err != nil {
		eg.breaker.RecordFailure()
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("external guardrail %q: marshal error: %w", config.ID, err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		eg.breaker.RecordFailure()
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("external guardrail %q: request creation error: %w", config.ID, err)
	}

	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := eg.client.Do(req)
	if err != nil {
		eg.breaker.RecordFailure()
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("external guardrail %q: request failed: %w", config.ID, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		eg.breaker.RecordFailure()
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("external guardrail %q: read response error: %w", config.ID, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		eg.breaker.RecordFailure()
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("external guardrail %q: HTTP %d: %s", config.ID, resp.StatusCode, string(respBody))
	}

	// Parse response for "flagged" boolean field.
	var respData map[string]any
	if err := json.Unmarshal(respBody, &respData); err != nil {
		eg.breaker.RecordFailure()
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("external guardrail %q: parse response error: %w", config.ID, err)
	}

	eg.breaker.RecordSuccess()

	flagged, _ := respData["flagged"].(bool)
	result.Triggered = flagged
	if flagged {
		if details, ok := respData["details"].(string); ok {
			result.Details = details
		} else {
			result.Details = "flagged by external guardrail"
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}

// CircuitBreakerState returns the current state of the circuit breaker (for testing).
func (eg *ExternalGuardrail) CircuitBreakerState() circuitState {
	return eg.breaker.State()
}
