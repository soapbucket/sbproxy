package policy

import (
	"context"
	"fmt"
	"sync"
)

// AsyncGuardrailTracker tracks async guardrail results.
type AsyncGuardrailTracker struct {
	mu       sync.Mutex
	pending  map[string]*asyncGuardrailJob
	results  chan *GuardrailResult
	maxAsync int
}

type asyncGuardrailJob struct {
	guardrailID string
	cancel      context.CancelFunc
	done        chan struct{}
}

// NewAsyncGuardrailTracker creates a tracker with a max concurrency limit.
func NewAsyncGuardrailTracker(maxAsync int) *AsyncGuardrailTracker {
	if maxAsync <= 0 {
		maxAsync = 10
	}
	return &AsyncGuardrailTracker{
		pending:  make(map[string]*asyncGuardrailJob),
		results:  make(chan *GuardrailResult, maxAsync),
		maxAsync: maxAsync,
	}
}

// Submit launches an async guardrail evaluation.
func (at *AsyncGuardrailTracker) Submit(ctx context.Context, config *GuardrailConfig, detector GuardrailDetector, content string) {
	at.mu.Lock()
	if len(at.pending) >= at.maxAsync {
		at.mu.Unlock()
		return
	}

	jobCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	job := &asyncGuardrailJob{
		guardrailID: config.ID,
		cancel:      cancel,
		done:        done,
	}
	at.pending[config.ID] = job
	at.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Send an error result on panic.
				at.results <- &GuardrailResult{
					GuardrailID: config.ID,
					Name:        config.Name,
					Action:      config.Action,
					Async:       true,
					Details:     fmt.Sprintf("panic: %v", r),
				}
			}
			close(done)
			at.mu.Lock()
			delete(at.pending, config.ID)
			at.mu.Unlock()
		}()

		result, err := detector.Detect(jobCtx, config, content)
		if err != nil {
			// On error, send a non-triggered result with error details.
			at.results <- &GuardrailResult{
				GuardrailID: config.ID,
				Name:        config.Name,
				Action:      config.Action,
				Async:       true,
				Details:     fmt.Sprintf("error: %v", err),
			}
			return
		}

		result.Async = true
		at.results <- result
	}()
}

// Results returns the channel of completed async results.
func (at *AsyncGuardrailTracker) Results() <-chan *GuardrailResult {
	return at.results
}

// PendingCount returns the number of still-running async guardrails.
func (at *AsyncGuardrailTracker) PendingCount() int {
	at.mu.Lock()
	defer at.mu.Unlock()
	return len(at.pending)
}

// CancelAll cancels all pending async guardrails.
func (at *AsyncGuardrailTracker) CancelAll() {
	at.mu.Lock()
	defer at.mu.Unlock()
	for _, job := range at.pending {
		job.cancel()
	}
}

// BuildAsyncHeaders creates response headers for async guardrail results.
func BuildAsyncHeaders(results []*GuardrailResult) map[string]string {
	headers := make(map[string]string)
	if len(results) == 0 {
		return headers
	}

	var flagged []string
	var blocked []string
	for _, r := range results {
		if r.Triggered {
			switch r.Action {
			case GuardrailActionBlock:
				blocked = append(blocked, r.GuardrailID)
			case GuardrailActionFlag:
				flagged = append(flagged, r.GuardrailID)
			}
		}
	}

	if len(flagged) > 0 {
		headers["X-Guardrail-Flagged"] = joinIDs(flagged)
	}
	if len(blocked) > 0 {
		headers["X-Guardrail-Blocked"] = joinIDs(blocked)
	}

	return headers
}

func joinIDs(ids []string) string {
	result := ""
	for i, id := range ids {
		if i > 0 {
			result += ","
		}
		result += id
	}
	return result
}
