package policy

import (
	"context"
	"testing"
	"time"
)

// slowDetector simulates a detector that takes time to run.
type slowDetector struct {
	delay   time.Duration
	trigger bool
}

func (sd *slowDetector) Detect(ctx context.Context, config *GuardrailConfig, _ string) (*GuardrailResult, error) {
	select {
	case <-time.After(sd.delay):
	case <-ctx.Done():
		return &GuardrailResult{
			GuardrailID: config.ID,
			Name:        config.Name,
			Action:      config.Action,
			Details:     "cancelled",
		}, ctx.Err()
	}
	return &GuardrailResult{
		GuardrailID: config.ID,
		Name:        config.Name,
		Triggered:   sd.trigger,
		Action:      config.Action,
	}, nil
}

func TestAsyncTracker_Submit(t *testing.T) {
	tracker := NewAsyncGuardrailTracker(5)

	cfg := &GuardrailConfig{
		ID:     "async-1",
		Name:   "slow-check",
		Action: GuardrailActionFlag,
	}
	detector := &slowDetector{delay: 10 * time.Millisecond, trigger: true}

	tracker.Submit(context.Background(), cfg, detector, "test content")

	// Wait for result.
	select {
	case result := <-tracker.Results():
		if result.GuardrailID != "async-1" {
			t.Errorf("expected guardrail_id async-1, got %s", result.GuardrailID)
		}
		if !result.Triggered {
			t.Error("expected triggered=true")
		}
		if !result.Async {
			t.Error("expected async=true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for async result")
	}
}

func TestAsyncTracker_Results(t *testing.T) {
	tracker := NewAsyncGuardrailTracker(10)

	for i := 0; i < 3; i++ {
		cfg := &GuardrailConfig{
			ID:     "async-" + string(rune('a'+i)),
			Name:   "check",
			Action: GuardrailActionFlag,
		}
		tracker.Submit(context.Background(), cfg, &slowDetector{delay: 5 * time.Millisecond, trigger: true}, "content")
	}

	received := 0
	timeout := time.After(2 * time.Second)
	for received < 3 {
		select {
		case <-tracker.Results():
			received++
		case <-timeout:
			t.Fatalf("timed out, only received %d/3 results", received)
		}
	}
}

func TestAsyncTracker_CancelAll(t *testing.T) {
	tracker := NewAsyncGuardrailTracker(5)

	cfg := &GuardrailConfig{
		ID:     "cancel-me",
		Name:   "slow-check",
		Action: GuardrailActionBlock,
	}
	// Use a long delay so we can cancel before it finishes.
	detector := &slowDetector{delay: 5 * time.Second, trigger: true}

	tracker.Submit(context.Background(), cfg, detector, "content")

	// Give the goroutine a moment to start.
	time.Sleep(10 * time.Millisecond)

	tracker.CancelAll()

	// The result should arrive with an error (cancelled context).
	select {
	case result := <-tracker.Results():
		// We expect a result with error details from cancellation.
		if result.GuardrailID != "cancel-me" {
			t.Errorf("expected cancel-me, got %s", result.GuardrailID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for cancelled result")
	}
}

func TestAsyncTracker_PendingCount(t *testing.T) {
	tracker := NewAsyncGuardrailTracker(10)

	for i := 0; i < 3; i++ {
		cfg := &GuardrailConfig{
			ID:     "pending-" + string(rune('a'+i)),
			Name:   "slow",
			Action: GuardrailActionFlag,
		}
		tracker.Submit(context.Background(), cfg, &slowDetector{delay: 200 * time.Millisecond, trigger: false}, "content")
	}

	// Pending count should be > 0 immediately after submit.
	time.Sleep(5 * time.Millisecond)
	count := tracker.PendingCount()
	if count == 0 {
		t.Error("expected pending count > 0 right after submit")
	}

	// Wait for all to finish.
	for i := 0; i < 3; i++ {
		select {
		case <-tracker.Results():
		case <-time.After(2 * time.Second):
			t.Fatal("timed out")
		}
	}

	// Give goroutines a moment to clean up pending map.
	time.Sleep(50 * time.Millisecond)
	count = tracker.PendingCount()
	if count != 0 {
		t.Errorf("expected pending count 0 after all done, got %d", count)
	}
}

func TestBuildAsyncHeaders(t *testing.T) {
	results := []*GuardrailResult{
		{GuardrailID: "g1", Triggered: true, Action: GuardrailActionFlag},
		{GuardrailID: "g2", Triggered: false, Action: GuardrailActionBlock},
		{GuardrailID: "g3", Triggered: true, Action: GuardrailActionBlock},
	}

	headers := BuildAsyncHeaders(results)

	if headers["X-Guardrail-Flagged"] != "g1" {
		t.Errorf("expected flagged=g1, got %s", headers["X-Guardrail-Flagged"])
	}
	if headers["X-Guardrail-Blocked"] != "g3" {
		t.Errorf("expected blocked=g3, got %s", headers["X-Guardrail-Blocked"])
	}

	// Empty results produce empty headers.
	empty := BuildAsyncHeaders(nil)
	if len(empty) != 0 {
		t.Errorf("expected empty headers, got %v", empty)
	}
}
