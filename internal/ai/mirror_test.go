package ai

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrafficMirror_SampleRate(t *testing.T) {
	var mirrorCalls atomic.Int64

	exec := func(_ context.Context, _ *ChatCompletionRequest, _ string, _ string) (*ChatCompletionResponse, error) {
		mirrorCalls.Add(1)
		return &ChatCompletionResponse{ID: "mirror"}, nil
	}

	mirror := NewTrafficMirror(MirrorConfig{
		Enabled:     true,
		TargetModel: "test-model",
		SampleRate:  1.0, // Mirror all requests
	}, exec)

	if mirror == nil {
		t.Fatal("expected non-nil mirror with enabled config")
	}

	ctx := context.Background()
	req := &ChatCompletionRequest{Model: "gpt-4o"}

	// Fire multiple mirrors
	for i := 0; i < 10; i++ {
		mirror.MaybeMirror(ctx, req)
	}

	// Wait for async goroutines
	time.Sleep(100 * time.Millisecond)

	if got := mirror.Mirrored(); got != 10 {
		t.Errorf("expected 10 mirrored requests, got %d", got)
	}
}

func TestTrafficMirror_ZeroSampleRate(t *testing.T) {
	exec := func(_ context.Context, _ *ChatCompletionRequest, _ string, _ string) (*ChatCompletionResponse, error) {
		t.Error("executor should not be called with 0 sample rate")
		return nil, nil
	}

	mirror := NewTrafficMirror(MirrorConfig{
		Enabled:    true,
		SampleRate: 0.0,
	}, exec)

	if mirror != nil {
		t.Error("expected nil mirror with 0 sample rate")
	}
}

func TestTrafficMirror_Disabled(t *testing.T) {
	mirror := NewTrafficMirror(MirrorConfig{
		Enabled:    false,
		SampleRate: 1.0,
	}, nil)

	if mirror != nil {
		t.Error("expected nil mirror when disabled")
	}
}

func TestTrafficMirror_NoLatencyImpact(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)

	exec := func(_ context.Context, _ *ChatCompletionRequest, _ string, _ string) (*ChatCompletionResponse, error) {
		// Simulate a slow mirror target
		time.Sleep(200 * time.Millisecond)
		wg.Done()
		return &ChatCompletionResponse{ID: "mirror"}, nil
	}

	mirror := NewTrafficMirror(MirrorConfig{
		Enabled:     true,
		TargetModel: "slow-model",
		SampleRate:  1.0,
	}, exec)

	ctx := context.Background()
	req := &ChatCompletionRequest{Model: "gpt-4o"}

	start := time.Now()
	mirror.MaybeMirror(ctx, req)
	elapsed := time.Since(start)

	// MaybeMirror should return almost immediately (fire-and-forget)
	if elapsed > 50*time.Millisecond {
		t.Errorf("MaybeMirror took %v, expected near-instant return", elapsed)
	}

	// Wait for the background goroutine to complete
	wg.Wait()
}

func TestTrafficMirror_ErrorsDontPropagate(t *testing.T) {
	exec := func(_ context.Context, _ *ChatCompletionRequest, _ string, _ string) (*ChatCompletionResponse, error) {
		return nil, errors.New("provider error")
	}

	mirror := NewTrafficMirror(MirrorConfig{
		Enabled:     true,
		TargetModel: "bad-model",
		SampleRate:  1.0,
	}, exec)

	ctx := context.Background()
	req := &ChatCompletionRequest{Model: "gpt-4o"}

	// Should not panic or return an error
	mirror.MaybeMirror(ctx, req)

	// Wait for the async goroutine
	time.Sleep(50 * time.Millisecond)

	if got := mirror.Errors(); got != 1 {
		t.Errorf("expected 1 error, got %d", got)
	}
}

func TestTrafficMirror_NilSafety(t *testing.T) {
	var mirror *TrafficMirror

	// All methods should be safe on nil
	mirror.MaybeMirror(context.Background(), &ChatCompletionRequest{})
	if got := mirror.Mirrored(); got != 0 {
		t.Errorf("expected 0 mirrored on nil, got %d", got)
	}
	if got := mirror.Errors(); got != 0 {
		t.Errorf("expected 0 errors on nil, got %d", got)
	}
}

func TestTrafficMirror_TargetModelOverride(t *testing.T) {
	var capturedModel string
	var mu sync.Mutex

	exec := func(_ context.Context, req *ChatCompletionRequest, _ string, _ string) (*ChatCompletionResponse, error) {
		mu.Lock()
		capturedModel = req.Model
		mu.Unlock()
		return &ChatCompletionResponse{ID: "mirror"}, nil
	}

	mirror := NewTrafficMirror(MirrorConfig{
		Enabled:     true,
		TargetModel: "claude-sonnet-4-20250514",
		SampleRate:  1.0,
	}, exec)

	ctx := context.Background()
	req := &ChatCompletionRequest{Model: "gpt-4o"}

	mirror.MaybeMirror(ctx, req)
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if capturedModel != "claude-sonnet-4-20250514" {
		t.Errorf("expected mirror model claude-sonnet-4-20250514, got %q", capturedModel)
	}
	mu.Unlock()
}
