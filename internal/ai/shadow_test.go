package ai

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func makeTestResponse(content string, totalTokens int) *ChatCompletionResponse {
	finish := "stop"
	return &ChatCompletionResponse{
		ID:      "chatcmpl-test",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "gpt-4o",
		Choices: []Choice{
			{
				Index:        0,
				Message:      mustTextMessage("assistant", content),
				FinishReason: &finish,
			},
		},
		Usage: &Usage{
			PromptTokens:     10,
			CompletionTokens: totalTokens - 10,
			TotalTokens:      totalTokens,
		},
	}
}

func TestShadow_ExecuteWithShadow(t *testing.T) {
	var primaryCalled, shadowCalled atomic.Bool

	exec := func(_ context.Context, _ *ChatCompletionRequest, provider string, _ string) (*ChatCompletionResponse, error) {
		if provider == "primary" {
			primaryCalled.Store(true)
			return makeTestResponse("hello", 20), nil
		}
		shadowCalled.Store(true)
		return makeTestResponse("hello shadow", 25), nil
	}

	se := NewShadowExecutor(ShadowConfig{
		Enabled:        true,
		ShadowProvider: "shadow",
		SampleRate:     1.0,
		AsyncCompare:   false,
	}, exec)

	req := &ChatCompletionRequest{Model: "gpt-4o"}
	resp, err := se.Execute(context.Background(), req, "primary", "gpt-4o")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if !primaryCalled.Load() {
		t.Error("primary was not called")
	}
	if !shadowCalled.Load() {
		t.Error("shadow was not called")
	}
}

func TestShadow_PrimaryOnlyReturned(t *testing.T) {
	exec := func(_ context.Context, _ *ChatCompletionRequest, provider string, _ string) (*ChatCompletionResponse, error) {
		if provider == "primary" {
			return makeTestResponse("primary response", 20), nil
		}
		return makeTestResponse("shadow response", 30), nil
	}

	se := NewShadowExecutor(ShadowConfig{
		Enabled:        true,
		ShadowProvider: "shadow",
		SampleRate:     1.0,
		AsyncCompare:   false,
	}, exec)

	req := &ChatCompletionRequest{Model: "gpt-4o"}
	resp, err := se.Execute(context.Background(), req, "primary", "gpt-4o")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify we got the primary response, not the shadow
	content := resp.Choices[0].Message.ContentString()
	if content != "primary response" {
		t.Errorf("expected primary response, got %q", content)
	}
}

func TestShadow_SampleRate_Zero(t *testing.T) {
	var shadowCalled atomic.Bool

	exec := func(_ context.Context, _ *ChatCompletionRequest, provider string, _ string) (*ChatCompletionResponse, error) {
		if provider == "shadow" {
			shadowCalled.Store(true)
		}
		return makeTestResponse("hello", 20), nil
	}

	se := NewShadowExecutor(ShadowConfig{
		Enabled:        true,
		ShadowProvider: "shadow",
		SampleRate:     0.0,
	}, exec)

	req := &ChatCompletionRequest{Model: "gpt-4o"}
	for i := 0; i < 100; i++ {
		_, _ = se.Execute(context.Background(), req, "primary", "gpt-4o")
	}

	if shadowCalled.Load() {
		t.Error("shadow should not have been called with sample rate 0")
	}
}

func TestShadow_SampleRate_Full(t *testing.T) {
	var shadowCount atomic.Int64

	exec := func(_ context.Context, _ *ChatCompletionRequest, provider string, _ string) (*ChatCompletionResponse, error) {
		if provider == "shadow" {
			shadowCount.Add(1)
		}
		return makeTestResponse("hello", 20), nil
	}

	se := NewShadowExecutor(ShadowConfig{
		Enabled:        true,
		ShadowProvider: "shadow",
		SampleRate:     1.0,
		AsyncCompare:   false,
	}, exec)

	req := &ChatCompletionRequest{Model: "gpt-4o"}
	for i := 0; i < 10; i++ {
		_, _ = se.Execute(context.Background(), req, "primary", "gpt-4o")
	}

	if shadowCount.Load() != 10 {
		t.Errorf("expected 10 shadow calls, got %d", shadowCount.Load())
	}
}

func TestShadow_ShadowError(t *testing.T) {
	exec := func(_ context.Context, _ *ChatCompletionRequest, provider string, _ string) (*ChatCompletionResponse, error) {
		if provider == "shadow" {
			return nil, errors.New("shadow provider failed")
		}
		return makeTestResponse("primary ok", 20), nil
	}

	se := NewShadowExecutor(ShadowConfig{
		Enabled:        true,
		ShadowProvider: "shadow",
		SampleRate:     1.0,
		AsyncCompare:   false,
	}, exec)

	req := &ChatCompletionRequest{Model: "gpt-4o"}
	resp, err := se.Execute(context.Background(), req, "primary", "gpt-4o")
	if err != nil {
		t.Fatalf("primary should succeed even when shadow fails: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}

	content := resp.Choices[0].Message.ContentString()
	if content != "primary ok" {
		t.Errorf("expected 'primary ok', got %q", content)
	}

	// Check shadow error was tracked
	if se.metrics.ShadowErrors.Load() != 1 {
		t.Errorf("expected 1 shadow error, got %d", se.metrics.ShadowErrors.Load())
	}
}

func TestShadow_ContentMatch(t *testing.T) {
	exec := func(_ context.Context, _ *ChatCompletionRequest, _ string, _ string) (*ChatCompletionResponse, error) {
		return makeTestResponse("identical", 20), nil
	}

	se := NewShadowExecutor(ShadowConfig{
		Enabled:        true,
		ShadowProvider: "shadow",
		SampleRate:     1.0,
		AsyncCompare:   false,
	}, exec)

	req := &ChatCompletionRequest{Model: "gpt-4o"}
	_, _ = se.Execute(context.Background(), req, "primary", "gpt-4o")

	if se.metrics.ContentMatches.Load() != 1 {
		t.Errorf("expected 1 content match, got %d", se.metrics.ContentMatches.Load())
	}

	// Read result from channel
	select {
	case sr := <-se.Results():
		if !sr.ContentMatch {
			t.Error("expected ContentMatch to be true")
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for shadow result")
	}
}

func TestShadow_ContentMismatch(t *testing.T) {
	exec := func(_ context.Context, _ *ChatCompletionRequest, provider string, _ string) (*ChatCompletionResponse, error) {
		if provider == "primary" {
			return makeTestResponse("answer A", 20), nil
		}
		return makeTestResponse("answer B", 22), nil
	}

	se := NewShadowExecutor(ShadowConfig{
		Enabled:        true,
		ShadowProvider: "shadow",
		SampleRate:     1.0,
		AsyncCompare:   false,
		LogDiffs:       true,
	}, exec)

	req := &ChatCompletionRequest{Model: "gpt-4o"}
	_, _ = se.Execute(context.Background(), req, "primary", "gpt-4o")

	if se.metrics.ContentMatches.Load() != 0 {
		t.Errorf("expected 0 content matches, got %d", se.metrics.ContentMatches.Load())
	}

	select {
	case sr := <-se.Results():
		if sr.ContentMatch {
			t.Error("expected ContentMatch to be false")
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for shadow result")
	}
}

func TestShadow_Metrics(t *testing.T) {
	exec := func(_ context.Context, _ *ChatCompletionRequest, _ string, _ string) (*ChatCompletionResponse, error) {
		return makeTestResponse("hello", 20), nil
	}

	se := NewShadowExecutor(ShadowConfig{
		Enabled:        true,
		ShadowProvider: "shadow",
		SampleRate:     1.0,
		AsyncCompare:   false,
	}, exec)

	req := &ChatCompletionRequest{Model: "gpt-4o"}
	for i := 0; i < 5; i++ {
		_, _ = se.Execute(context.Background(), req, "primary", "gpt-4o")
	}

	m := se.Metrics()
	if m.TotalShadowed.Load() != 5 {
		t.Errorf("expected 5 total shadowed, got %d", m.TotalShadowed.Load())
	}
	if m.ContentMatches.Load() != 5 {
		t.Errorf("expected 5 content matches, got %d", m.ContentMatches.Load())
	}
	if m.ShadowErrors.Load() != 0 {
		t.Errorf("expected 0 shadow errors, got %d", m.ShadowErrors.Load())
	}
}

func TestShadow_AsyncCompare(t *testing.T) {
	exec := func(_ context.Context, _ *ChatCompletionRequest, provider string, _ string) (*ChatCompletionResponse, error) {
		if provider == "shadow" {
			time.Sleep(10 * time.Millisecond) // Shadow is slightly slower
		}
		return makeTestResponse("hello", 20), nil
	}

	se := NewShadowExecutor(ShadowConfig{
		Enabled:        true,
		ShadowProvider: "shadow",
		SampleRate:     1.0,
		AsyncCompare:   true,
	}, exec)

	req := &ChatCompletionRequest{Model: "gpt-4o"}
	resp, err := se.Execute(context.Background(), req, "primary", "gpt-4o")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}

	// Result should eventually arrive on the channel
	select {
	case sr := <-se.Results():
		if sr.PrimaryProvider != "primary" {
			t.Errorf("expected primary provider, got %q", sr.PrimaryProvider)
		}
		if sr.ShadowProvider != "shadow" {
			t.Errorf("expected shadow provider, got %q", sr.ShadowProvider)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for async shadow result")
	}
}

func TestShadow_ConcurrentAccess(t *testing.T) {
	exec := func(_ context.Context, _ *ChatCompletionRequest, _ string, _ string) (*ChatCompletionResponse, error) {
		return makeTestResponse("hello", 20), nil
	}

	se := NewShadowExecutor(ShadowConfig{
		Enabled:        true,
		ShadowProvider: "shadow",
		SampleRate:     1.0,
		AsyncCompare:   false,
	}, exec)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := &ChatCompletionRequest{Model: "gpt-4o-" + strconv.Itoa(idx)}
			resp, err := se.Execute(context.Background(), req, "primary", "gpt-4o")
			if err != nil {
				t.Errorf("request %d failed: %v", idx, err)
			}
			if resp == nil {
				t.Errorf("request %d returned nil", idx)
			}
		}(i)
	}
	wg.Wait()

	m := se.Metrics()
	if m.TotalShadowed.Load() != 50 {
		t.Errorf("expected 50 total shadowed, got %d", m.TotalShadowed.Load())
	}
}
