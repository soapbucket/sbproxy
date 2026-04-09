package guardrails

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func TestParallelGuardrail_GuardrailFailsFirst(t *testing.T) {
	req := &ai.ChatCompletionRequest{Model: "gpt-4o"}

	guard := func(ctx context.Context, _ *ai.ChatCompletionRequest) error {
		// Guardrail fails immediately
		return errors.New("content policy violation")
	}

	var llmCancelled atomic.Bool
	llmCall := func() (*ai.ChatCompletionResponse, error) {
		// Simulate slow LLM
		time.Sleep(500 * time.Millisecond)
		llmCancelled.Store(true)
		return &ai.ChatCompletionResponse{ID: "should-not-return"}, nil
	}

	resp, err := ParallelGuardrail(context.Background(), req, guard, llmCall)
	if resp != nil {
		t.Error("expected nil response when guardrail blocks")
	}
	if err == nil {
		t.Fatal("expected error when guardrail blocks")
	}
	if !errors.Is(err, errors.Unwrap(err)) && err.Error() != "guardrail blocked: content policy violation" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParallelGuardrail_LLMFinishesFirst(t *testing.T) {
	req := &ai.ChatCompletionRequest{Model: "gpt-4o"}

	guard := func(ctx context.Context, _ *ai.ChatCompletionRequest) error {
		// Slow guardrail
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
			return nil
		}
	}

	expectedResp := &ai.ChatCompletionResponse{ID: "fast-llm-response"}
	llmCall := func() (*ai.ChatCompletionResponse, error) {
		// LLM responds immediately
		return expectedResp, nil
	}

	resp, err := ParallelGuardrail(context.Background(), req, guard, llmCall)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.ID != "fast-llm-response" {
		t.Errorf("expected response ID 'fast-llm-response', got %q", resp.ID)
	}
}

func TestParallelGuardrail_BothPass(t *testing.T) {
	req := &ai.ChatCompletionRequest{Model: "gpt-4o"}

	guard := func(ctx context.Context, _ *ai.ChatCompletionRequest) error {
		// Guardrail passes quickly
		return nil
	}

	expectedResp := &ai.ChatCompletionResponse{ID: "llm-response"}
	llmCall := func() (*ai.ChatCompletionResponse, error) {
		time.Sleep(50 * time.Millisecond)
		return expectedResp, nil
	}

	resp, err := ParallelGuardrail(context.Background(), req, guard, llmCall)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.ID != "llm-response" {
		t.Errorf("expected response ID 'llm-response', got %q", resp.ID)
	}
}

func TestParallelGuardrail_LLMError(t *testing.T) {
	req := &ai.ChatCompletionRequest{Model: "gpt-4o"}

	guard := func(ctx context.Context, _ *ai.ChatCompletionRequest) error {
		// Slow guardrail
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	llmCall := func() (*ai.ChatCompletionResponse, error) {
		return nil, errors.New("provider timeout")
	}

	resp, err := ParallelGuardrail(context.Background(), req, guard, llmCall)
	if resp != nil {
		t.Error("expected nil response on LLM error")
	}
	if err == nil {
		t.Fatal("expected error on LLM failure")
	}
	if err.Error() != "provider timeout" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParallelGuardrail_CancellationPropagation(t *testing.T) {
	req := &ai.ChatCompletionRequest{Model: "gpt-4o"}

	ctx, cancel := context.WithCancel(context.Background())

	var guardCancelled atomic.Bool

	guard := func(ctx context.Context, _ *ai.ChatCompletionRequest) error {
		select {
		case <-ctx.Done():
			guardCancelled.Store(true)
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return nil
		}
	}

	llmCall := func() (*ai.ChatCompletionResponse, error) {
		// Wait a bit, then the parent context should be cancelled
		time.Sleep(5 * time.Second)
		return &ai.ChatCompletionResponse{ID: "should-not-return"}, nil
	}

	// Cancel the parent context after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := ParallelGuardrail(ctx, req, guard, llmCall)
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
}

func TestParallelGuardrail_GuardrailPassThenLLMError(t *testing.T) {
	req := &ai.ChatCompletionRequest{Model: "gpt-4o"}

	guard := func(ctx context.Context, _ *ai.ChatCompletionRequest) error {
		// Guardrail passes immediately
		return nil
	}

	llmCall := func() (*ai.ChatCompletionResponse, error) {
		time.Sleep(50 * time.Millisecond)
		return nil, errors.New("rate limited")
	}

	resp, err := ParallelGuardrail(context.Background(), req, guard, llmCall)
	if resp != nil {
		t.Error("expected nil response on LLM error")
	}
	if err == nil || err.Error() != "rate limited" {
		t.Errorf("expected 'rate limited' error, got %v", err)
	}
}
