// Package guardrails provides safety guardrail implementations for AI requests.
package guardrails

import (
	"context"
	"fmt"

	"github.com/soapbucket/sbproxy/internal/ai"
)

// ParallelGuardrail runs a guardrail check and an LLM call concurrently.
// If the guardrail fails before the LLM responds, the LLM call is cancelled
// and the guardrail error is returned. If the LLM responds first, the guardrail
// is cancelled and the LLM response is returned immediately.
//
// This enables "during-call" guardrails that race against the LLM provider,
// reducing total latency compared to sequential pre-check + call patterns.
func ParallelGuardrail(
	ctx context.Context,
	req *ai.ChatCompletionRequest,
	guard func(context.Context, *ai.ChatCompletionRequest) error,
	llmCall func() (*ai.ChatCompletionResponse, error),
) (*ai.ChatCompletionResponse, error) {
	guardCtx, guardCancel := context.WithCancel(ctx)
	defer guardCancel()

	llmCtx, llmCancel := context.WithCancel(ctx)
	defer llmCancel()

	type guardResult struct {
		err error
	}
	type llmResult struct {
		resp *ai.ChatCompletionResponse
		err  error
	}

	guardCh := make(chan guardResult, 1)
	llmCh := make(chan llmResult, 1)

	// Run guardrail check
	go func() {
		err := guard(guardCtx, req)
		guardCh <- guardResult{err: err}
	}()

	// Run LLM call
	go func() {
		resp, err := llmCall()
		llmCh <- llmResult{resp: resp, err: err}
	}()

	// Wait for whichever finishes first
	for {
		select {
		case gr := <-guardCh:
			if gr.err != nil {
				// Guardrail failed - cancel the LLM call and return error
				llmCancel()
				return nil, fmt.Errorf("guardrail blocked: %w", gr.err)
			}
			// Guardrail passed - wait for LLM to complete
			lr := <-llmCh
			return lr.resp, lr.err

		case lr := <-llmCh:
			// LLM finished first - cancel the guardrail
			guardCancel()
			if lr.err != nil {
				return nil, lr.err
			}
			return lr.resp, nil

		case <-llmCtx.Done():
			// Parent context cancelled
			return nil, llmCtx.Err()
		}
	}
}
