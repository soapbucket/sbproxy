// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai"
	"golang.org/x/sync/errgroup"
)

// Engine runs guardrails in order, short-circuiting on block.
type Engine struct {
	input    []guardrailWithAction
	output   []guardrailWithAction
	parallel bool
}

type guardrailWithAction struct {
	guardrail Guardrail
	action    Action
}

// NewEngine creates a guardrail engine from config.
func NewEngine(cfg *GuardrailsConfig) (*Engine, error) {
	if cfg == nil {
		return &Engine{}, nil
	}

	e := &Engine{parallel: cfg.Parallel}

	for _, entry := range cfg.Input {
		g, err := Create(entry.Type, entry.Config)
		if err != nil {
			return nil, err
		}
		action := entry.Action
		if action == "" {
			action = ActionBlock
		}
		e.input = append(e.input, guardrailWithAction{guardrail: g, action: action})
	}

	for _, entry := range cfg.Output {
		g, err := Create(entry.Type, entry.Config)
		if err != nil {
			return nil, err
		}
		action := entry.Action
		if action == "" {
			action = ActionBlock
		}
		e.output = append(e.output, guardrailWithAction{guardrail: g, action: action})
	}

	return e, nil
}

// RunInput executes all input guardrails in order.
// Returns the (possibly transformed) content, any blocking result, and flagged results.
func (e *Engine) RunInput(ctx context.Context, content *Content) (*Content, *Result, []*Result, error) {
	if e.parallel {
		return e.runParallel(ctx, content, e.input)
	}
	return e.run(ctx, content, e.input)
}

// RunOutput executes all output guardrails in order.
// Returns the (possibly transformed) content, any blocking result, and flagged results.
func (e *Engine) RunOutput(ctx context.Context, content *Content) (*Content, *Result, []*Result, error) {
	if e.parallel {
		return e.runParallel(ctx, content, e.output)
	}
	return e.run(ctx, content, e.output)
}

// HasInput returns true if there are input guardrails configured.
func (e *Engine) HasInput() bool {
	return len(e.input) > 0
}

// HasOutput returns true if there are output guardrails configured.
func (e *Engine) HasOutput() bool {
	return len(e.output) > 0
}

func (e *Engine) run(ctx context.Context, content *Content, guards []guardrailWithAction) (*Content, *Result, []*Result, error) {
	current := content
	var flagged []*Result

	for _, gwa := range guards {
		start := time.Now()
		result, err := gwa.guardrail.Check(ctx, current)
		if err != nil {
			return current, nil, nil, err
		}
		result.Latency = time.Since(start)
		result.Guardrail = gwa.guardrail.Name()
		ai.AIGuardrailDuration(gwa.guardrail.Name(), string(gwa.guardrail.Phase()), result.Latency.Seconds())

		if !result.Pass {
			result.Action = gwa.action
			switch gwa.action {
			case ActionBlock:
				return current, result, flagged, nil
			case ActionTransform:
				transformed, terr := gwa.guardrail.Transform(ctx, current)
				if terr != nil {
					return current, nil, nil, terr
				}
				current = transformed
			case ActionFlag:
				// Collect flagged results for header injection
				flagged = append(flagged, result)
				continue
			}
		}
	}
	return current, nil, flagged, nil
}

// runParallel executes guardrails concurrently using errgroup.
// It short-circuits on the first "block" action.
// Transform actions are collected and applied sequentially after all checks complete.
func (e *Engine) runParallel(ctx context.Context, content *Content, guards []guardrailWithAction) (*Content, *Result, []*Result, error) {
	if len(guards) == 0 {
		return content, nil, nil, nil
	}

	type indexedResult struct {
		index  int
		result *Result
		gwa    guardrailWithAction
	}

	results := make([]indexedResult, len(guards))
	var mu sync.Mutex
	var blockResult *Result

	eg, egCtx := errgroup.WithContext(ctx)

	for i, gwa := range guards {
		idx := i
		g := gwa
		eg.Go(func() error {
			// Check for early termination from another goroutine.
			select {
			case <-egCtx.Done():
				return egCtx.Err()
			default:
			}

			start := time.Now()
			result, err := g.guardrail.Check(egCtx, content)
			if err != nil {
				return err
			}
			result.Latency = time.Since(start)
			result.Guardrail = g.guardrail.Name()
			ai.AIGuardrailDuration(g.guardrail.Name(), string(g.guardrail.Phase()), result.Latency.Seconds())

			mu.Lock()
			results[idx] = indexedResult{index: idx, result: result, gwa: g}
			// Short-circuit on block action.
			if !result.Pass && g.action == ActionBlock && blockResult == nil {
				result.Action = ActionBlock
				blockResult = result
			}
			mu.Unlock()

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		// If context was cancelled due to short-circuit, check for block result.
		if blockResult != nil {
			return content, blockResult, nil, nil
		}
		return content, nil, nil, err
	}

	// If any guardrail blocked, return the first one by index order.
	if blockResult != nil {
		// Find the earliest block result by index.
		for _, ir := range results {
			if ir.result != nil && !ir.result.Pass && ir.gwa.action == ActionBlock {
				return content, ir.result, nil, nil
			}
		}
	}

	// Apply transforms and collect flags sequentially in order.
	current := content
	var flagged []*Result

	for _, ir := range results {
		if ir.result == nil {
			continue
		}
		if !ir.result.Pass {
			ir.result.Action = ir.gwa.action
			switch ir.gwa.action {
			case ActionTransform:
				transformed, terr := ir.gwa.guardrail.Transform(ctx, current)
				if terr != nil {
					return current, nil, nil, terr
				}
				current = transformed
			case ActionFlag:
				flagged = append(flagged, ir.result)
			}
		}
	}

	return current, nil, flagged, nil
}

// CheckContent runs specific guardrails by name against content (standalone API).
func (e *Engine) CheckContent(ctx context.Context, content *Content, guardrailNames []string, phase Phase) ([]*Result, error) {
	var results []*Result

	for _, name := range guardrailNames {
		g, err := Create(name, nil)
		if err != nil {
			return nil, err
		}
		if phase != "" && g.Phase() != phase {
			continue
		}

		start := time.Now()
		result, err := g.Check(ctx, content)
		if err != nil {
			return nil, err
		}
		result.Latency = time.Since(start)
		result.Guardrail = name
		results = append(results, result)
	}

	return results, nil
}
