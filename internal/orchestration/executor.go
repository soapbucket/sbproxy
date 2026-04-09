// Package orchestration coordinates multi-step request processing workflows and action sequencing.
package orchestration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/config/callback"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	templateresolver "github.com/soapbucket/sbproxy/internal/template"
)

// Executor executes orchestration workflows
type Executor struct {
	steps           []Step
	parallel        bool
	timeout         time.Duration
	responseBuilder *ResponseBuilder
	continueOnError bool
}

// Step represents a step in the orchestration workflow
type Step struct {
	name            string
	callback        *callback.Callback
	condition       string
	dependsOn       []string
	continueOnError *bool
	retry           *RetryConfig
}

// RetryConfig defines retry behavior
type RetryConfig struct {
	maxAttempts  int
	backoff      string
	initialDelay time.Duration
	maxDelay     time.Duration
}

// ResponseBuilder builds the final response
type ResponseBuilder struct {
	template    string
	contentType string
	statusCode  int
	headers     map[string]string
}

// ExecutionContext tracks the execution state
type ExecutionContext struct {
	Request    *http.Request
	Steps      map[string]*StepResult
	Errors     []error
	StartTime  time.Time
	mu         sync.RWMutex
}

// StepResult contains the result of a step execution
type StepResult struct {
	Name      string         `json:"name"`
	Response  map[string]any `json:"response"`
	Duration  time.Duration  `json:"duration"`
	Error     error          `json:"error,omitempty"`
	StartTime time.Time      `json:"start_time"`
	EndTime   time.Time      `json:"end_time"`
	Attempts  int            `json:"attempts"` // Number of attempts (including retries)
}

// Execute runs the orchestration workflow
func (e *Executor) Execute(ctx context.Context, req *http.Request) (*http.Response, error) {
	execCtx := &ExecutionContext{
		Request:   req,
		Steps:     make(map[string]*StepResult),
		Errors:    []error{},
		StartTime: time.Now(),
	}

	// Apply timeout if configured
	if e.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	// Build execution plan (resolve dependencies)
	plan, err := e.buildExecutionPlan()
	if err != nil {
		return nil, fmt.Errorf("failed to build execution plan: %w", err)
	}

	// Execute based on mode
	if e.parallel {
		err = e.executeParallel(ctx, execCtx, plan)
	} else {
		err = e.executeSequential(ctx, execCtx, plan)
	}

	// Check if we should fail on errors
	if err != nil && !e.continueOnError {
		return nil, err
	}

	// Build response
	return e.buildResponse(ctx, execCtx)
}

// executeSequential executes steps in order
func (e *Executor) executeSequential(ctx context.Context, execCtx *ExecutionContext, plan *ExecutionPlan) error {
	for _, step := range plan.Order {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Execute step
		if err := e.executeStep(ctx, execCtx, step); err != nil {
			if !e.shouldContinueOnError(step) {
				return fmt.Errorf("step %s failed: %w", step.name, err)
			}
			// Log error but continue
			slog.Error("step failed but continuing",
				"step", step.name,
				"error", err)
			execCtx.mu.Lock()
			execCtx.Errors = append(execCtx.Errors, err)
			execCtx.mu.Unlock()
		}
	}

	return nil
}

// executeParallel executes steps in parallel respecting dependencies
func (e *Executor) executeParallel(ctx context.Context, execCtx *ExecutionContext, plan *ExecutionPlan) error {
	// Group steps by level (steps at same level can run in parallel)
	levels := plan.GetLevels()

	for _, level := range levels {
		// Execute all steps in this level in parallel
		var wg sync.WaitGroup
		errChan := make(chan error, len(level))

		for _, step := range level {
			wg.Add(1)
			go func(s Step) {
				defer wg.Done()

				// Check context cancellation
				select {
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				default:
				}

				// Execute step
				if err := e.executeStep(ctx, execCtx, s); err != nil {
					if !e.shouldContinueOnError(s) {
						errChan <- fmt.Errorf("step %s failed: %w", s.name, err)
						return
					}
					// Log error but continue
					slog.Error("step failed but continuing",
						"step", s.name,
						"error", err)
					execCtx.mu.Lock()
					execCtx.Errors = append(execCtx.Errors, err)
					execCtx.mu.Unlock()
				}
			}(step)
		}

		wg.Wait()
		close(errChan)

		// Check for errors from this level
		for err := range errChan {
			if !e.continueOnError {
				return err
			}
		}
	}

	return nil
}

// executeStep executes a single step with retry logic
func (e *Executor) executeStep(ctx context.Context, execCtx *ExecutionContext, step Step) error {
	// Check if step should execute (condition evaluation)
	shouldExecute, err := e.evaluateCondition(ctx, execCtx, step)
	if err != nil {
		return fmt.Errorf("condition evaluation failed: %w", err)
	}
	if !shouldExecute {
		slog.Debug("step skipped due to condition",
			"step", step.name)
		return nil
	}

	// Execute with retry
	var result *StepResult
	attempts := 0
	maxAttempts := 1

	if step.retry != nil && step.retry.maxAttempts > 0 {
		maxAttempts = step.retry.maxAttempts
	}

	for attempts < maxAttempts {
		attempts++
		result, err = e.executeStepOnce(ctx, execCtx, step)
		
		if err == nil {
			break
		}

		// Check if we should retry
		if attempts < maxAttempts {
			delay := e.calculateRetryDelay(step, attempts)
			slog.Warn("step failed, retrying",
				"step", step.name,
				"attempt", attempts,
				"max_attempts", maxAttempts,
				"delay", delay,
				"error", err)

			select {
			case <-time.After(delay):
				// Continue to retry
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	if result != nil {
		result.Attempts = attempts
		execCtx.mu.Lock()
		execCtx.Steps[step.name] = result
		execCtx.mu.Unlock()
	}

	return err
}

// executeStepOnce executes a step once (no retry)
func (e *Executor) executeStepOnce(ctx context.Context, execCtx *ExecutionContext, step Step) (*StepResult, error) {
	startTime := time.Now()

	slog.Debug("executing step",
		"step", step.name)

	// Build callback context with access to previous step results
	callbackCtx := e.buildCallbackContext(ctx, execCtx)

	// Execute callback
	result, err := step.callback.Do(ctx, callbackCtx)
	
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	stepResult := &StepResult{
		Name:      step.name,
		Response:  result,
		Duration:  duration,
		Error:     err,
		StartTime: startTime,
		EndTime:   endTime,
		Attempts:  1,
	}

	slog.Debug("step completed",
		"step", step.name,
		"duration", duration,
		"error", err != nil)

	return stepResult, err
}

// buildCallbackContext builds context for callback execution
// Includes previous step results for chaining
func (e *Executor) buildCallbackContext(ctx context.Context, execCtx *ExecutionContext) map[string]any {
	execCtx.mu.RLock()
	defer execCtx.mu.RUnlock()

	// Build context with step results and 9-namespace model
	callbackCtx := map[string]any{
		"steps": e.buildStepsContext(execCtx.Steps),
	}

	// Add namespace context objects from RequestData
	if rd := reqctx.GetRequestData(execCtx.Request.Context()); rd != nil {
		if rd.Snapshot != nil {
			callbackCtx["request"] = rd.Snapshot
		}
		if rd.OriginCtx != nil {
			callbackCtx["origin"] = rd.OriginCtx
		}
		if rd.CtxObj != nil {
			callbackCtx["ctx"] = rd.CtxObj
		}
		if rd.SessionCtx != nil {
			callbackCtx["session"] = rd.SessionCtx
		}
		if rd.ServerCtx != nil {
			callbackCtx["server"] = rd.ServerCtx
		}
		if rd.VarsCtx != nil && rd.VarsCtx.Data != nil {
			callbackCtx["vars"] = rd.VarsCtx.Data
		}
		if rd.FeaturesCtx != nil && rd.FeaturesCtx.Data != nil {
			callbackCtx["features"] = rd.FeaturesCtx.Data
		}
		if rd.ClientCtx != nil {
			callbackCtx["client"] = rd.ClientCtx
		}
	}

	return callbackCtx
}

// buildStepsContext builds the steps context for templates.
// Adds response_json (JSON string) and response_count (array length) for
// use in Mustache templates that cannot apply filters.
func (e *Executor) buildStepsContext(steps map[string]*StepResult) map[string]any {
	result := make(map[string]any, len(steps))

	for name, stepResult := range steps {
		stepCtx := map[string]any{
			"response":   stepResult.Response,
			"duration":   stepResult.Duration.Milliseconds(),
			"error":      stepResult.Error,
			"start_time": stepResult.StartTime,
			"end_time":   stepResult.EndTime,
			"attempts":   stepResult.Attempts,
		}

		// Add response_json: JSON-encoded string of the response.
		// Replaces the need for |tojson filters in Mustache templates.
		if stepResult.Response != nil {
			if b, err := json.Marshal(stepResult.Response); err == nil {
				stepCtx["response_json"] = string(b)
			}
		} else {
			stepCtx["response_json"] = "null"
		}

		result[name] = stepCtx
	}

	return result
}

// evaluateCondition evaluates a step's condition using the template resolver
func (e *Executor) evaluateCondition(ctx context.Context, execCtx *ExecutionContext, step Step) (bool, error) {
	if step.condition == "" {
		return true, nil // No condition means always execute
	}

	// Build template context with steps and request data
	templateCtx := e.buildTemplateContext(execCtx)

	// Resolve condition template
	result, err := templateresolver.ResolveWithContext(step.condition, templateCtx)
	if err != nil {
		return false, fmt.Errorf("condition template error: %w", err)
	}

	// Convert result to boolean
	result = strings.TrimSpace(result)
	return result == "true" || result == "True", nil
}

// buildTemplateContext builds template context for condition evaluation and response building
func (e *Executor) buildTemplateContext(execCtx *ExecutionContext) map[string]any {
	execCtx.mu.RLock()
	defer execCtx.mu.RUnlock()

	ctx := map[string]any{
		"steps": e.buildStepsContext(execCtx.Steps),
	}

	// Add request context
	if execCtx.Request != nil {
		requestCtx := templateresolver.BuildContext(execCtx.Request)
		for k, v := range requestCtx {
			ctx[k] = v
		}
	}

	return ctx
}

// calculateRetryDelay calculates the delay before next retry
func (e *Executor) calculateRetryDelay(step Step, attempt int) time.Duration {
	if step.retry == nil {
		return 100 * time.Millisecond
	}

	delay := step.retry.initialDelay

	if step.retry.backoff == "exponential" {
		// Exponential backoff: delay * 2^(attempt-1)
		for i := 1; i < attempt; i++ {
			delay *= 2
		}
	}

	// Cap at max delay
	if delay > step.retry.maxDelay {
		delay = step.retry.maxDelay
	}

	return delay
}

// shouldContinueOnError determines if execution should continue after error
func (e *Executor) shouldContinueOnError(step Step) bool {
	// Step-level override takes precedence
	if step.continueOnError != nil {
		return *step.continueOnError
	}
	// Fall back to orchestration-level setting
	return e.continueOnError
}

// buildResponse builds the final HTTP response using the response builder
func (e *Executor) buildResponse(ctx context.Context, execCtx *ExecutionContext) (*http.Response, error) {
	if e.responseBuilder == nil {
		return nil, fmt.Errorf("response builder not configured")
	}

	// Build template context with all step results
	templateCtx := e.buildTemplateContext(execCtx)

	// Add errors to context
	templateCtx["errors"] = execCtx.Errors
	templateCtx["error_count"] = len(execCtx.Errors)
	templateCtx["total_duration"] = time.Since(execCtx.StartTime).Milliseconds()

	// Resolve response template
	body, err := templateresolver.ResolveWithContext(e.responseBuilder.template, templateCtx)
	if err != nil {
		return nil, fmt.Errorf("response template error: %w", err)
	}

	// Build HTTP response
	statusCode := e.responseBuilder.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	resp := &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       execCtx.Request,
	}

	// Set Content-Type
	contentType := e.responseBuilder.contentType
	if contentType == "" {
		contentType = "application/json"
	}
	resp.Header.Set("Content-Type", contentType)
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))

	// Add custom headers
	for k, v := range e.responseBuilder.headers {
		resp.Header.Set(k, v)
	}

	slog.Info("orchestration completed",
		"steps_completed", len(execCtx.Steps),
		"errors", len(execCtx.Errors),
		"total_duration", time.Since(execCtx.StartTime))

	return resp, nil
}

// buildExecutionPlan builds an execution plan from steps
func (e *Executor) buildExecutionPlan() (*ExecutionPlan, error) {
	// Build dependency graph
	graph, err := buildDependencyGraph(e.steps)
	if err != nil {
		return nil, err
	}

	// Detect cycles
	if graph.hasCycle() {
		return nil, fmt.Errorf("circular dependency detected in orchestration steps")
	}

	// Get topological order for sequential execution
	order := graph.topologicalSort()

	// Get levels for parallel execution
	levels := graph.getLevels()

	return &ExecutionPlan{
		Graph:  graph,
		Order:  order,
		Levels: levels,
	}, nil
}

// ExecutionPlan represents the planned execution order
type ExecutionPlan struct {
	Graph  *DependencyGraph
	Order  []Step   // For sequential execution
	Levels [][]Step // For parallel execution (steps at same level can run in parallel)
}

// GetLevels returns the levels for parallel execution
func (p *ExecutionPlan) GetLevels() [][]Step {
	return p.Levels
}

