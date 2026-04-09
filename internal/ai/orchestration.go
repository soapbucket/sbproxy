// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"
)

// WorkflowStep defines a single step in an orchestration workflow.
type WorkflowStep struct {
	Name         string        `json:"name"`
	Provider     string        `json:"provider,omitempty"`
	Model        string        `json:"model,omitempty"`
	Transform    string        `json:"transform,omitempty"` // "append_context", "replace_last", "summarize"
	Timeout      time.Duration `json:"timeout,omitempty"`
	OnError      string        `json:"on_error,omitempty"` // "stop", "skip", "fallback"
	Condition    string        `json:"condition,omitempty"`
	SystemPrompt string        `json:"system_prompt,omitempty"`
	Temperature  *float64      `json:"temperature,omitempty"`
	MaxTokens    int           `json:"max_tokens,omitempty"`
}

// WorkflowConfig defines an orchestration workflow.
type WorkflowConfig struct {
	Name          string         `json:"name"`
	Pattern       string         `json:"pattern"` // "sequential", "fan_out", "eval_pipeline", "guardrail_sandwich"
	Steps         []WorkflowStep `json:"steps"`
	ConsensusMode string         `json:"consensus_mode,omitempty"` // "majority", "best_score", "first"
	MaxParallel   int            `json:"max_parallel,omitempty"`
}

// WorkflowResult is the output of a workflow execution.
type WorkflowResult struct {
	FinalResponse *ChatCompletionResponse `json:"final_response"`
	Steps         []StepResult            `json:"steps"`
	TotalTokens   int                     `json:"total_tokens"`
	TotalLatency  time.Duration           `json:"total_latency"`
	Pattern       string                  `json:"pattern"`
}

// StepResult holds the output of a single workflow step.
type StepResult struct {
	Name     string                  `json:"name"`
	Response *ChatCompletionResponse `json:"response,omitempty"`
	Error    string                  `json:"error,omitempty"`
	Latency  time.Duration           `json:"latency"`
	Tokens   int                     `json:"tokens"`
	Skipped  bool                    `json:"skipped,omitempty"`
}

// RequestExecutor is the interface for executing a single AI request.
type RequestExecutor interface {
	Execute(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error)
}

// WorkflowExecutor runs orchestration workflows.
type WorkflowExecutor struct {
	handler RequestExecutor
}

// NewWorkflowExecutor creates a new workflow executor with the given request handler.
func NewWorkflowExecutor(handler RequestExecutor) *WorkflowExecutor {
	return &WorkflowExecutor{handler: handler}
}

// Execute runs the workflow according to the configured pattern.
func (we *WorkflowExecutor) Execute(ctx context.Context, config *WorkflowConfig, initialReq *ChatCompletionRequest) (*WorkflowResult, error) {
	if config == nil {
		return nil, errors.New("workflow config is nil")
	}
	if len(config.Steps) == 0 {
		return nil, errors.New("workflow has no steps")
	}

	start := time.Now()

	var result *WorkflowResult
	var err error

	switch config.Pattern {
	case "sequential":
		result, err = we.executeSequential(ctx, config.Steps, initialReq)
	case "fan_out":
		result, err = we.executeFanOut(ctx, config, initialReq)
	case "eval_pipeline":
		result, err = we.executeEvalPipeline(ctx, config.Steps, initialReq)
	case "guardrail_sandwich":
		result, err = we.executeGuardrailSandwich(ctx, config.Steps, initialReq)
	default:
		return nil, fmt.Errorf("unknown workflow pattern: %q", config.Pattern)
	}

	if err != nil {
		return nil, err
	}

	result.Pattern = config.Pattern
	result.TotalLatency = time.Since(start)
	return result, nil
}

// executeSequential runs steps one after another, passing output as context to subsequent steps.
func (we *WorkflowExecutor) executeSequential(ctx context.Context, steps []WorkflowStep, req *ChatCompletionRequest) (*WorkflowResult, error) {
	result := &WorkflowResult{
		Steps: make([]StepResult, 0, len(steps)),
	}

	currentReq := cloneRequest(req)
	var lastResp *ChatCompletionResponse

	for i, step := range steps {
		stepCtx := ctx
		if step.Timeout > 0 {
			var cancel context.CancelFunc
			stepCtx, cancel = context.WithTimeout(ctx, step.Timeout)
			defer cancel()
		}

		// Apply transform from previous step output
		if i > 0 && lastResp != nil {
			currentReq = applyTransform(currentReq, lastResp, step)
		}

		// Apply step-specific overrides
		stepReq := applyStepOverrides(currentReq, step)

		stepStart := time.Now()
		resp, err := we.handler.Execute(stepCtx, stepReq)
		stepLatency := time.Since(stepStart)

		sr := StepResult{
			Name:    step.Name,
			Latency: stepLatency,
		}

		if err != nil {
			sr.Error = err.Error()

			switch step.OnError {
			case "skip":
				sr.Skipped = true
				result.Steps = append(result.Steps, sr)
				slog.Warn("workflow step skipped due to error", "step", step.Name, "error", err)
				continue
			case "stop", "":
				result.Steps = append(result.Steps, sr)
				// Return what we have so far with the last successful response
				if lastResp != nil {
					result.FinalResponse = lastResp
				}
				return result, fmt.Errorf("step %q failed: %w", step.Name, err)
			default:
				// For any other on_error value, treat as stop
				result.Steps = append(result.Steps, sr)
				if lastResp != nil {
					result.FinalResponse = lastResp
				}
				return result, fmt.Errorf("step %q failed: %w", step.Name, err)
			}
		}

		sr.Response = resp
		if resp.Usage != nil {
			sr.Tokens = resp.Usage.TotalTokens
			result.TotalTokens += resp.Usage.TotalTokens
		}

		result.Steps = append(result.Steps, sr)
		lastResp = resp
	}

	result.FinalResponse = lastResp
	return result, nil
}

// executeFanOut runs steps in parallel, then selects or merges results.
func (we *WorkflowExecutor) executeFanOut(ctx context.Context, config *WorkflowConfig, req *ChatCompletionRequest) (*WorkflowResult, error) {
	steps := config.Steps
	maxParallel := config.MaxParallel
	if maxParallel <= 0 {
		maxParallel = len(steps)
	}

	result := &WorkflowResult{
		Steps: make([]StepResult, len(steps)),
	}

	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup

	for i, step := range steps {
		wg.Add(1)
		go func(idx int, s WorkflowStep) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			stepCtx := ctx
			if s.Timeout > 0 {
				var cancel context.CancelFunc
				stepCtx, cancel = context.WithTimeout(ctx, s.Timeout)
				defer cancel()
			}

			stepReq := applyStepOverrides(cloneRequest(req), s)
			stepStart := time.Now()
			resp, err := we.handler.Execute(stepCtx, stepReq)
			stepLatency := time.Since(stepStart)

			sr := StepResult{
				Name:    s.Name,
				Latency: stepLatency,
			}

			if err != nil {
				sr.Error = err.Error()
				if s.OnError == "skip" {
					sr.Skipped = true
				}
			} else {
				sr.Response = resp
				if resp.Usage != nil {
					sr.Tokens = resp.Usage.TotalTokens
				}
			}

			result.Steps[idx] = sr
		}(i, step)
	}

	wg.Wait()

	// Sum tokens
	for _, sr := range result.Steps {
		result.TotalTokens += sr.Tokens
	}

	// Apply consensus
	consensusMode := config.ConsensusMode
	if consensusMode == "" {
		consensusMode = "first"
	}

	switch consensusMode {
	case "first":
		result.FinalResponse = selectFirst(result.Steps)
	case "majority":
		result.FinalResponse = selectMajority(result.Steps)
	case "best_score":
		result.FinalResponse = selectBestScore(result.Steps)
	default:
		result.FinalResponse = selectFirst(result.Steps)
	}

	if result.FinalResponse == nil {
		return result, errors.New("all fan-out steps failed")
	}

	return result, nil
}

// executeEvalPipeline runs a primary request, then evaluation steps that score the output.
// The first step is the primary request. Subsequent steps are evaluators that receive the
// primary output in their context.
func (we *WorkflowExecutor) executeEvalPipeline(ctx context.Context, steps []WorkflowStep, req *ChatCompletionRequest) (*WorkflowResult, error) {
	if len(steps) < 2 {
		return nil, errors.New("eval_pipeline requires at least 2 steps (primary + evaluator)")
	}

	result := &WorkflowResult{
		Steps: make([]StepResult, 0, len(steps)),
	}

	// Step 0: primary request
	primaryStep := steps[0]
	primaryReq := applyStepOverrides(cloneRequest(req), primaryStep)

	stepStart := time.Now()
	primaryResp, err := we.handler.Execute(ctx, primaryReq)
	stepLatency := time.Since(stepStart)

	sr := StepResult{
		Name:    primaryStep.Name,
		Latency: stepLatency,
	}

	if err != nil {
		sr.Error = err.Error()
		result.Steps = append(result.Steps, sr)
		return result, fmt.Errorf("primary step %q failed: %w", primaryStep.Name, err)
	}

	sr.Response = primaryResp
	if primaryResp.Usage != nil {
		sr.Tokens = primaryResp.Usage.TotalTokens
		result.TotalTokens += primaryResp.Usage.TotalTokens
	}
	result.Steps = append(result.Steps, sr)

	// Run evaluator steps
	primaryContent := extractResponseContent(primaryResp)

	for _, evalStep := range steps[1:] {
		evalCtx := ctx
		if evalStep.Timeout > 0 {
			var cancel context.CancelFunc
			evalCtx, cancel = context.WithTimeout(ctx, evalStep.Timeout)
			defer cancel()
		}

		// Build eval request with primary output as context
		evalReq := buildEvalRequest(req, primaryContent, evalStep)

		evalStart := time.Now()
		evalResp, evalErr := we.handler.Execute(evalCtx, evalReq)
		evalLatency := time.Since(evalStart)

		evalSR := StepResult{
			Name:    evalStep.Name,
			Latency: evalLatency,
		}

		if evalErr != nil {
			evalSR.Error = evalErr.Error()
			if evalStep.OnError == "skip" {
				evalSR.Skipped = true
			}
		} else {
			evalSR.Response = evalResp
			if evalResp.Usage != nil {
				evalSR.Tokens = evalResp.Usage.TotalTokens
				result.TotalTokens += evalResp.Usage.TotalTokens
			}
		}

		result.Steps = append(result.Steps, evalSR)
	}

	result.FinalResponse = primaryResp
	return result, nil
}

// executeGuardrailSandwich runs pre-guardrail check, main request, then post-guardrail check.
// Expects exactly 3 steps: pre-guardrail, main, post-guardrail.
func (we *WorkflowExecutor) executeGuardrailSandwich(ctx context.Context, steps []WorkflowStep, req *ChatCompletionRequest) (*WorkflowResult, error) {
	if len(steps) < 3 {
		return nil, errors.New("guardrail_sandwich requires at least 3 steps (pre-guardrail, main, post-guardrail)")
	}

	result := &WorkflowResult{
		Steps: make([]StepResult, 0, len(steps)),
	}

	// Step 0: Pre-guardrail
	preStep := steps[0]
	preReq := buildGuardrailRequest(req, preStep, "pre")
	preReq = applyStepOverrides(preReq, preStep)

	preStart := time.Now()
	preResp, preErr := we.handler.Execute(ctx, preReq)
	preLatency := time.Since(preStart)

	preSR := StepResult{
		Name:    preStep.Name,
		Latency: preLatency,
	}

	if preErr != nil {
		preSR.Error = preErr.Error()
		result.Steps = append(result.Steps, preSR)
		return result, fmt.Errorf("pre-guardrail %q failed: %w", preStep.Name, preErr)
	}

	preSR.Response = preResp
	if preResp.Usage != nil {
		preSR.Tokens = preResp.Usage.TotalTokens
		result.TotalTokens += preResp.Usage.TotalTokens
	}
	result.Steps = append(result.Steps, preSR)

	// Check if pre-guardrail blocked the request
	if isGuardrailBlock(preResp) {
		result.FinalResponse = preResp
		return result, nil
	}

	// Step 1: Main request
	mainStep := steps[1]
	mainReq := applyStepOverrides(cloneRequest(req), mainStep)

	mainStart := time.Now()
	mainResp, mainErr := we.handler.Execute(ctx, mainReq)
	mainLatency := time.Since(mainStart)

	mainSR := StepResult{
		Name:    mainStep.Name,
		Latency: mainLatency,
	}

	if mainErr != nil {
		mainSR.Error = mainErr.Error()
		result.Steps = append(result.Steps, mainSR)
		return result, fmt.Errorf("main step %q failed: %w", mainStep.Name, mainErr)
	}

	mainSR.Response = mainResp
	if mainResp.Usage != nil {
		mainSR.Tokens = mainResp.Usage.TotalTokens
		result.TotalTokens += mainResp.Usage.TotalTokens
	}
	result.Steps = append(result.Steps, mainSR)

	// Step 2: Post-guardrail
	postStep := steps[2]
	mainContent := extractResponseContent(mainResp)
	postReq := buildGuardrailRequest(req, postStep, "post")

	// Include the main response content for the post-guardrail to evaluate
	postReq.Messages = append(postReq.Messages, Message{
		Role:    "assistant",
		Content: json.RawMessage(strconv.Quote(mainContent)),
	})
	postReq = applyStepOverrides(postReq, postStep)

	postStart := time.Now()
	postResp, postErr := we.handler.Execute(ctx, postReq)
	postLatency := time.Since(postStart)

	postSR := StepResult{
		Name:    postStep.Name,
		Latency: postLatency,
	}

	if postErr != nil {
		postSR.Error = postErr.Error()
		result.Steps = append(result.Steps, postSR)
		return result, fmt.Errorf("post-guardrail %q failed: %w", postStep.Name, postErr)
	}

	postSR.Response = postResp
	if postResp.Usage != nil {
		postSR.Tokens = postResp.Usage.TotalTokens
		result.TotalTokens += postResp.Usage.TotalTokens
	}
	result.Steps = append(result.Steps, postSR)

	// Check if post-guardrail blocked the response
	if isGuardrailBlock(postResp) {
		result.FinalResponse = postResp
		return result, nil
	}

	result.FinalResponse = mainResp
	return result, nil
}

// cloneRequest creates a shallow copy of a ChatCompletionRequest with a copied message slice.
func cloneRequest(req *ChatCompletionRequest) *ChatCompletionRequest {
	if req == nil {
		return &ChatCompletionRequest{}
	}
	clone := *req
	clone.Messages = make([]Message, len(req.Messages))
	copy(clone.Messages, req.Messages)
	return &clone
}

// applyStepOverrides applies step-specific configuration to a request.
func applyStepOverrides(req *ChatCompletionRequest, step WorkflowStep) *ChatCompletionRequest {
	if step.Model != "" {
		req.Model = step.Model
	}
	if step.Temperature != nil {
		req.Temperature = step.Temperature
	}
	if step.MaxTokens > 0 {
		req.MaxTokens = &step.MaxTokens
	}
	if step.SystemPrompt != "" {
		// Prepend or replace system message
		found := false
		for i, msg := range req.Messages {
			if msg.Role == "system" {
				req.Messages[i].Content = json.RawMessage(strconv.Quote(step.SystemPrompt))
				found = true
				break
			}
		}
		if !found {
			req.Messages = append([]Message{{
				Role:    "system",
				Content: json.RawMessage(strconv.Quote(step.SystemPrompt)),
			}}, req.Messages...)
		}
	}
	return req
}

// applyTransform modifies the current request based on the previous response and the step's transform type.
func applyTransform(req *ChatCompletionRequest, prevResp *ChatCompletionResponse, step WorkflowStep) *ChatCompletionRequest {
	prevContent := extractResponseContent(prevResp)
	if prevContent == "" {
		return req
	}

	clone := cloneRequest(req)

	switch step.Transform {
	case "append_context":
		// Append previous response as assistant message
		clone.Messages = append(clone.Messages, Message{
			Role:    "assistant",
			Content: json.RawMessage(strconv.Quote(prevContent)),
		})
		// If step has a system prompt, add a user message to prompt continuation
		if step.SystemPrompt != "" {
			clone.Messages = append(clone.Messages, Message{
				Role:    "user",
				Content: json.RawMessage(strconv.Quote(step.SystemPrompt)),
			})
		}

	case "replace_last":
		// Replace the last user message with the step's system prompt + previous output
		prompt := step.SystemPrompt
		if prompt == "" {
			prompt = "Continue based on this context:"
		}
		replacement := prompt + "\n\n" + prevContent
		// Find last user message and replace
		for i := len(clone.Messages) - 1; i >= 0; i-- {
			if clone.Messages[i].Role == "user" {
				clone.Messages[i].Content = json.RawMessage(strconv.Quote(replacement))
				break
			}
		}

	case "summarize":
		// Add "Summarize the following:" prefix to previous output
		summaryPrompt := "Summarize the following:\n\n" + prevContent
		clone.Messages = append(clone.Messages, Message{
			Role:    "user",
			Content: json.RawMessage(strconv.Quote(summaryPrompt)),
		})

	default:
		// Default: append as context
		clone.Messages = append(clone.Messages, Message{
			Role:    "assistant",
			Content: json.RawMessage(strconv.Quote(prevContent)),
		})
	}

	return clone
}

// extractResponseContent extracts the text content from the first choice of a response.
func extractResponseContent(resp *ChatCompletionResponse) string {
	if resp == nil || len(resp.Choices) == 0 {
		return ""
	}
	return resp.Choices[0].Message.ContentString()
}

// selectFirst returns the first successful response from step results.
func selectFirst(steps []StepResult) *ChatCompletionResponse {
	for _, s := range steps {
		if s.Response != nil && !s.Skipped {
			return s.Response
		}
	}
	return nil
}

// selectMajority picks the response whose content appears most frequently.
func selectMajority(steps []StepResult) *ChatCompletionResponse {
	type candidate struct {
		content  string
		response *ChatCompletionResponse
		count    int
	}

	var candidates []candidate

	for _, s := range steps {
		if s.Response == nil || s.Skipped {
			continue
		}
		content := extractResponseContent(s.Response)
		found := false
		for i := range candidates {
			if contentSimilar(candidates[i].content, content) {
				candidates[i].count++
				found = true
				break
			}
		}
		if !found {
			candidates = append(candidates, candidate{
				content:  content,
				response: s.Response,
				count:    1,
			})
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.count > best.count {
			best = c
		}
	}
	return best.response
}

// selectBestScore returns the response with the highest eval score.
// Looks for a numeric score in the response content (first number found).
func selectBestScore(steps []StepResult) *ChatCompletionResponse {
	var bestResp *ChatCompletionResponse
	bestScore := -1.0

	for _, s := range steps {
		if s.Response == nil || s.Skipped {
			continue
		}
		content := extractResponseContent(s.Response)
		score := extractScore(content)
		if score > bestScore {
			bestScore = score
			bestResp = s.Response
		}
	}

	return bestResp
}

// contentSimilar does a basic similarity check between two strings.
// For production use this could be replaced with cosine similarity on embeddings.
func contentSimilar(a, b string) bool {
	// Normalize whitespace and case for comparison
	a = strings.TrimSpace(strings.ToLower(a))
	b = strings.TrimSpace(strings.ToLower(b))
	if a == b {
		return true
	}
	// Simple prefix match for short responses
	if len(a) > 20 && len(b) > 20 {
		// Check if first 80% of the shorter string matches
		shorter := a
		longer := b
		if len(a) > len(b) {
			shorter = b
			longer = a
		}
		cutoff := len(shorter) * 80 / 100
		if cutoff > 0 && strings.HasPrefix(longer, shorter[:cutoff]) {
			return true
		}
	}
	return false
}

// extractScore extracts the first numeric value from a string, used for eval scoring.
func extractScore(content string) float64 {
	// Try to find a JSON score field
	var scoreObj struct {
		Score float64 `json:"score"`
	}
	if err := json.Unmarshal([]byte(content), &scoreObj); err == nil && scoreObj.Score > 0 {
		return scoreObj.Score
	}

	// Fallback: find first number in string
	words := strings.Fields(content)
	for _, w := range words {
		w = strings.TrimRight(w, ".,;:!?")
		if f, err := strconv.ParseFloat(w, 64); err == nil {
			return f
		}
	}
	return 0
}

// buildEvalRequest creates a request for an evaluator step with the primary output as context.
func buildEvalRequest(originalReq *ChatCompletionRequest, primaryContent string, evalStep WorkflowStep) *ChatCompletionRequest {
	evalReq := cloneRequest(originalReq)

	systemPrompt := evalStep.SystemPrompt
	if systemPrompt == "" {
		systemPrompt = "Evaluate the following AI response for quality, accuracy, and safety. Provide a score from 0 to 10."
	}

	evalReq.Messages = []Message{
		{
			Role:    "system",
			Content: json.RawMessage(strconv.Quote(systemPrompt)),
		},
		{
			Role:    "user",
			Content: json.RawMessage(strconv.Quote("AI Response to evaluate:\n\n" + primaryContent)),
		},
	}

	return evalReq
}

// buildGuardrailRequest creates a request for a guardrail check step.
func buildGuardrailRequest(originalReq *ChatCompletionRequest, step WorkflowStep, phase string) *ChatCompletionRequest {
	req := cloneRequest(originalReq)

	systemPrompt := step.SystemPrompt
	if systemPrompt == "" {
		if phase == "pre" {
			systemPrompt = "Check if the following user input is safe and appropriate. Respond with PASS if safe or BLOCK if unsafe, followed by a brief reason."
		} else {
			systemPrompt = "Check if the following AI response is safe, accurate, and appropriate. Respond with PASS if acceptable or BLOCK if it should be filtered, followed by a brief reason."
		}
	}

	// Replace or prepend system message
	found := false
	for i, msg := range req.Messages {
		if msg.Role == "system" {
			req.Messages[i].Content = json.RawMessage(strconv.Quote(systemPrompt))
			found = true
			break
		}
	}
	if !found {
		req.Messages = append([]Message{{
			Role:    "system",
			Content: json.RawMessage(strconv.Quote(systemPrompt)),
		}}, req.Messages...)
	}

	return req
}

// isGuardrailBlock checks if a guardrail response indicates the content should be blocked.
func isGuardrailBlock(resp *ChatCompletionResponse) bool {
	if resp == nil || len(resp.Choices) == 0 {
		return false
	}
	content := strings.ToUpper(strings.TrimSpace(extractResponseContent(resp)))
	return strings.HasPrefix(content, "BLOCK")
}
