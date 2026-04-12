// cel_guardrails.go implements CEL-based safety guardrails for the AI gateway.
//
// Guardrails are CEL expressions that evaluate to true when a safety rule
// is violated. Each guardrail has:
//
//   - Phase: "input" (evaluated before provider call) or "output" (evaluated after)
//   - Action: "block" (reject the request with an error) or "flag" (record the
//     violation for audit without stopping the request)
//
// Input guardrails receive a "request" variable with messages, model,
// temperature, and max_tokens. Output guardrails receive a "response"
// variable with content, model, finish_reason, tokens_input, and
// tokens_output.
//
// Guardrails support fail-open (skip on eval error) and fail-closed
// (block on eval error) modes, controlled per-engine.
package hooks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/soapbucket/sbproxy/internal/ai"
)

// CELGuardrailConfig is the YAML/JSON configuration for a single CEL guardrail expression.
type CELGuardrailConfig struct {
	Name      string `json:"name" yaml:"name"`
	Phase     string `json:"phase" yaml:"phase"`         // "input" or "output"
	Condition string `json:"condition" yaml:"condition"` // CEL expression returning bool
	Action    string `json:"action" yaml:"action"`       // "block" or "flag"
	Message   string `json:"message,omitempty" yaml:"message,omitempty"`
}

// CELGuardrail is a compiled guardrail ready for evaluation.
type CELGuardrail struct {
	Name      string
	Phase     string      // "input" or "output"
	Condition celgo.Program // Compiled CEL program returning bool
	Action    string      // "block" or "flag"
	Message   string      // Error message for block action
}

// CELGuardrailResult is the outcome of guardrail evaluation.
type CELGuardrailResult struct {
	Blocked bool
	Flagged bool
	Rule    string
	Message string
}

// CELGuardrailEngine evaluates CEL-based guardrail expressions on AI requests and responses.
type CELGuardrailEngine struct {
	inputGuards  []CELGuardrail
	outputGuards []CELGuardrail
	failOpen     bool
}

// Shared CEL environments for guardrail expressions (one for input, one for output).
var (
	guardrailInputEnvOnce  sync.Once
	guardrailInputEnvVal   *celgo.Env
	guardrailInputEnvErr   error
	guardrailOutputEnvOnce sync.Once
	guardrailOutputEnvVal  *celgo.Env
	guardrailOutputEnvErr  error
)

// getGuardrailInputEnv returns the CEL environment for input guardrail expressions.
// Variables: request.messages (list of {role, content}), request.model (string),
// request.temperature (double), request.max_tokens (int).
func getGuardrailInputEnv() (*celgo.Env, error) {
	guardrailInputEnvOnce.Do(func() {
		guardrailInputEnvVal, guardrailInputEnvErr = celgo.NewEnv(
			celgo.Variable("request", celgo.MapType(celgo.StringType, celgo.DynType)),
			ext.Strings(),
		)
	})
	return guardrailInputEnvVal, guardrailInputEnvErr
}

// getGuardrailOutputEnv returns the CEL environment for output guardrail expressions.
// Variables: response.content (string), response.tokens_input (int),
// response.tokens_output (int), response.model (string), response.finish_reason (string).
func getGuardrailOutputEnv() (*celgo.Env, error) {
	guardrailOutputEnvOnce.Do(func() {
		guardrailOutputEnvVal, guardrailOutputEnvErr = celgo.NewEnv(
			celgo.Variable("response", celgo.MapType(celgo.StringType, celgo.DynType)),
			ext.Strings(),
		)
	})
	return guardrailOutputEnvVal, guardrailOutputEnvErr
}

// NewCELGuardrailEngine compiles all guardrail configurations and returns an engine ready for evaluation.
// Invalid CEL expressions cause an immediate error at config load time.
// Returns nil if configs is empty.
func NewCELGuardrailEngine(configs []CELGuardrailConfig, failOpen bool) (*CELGuardrailEngine, error) {
	if len(configs) == 0 {
		return nil, nil
	}

	engine := &CELGuardrailEngine{failOpen: failOpen}

	for i, cfg := range configs {
		if cfg.Name == "" {
			return nil, fmt.Errorf("cel_guardrail[%d]: name is required", i)
		}
		if cfg.Phase != "input" && cfg.Phase != "output" {
			return nil, fmt.Errorf("cel_guardrail[%d] %q: phase must be \"input\" or \"output\", got %q", i, cfg.Name, cfg.Phase)
		}
		if cfg.Action != "block" && cfg.Action != "flag" {
			return nil, fmt.Errorf("cel_guardrail[%d] %q: action must be \"block\" or \"flag\", got %q", i, cfg.Name, cfg.Action)
		}
		if cfg.Condition == "" {
			return nil, fmt.Errorf("cel_guardrail[%d] %q: condition is required", i, cfg.Name)
		}

		var env *celgo.Env
		var err error
		if cfg.Phase == "input" {
			env, err = getGuardrailInputEnv()
		} else {
			env, err = getGuardrailOutputEnv()
		}
		if err != nil {
			return nil, fmt.Errorf("cel_guardrail[%d] %q: env error: %w", i, cfg.Name, err)
		}

		ast, iss := env.Compile(cfg.Condition)
		if iss != nil && iss.Err() != nil {
			return nil, fmt.Errorf("cel_guardrail[%d] %q: compile error: %w", i, cfg.Name, iss.Err())
		}
		if ast.OutputType() != celgo.BoolType {
			return nil, fmt.Errorf("cel_guardrail[%d] %q: condition must return bool, got %s", i, cfg.Name, ast.OutputType())
		}
		prog, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("cel_guardrail[%d] %q: program error: %w", i, cfg.Name, err)
		}

		guard := CELGuardrail{
			Name:      cfg.Name,
			Phase:     cfg.Phase,
			Condition: prog,
			Action:    cfg.Action,
			Message:   cfg.Message,
		}

		if cfg.Phase == "input" {
			engine.inputGuards = append(engine.inputGuards, guard)
		} else {
			engine.outputGuards = append(engine.outputGuards, guard)
		}
	}

	return engine, nil
}

// HasInput returns true if any input-phase guardrails are configured.
func (e *CELGuardrailEngine) HasInput() bool {
	return e != nil && len(e.inputGuards) > 0
}

// HasOutput returns true if any output-phase guardrails are configured.
func (e *CELGuardrailEngine) HasOutput() bool {
	return e != nil && len(e.outputGuards) > 0
}

// CheckInput evaluates all input-phase guardrails against the request.
// Guardrails are evaluated in order; the first "block" action wins and returns immediately.
// "flag" actions are recorded but do not stop evaluation.
func (e *CELGuardrailEngine) CheckInput(ctx context.Context, req *ai.ChatCompletionRequest, wsID, reqID string) (*CELGuardrailResult, error) {
	if e == nil || len(e.inputGuards) == 0 {
		return nil, nil
	}

	activation := buildInputActivation(req)
	var flagResult *CELGuardrailResult

	for _, guard := range e.inputGuards {
		triggered, err := e.evalGuard(guard, activation)
		if err != nil {
			slog.Warn("cel_guardrail: input eval error",
				"name", guard.Name, "error", err,
				"workspace_id", wsID, "request_id", reqID)
			if !e.failOpen {
				return &CELGuardrailResult{
					Blocked: true,
					Rule:    guard.Name,
					Message: "guardrail evaluation error (fail-closed)",
				}, nil
			}
			// fail-open: skip this guardrail
			continue
		}

		if !triggered {
			continue
		}

		if guard.Action == "block" {
			msg := guard.Message
			if msg == "" {
				msg = "blocked by guardrail: " + guard.Name
			}
			return &CELGuardrailResult{
				Blocked: true,
				Rule:    guard.Name,
				Message: msg,
			}, nil
		}

		// flag action: record the first flag
		if flagResult == nil {
			flagResult = &CELGuardrailResult{
				Flagged: true,
				Rule:    guard.Name,
				Message: guard.Message,
			}
		}
	}

	return flagResult, nil
}

// CheckOutput evaluates all output-phase guardrails against the response.
// Guardrails are evaluated in order; the first "block" action wins.
func (e *CELGuardrailEngine) CheckOutput(ctx context.Context, resp *ai.ChatCompletionResponse, wsID, reqID string) (*CELGuardrailResult, error) {
	if e == nil || len(e.outputGuards) == 0 {
		return nil, nil
	}

	activation := buildOutputActivation(resp)
	var flagResult *CELGuardrailResult

	for _, guard := range e.outputGuards {
		triggered, err := e.evalGuard(guard, activation)
		if err != nil {
			slog.Warn("cel_guardrail: output eval error",
				"name", guard.Name, "error", err,
				"workspace_id", wsID, "request_id", reqID)
			if !e.failOpen {
				return &CELGuardrailResult{
					Blocked: true,
					Rule:    guard.Name,
					Message: "guardrail evaluation error (fail-closed)",
				}, nil
			}
			continue
		}

		if !triggered {
			continue
		}

		if guard.Action == "block" {
			msg := guard.Message
			if msg == "" {
				msg = "blocked by guardrail: " + guard.Name
			}
			return &CELGuardrailResult{
				Blocked: true,
				Rule:    guard.Name,
				Message: msg,
			}, nil
		}

		if flagResult == nil {
			flagResult = &CELGuardrailResult{
				Flagged: true,
				Rule:    guard.Name,
				Message: guard.Message,
			}
		}
	}

	return flagResult, nil
}

// evalGuard evaluates a single guardrail's condition. Returns true if the condition matched (guardrail triggered).
func (e *CELGuardrailEngine) evalGuard(guard CELGuardrail, activation map[string]any) (bool, error) {
	out, _, err := guard.Condition.Eval(activation)
	if err != nil {
		return false, err
	}
	val, ok := out.Value().(bool)
	if !ok {
		return false, errors.New("condition did not return bool")
	}
	return val, nil
}

// buildInputActivation constructs the CEL activation map for input guardrails.
func buildInputActivation(req *ai.ChatCompletionRequest) map[string]any {
	reqMap := map[string]any{
		"model": req.Model,
	}

	// Temperature
	if req.Temperature != nil {
		reqMap["temperature"] = *req.Temperature
	} else {
		reqMap["temperature"] = 0.0
	}

	// MaxTokens
	if req.MaxTokens != nil {
		reqMap["max_tokens"] = int64(*req.MaxTokens)
	} else {
		reqMap["max_tokens"] = int64(0)
	}

	// Messages as list of maps with role and content
	msgs := make([]any, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, map[string]any{
			"role":    m.Role,
			"content": m.ContentString(),
		})
	}
	reqMap["messages"] = msgs

	return map[string]any{
		"request": reqMap,
	}
}

// buildOutputActivation constructs the CEL activation map for output guardrails.
func buildOutputActivation(resp *ai.ChatCompletionResponse) map[string]any {
	respMap := map[string]any{
		"model": resp.Model,
	}

	// First choice content
	content := ""
	finishReason := ""
	if len(resp.Choices) > 0 {
		content = resp.Choices[0].Message.ContentString()
		if resp.Choices[0].FinishReason != nil {
			finishReason = *resp.Choices[0].FinishReason
		}
	}
	respMap["content"] = content
	respMap["finish_reason"] = finishReason

	// Token usage
	var tokensInput, tokensOutput int64
	if resp.Usage != nil {
		tokensInput = int64(resp.Usage.PromptTokens)
		tokensOutput = int64(resp.Usage.CompletionTokens)
	}
	respMap["tokens_input"] = tokensInput
	respMap["tokens_output"] = tokensOutput

	return map[string]any{
		"response": respMap,
	}
}
