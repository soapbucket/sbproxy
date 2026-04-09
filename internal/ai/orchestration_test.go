package ai

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

// mockExecutor implements RequestExecutor for tests.
type mockExecutor struct {
	responses []*ChatCompletionResponse
	errors    []error
	callIdx   atomic.Int64
	calls     []*ChatCompletionRequest
	mu        chan struct{} // simple mutex via buffered channel
}

func newMockExecutor(responses []*ChatCompletionResponse, errs []error) *mockExecutor {
	m := &mockExecutor{
		responses: responses,
		errors:    errs,
		calls:     make([]*ChatCompletionRequest, 0),
		mu:        make(chan struct{}, 1),
	}
	m.mu <- struct{}{} // initialize unlocked
	return m
}

func (m *mockExecutor) Execute(_ context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	idx := int(m.callIdx.Add(1)) - 1

	// Thread-safe append
	<-m.mu
	m.calls = append(m.calls, req)
	m.mu <- struct{}{}

	if idx < len(m.errors) && m.errors[idx] != nil {
		return nil, m.errors[idx]
	}
	if idx < len(m.responses) {
		return m.responses[idx], nil
	}
	return makeResponse("default response", 10), nil
}

func makeResponse(content string, tokens int) *ChatCompletionResponse {
	fr := "stop"
	return &ChatCompletionResponse{
		ID:      "resp-test",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "test-model",
		Choices: []Choice{
			{
				Index: 0,
				Message: Message{
					Role:    "assistant",
					Content: json.RawMessage(strconv.Quote(content)),
				},
				FinishReason: &fr,
			},
		},
		Usage: &Usage{
			PromptTokens:     tokens / 2,
			CompletionTokens: tokens / 2,
			TotalTokens:      tokens,
		},
	}
}

func makeRequest(userMsg string) *ChatCompletionRequest {
	return &ChatCompletionRequest{
		Model: "test-model",
		Messages: []Message{
			{Role: "user", Content: json.RawMessage(strconv.Quote(userMsg))},
		},
	}
}

// --- Sequential Tests ---

func TestSequentialWorkflow_TwoSteps(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("step 1 output", 20),
		makeResponse("step 2 output", 30),
	}, nil)

	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:    "two-step",
		Pattern: "sequential",
		Steps: []WorkflowStep{
			{Name: "step1"},
			{Name: "step2"},
		},
	}

	result, err := we.Execute(context.Background(), config, makeRequest("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(result.Steps))
	}
	if result.FinalResponse == nil {
		t.Fatal("expected final response")
	}
	content := extractResponseContent(result.FinalResponse)
	if content != "step 2 output" {
		t.Errorf("expected final content 'step 2 output', got %q", content)
	}
	if result.TotalTokens != 50 {
		t.Errorf("expected 50 total tokens, got %d", result.TotalTokens)
	}
	if result.Pattern != "sequential" {
		t.Errorf("expected pattern 'sequential', got %q", result.Pattern)
	}
}

func TestSequentialWorkflow_ThreeSteps_AppendContext(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("first analysis", 10),
		makeResponse("deeper analysis", 20),
		makeResponse("final summary", 15),
	}, nil)

	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:    "three-step-append",
		Pattern: "sequential",
		Steps: []WorkflowStep{
			{Name: "analyze"},
			{Name: "deepen", Transform: "append_context", SystemPrompt: "Go deeper on this analysis"},
			{Name: "summarize", Transform: "summarize"},
		},
	}

	result, err := we.Execute(context.Background(), config, makeRequest("analyze this data"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(result.Steps))
	}

	// Verify the second call got the previous response appended
	<-exec.mu
	calls := exec.calls
	exec.mu <- struct{}{}

	if len(calls) < 2 {
		t.Fatal("expected at least 2 calls")
	}

	// Second call should have more messages (original + assistant + user prompt)
	secondCall := calls[1]
	if len(secondCall.Messages) < 3 {
		t.Errorf("expected at least 3 messages in second call (original user + assistant + prompt), got %d", len(secondCall.Messages))
	}

	// Third call should have summarize transform applied
	if len(calls) >= 3 {
		thirdCall := calls[2]
		lastMsg := thirdCall.Messages[len(thirdCall.Messages)-1]
		lastContent := lastMsg.ContentString()
		if lastContent == "" {
			t.Error("expected summarize prompt in third call")
		}
	}

	if result.TotalTokens != 45 {
		t.Errorf("expected 45 total tokens, got %d", result.TotalTokens)
	}
}

func TestSequentialWorkflow_ErrorStop(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("ok", 10),
		nil, // this will trigger the error
	}, []error{nil, errors.New("provider timeout")})

	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:    "error-stop",
		Pattern: "sequential",
		Steps: []WorkflowStep{
			{Name: "step1"},
			{Name: "step2", OnError: "stop"},
			{Name: "step3"},
		},
	}

	_, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err == nil {
		t.Fatal("expected error from stopped workflow")
	}
	if !errors.Is(err, errors.Unwrap(err)) && err.Error() == "" {
		t.Fatal("expected wrapped error")
	}
}

func TestSequentialWorkflow_ErrorSkip(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("step 1 done", 10),
		nil,
		makeResponse("step 3 done", 15),
	}, []error{nil, errors.New("step 2 failed"), nil})

	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:    "error-skip",
		Pattern: "sequential",
		Steps: []WorkflowStep{
			{Name: "step1"},
			{Name: "step2", OnError: "skip"},
			{Name: "step3"},
		},
	}

	result, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Steps) != 3 {
		t.Fatalf("expected 3 step results, got %d", len(result.Steps))
	}

	if !result.Steps[1].Skipped {
		t.Error("expected step 2 to be skipped")
	}
	if result.Steps[1].Error == "" {
		t.Error("expected step 2 to have error message")
	}

	content := extractResponseContent(result.FinalResponse)
	if content != "step 3 done" {
		t.Errorf("expected final content 'step 3 done', got %q", content)
	}
}

func TestSequentialWorkflow_Timeout(t *testing.T) {
	slowExec := &slowExecutor{
		delay: 200 * time.Millisecond,
		resp:  makeResponse("slow response", 10),
	}

	we := NewWorkflowExecutor(slowExec)
	config := &WorkflowConfig{
		Name:    "timeout-test",
		Pattern: "sequential",
		Steps: []WorkflowStep{
			{Name: "slow_step", Timeout: 50 * time.Millisecond},
		},
	}

	_, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

type slowExecutor struct {
	delay time.Duration
	resp  *ChatCompletionResponse
}

func (s *slowExecutor) Execute(ctx context.Context, _ *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	select {
	case <-time.After(s.delay):
		return s.resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// --- Fan-Out Tests ---

func TestFanOut_Parallel(t *testing.T) {
	var callCount atomic.Int64
	countingExec := &countingExecutor{
		count: &callCount,
		resp:  makeResponse("parallel output", 10),
	}

	we := NewWorkflowExecutor(countingExec)
	config := &WorkflowConfig{
		Name:    "fan-out",
		Pattern: "fan_out",
		Steps: []WorkflowStep{
			{Name: "branch1"},
			{Name: "branch2"},
			{Name: "branch3"},
		},
		ConsensusMode: "first",
	}

	result, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount.Load() != 3 {
		t.Errorf("expected 3 parallel calls, got %d", callCount.Load())
	}

	if result.FinalResponse == nil {
		t.Fatal("expected final response")
	}

	if len(result.Steps) != 3 {
		t.Errorf("expected 3 step results, got %d", len(result.Steps))
	}
}

type countingExecutor struct {
	count *atomic.Int64
	resp  *ChatCompletionResponse
}

func (c *countingExecutor) Execute(_ context.Context, _ *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	c.count.Add(1)
	return c.resp, nil
}

func TestFanOut_ConsensusFirst(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("response A", 10),
		makeResponse("response B", 10),
		makeResponse("response C", 10),
	}, nil)

	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:          "consensus-first",
		Pattern:       "fan_out",
		Steps:         []WorkflowStep{{Name: "a"}, {Name: "b"}, {Name: "c"}},
		ConsensusMode: "first",
	}

	result, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.FinalResponse == nil {
		t.Fatal("expected a final response")
	}
}

func TestFanOut_ConsensusMajority(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("the answer is 42", 10),
		makeResponse("the answer is 42", 10),
		makeResponse("the answer is 7", 10),
	}, nil)

	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:          "consensus-majority",
		Pattern:       "fan_out",
		Steps:         []WorkflowStep{{Name: "a"}, {Name: "b"}, {Name: "c"}},
		ConsensusMode: "majority",
	}

	result, err := we.Execute(context.Background(), config, makeRequest("what is the answer?"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content := extractResponseContent(result.FinalResponse)
	if content != "the answer is 42" {
		t.Errorf("expected majority answer 'the answer is 42', got %q", content)
	}
}

func TestFanOut_PartialFailure(t *testing.T) {
	// Use a custom executor that fails for a specific model name.
	// We set each step's model to identify it, and fail the one named "fail-model".
	failExec := &modelBasedExecutor{
		failModel: "fail-model",
		resp:      makeResponse("success", 10),
	}

	we := NewWorkflowExecutor(failExec)
	config := &WorkflowConfig{
		Name:    "partial-fail",
		Pattern: "fan_out",
		Steps: []WorkflowStep{
			{Name: "a", Model: "ok-model-1"},
			{Name: "b", Model: "fail-model", OnError: "skip"},
			{Name: "c", Model: "ok-model-2"},
		},
		ConsensusMode: "first",
	}

	result, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.FinalResponse == nil {
		t.Fatal("expected final response despite partial failure")
	}

	// Step at index 1 (step "b") should have an error
	if result.Steps[1].Error == "" {
		t.Error("expected error on step b")
	}
}

// modelBasedExecutor fails for requests with a specific model name.
type modelBasedExecutor struct {
	failModel string
	resp      *ChatCompletionResponse
}

func (m *modelBasedExecutor) Execute(_ context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	if req.Model == m.failModel {
		return nil, errors.New("provider down")
	}
	return m.resp, nil
}

// --- Eval Pipeline Tests ---

func TestEvalPipeline_ScoreAboveThreshold(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("The capital of France is Paris.", 20),
		makeResponse(`{"score": 9.5, "reason": "accurate and concise"}`, 15),
	}, nil)

	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:    "eval-high-score",
		Pattern: "eval_pipeline",
		Steps: []WorkflowStep{
			{Name: "primary"},
			{Name: "evaluator", SystemPrompt: "Rate the response accuracy from 0 to 10. Respond as JSON with score and reason."},
		},
	}

	result, err := we.Execute(context.Background(), config, makeRequest("What is the capital of France?"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(result.Steps))
	}

	// Final response should be the primary response
	content := extractResponseContent(result.FinalResponse)
	if content != "The capital of France is Paris." {
		t.Errorf("expected primary response as final, got %q", content)
	}

	// Eval step should have a response
	evalContent := extractResponseContent(result.Steps[1].Response)
	if evalContent == "" {
		t.Error("expected eval step to have response content")
	}
}

func TestEvalPipeline_ScoreBelowThreshold(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("I think maybe it's London?", 20),
		makeResponse(`{"score": 2.0, "reason": "incorrect answer"}`, 15),
	}, nil)

	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:    "eval-low-score",
		Pattern: "eval_pipeline",
		Steps: []WorkflowStep{
			{Name: "primary"},
			{Name: "evaluator"},
		},
	}

	result, err := we.Execute(context.Background(), config, makeRequest("What is the capital of France?"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The pipeline still returns the primary response (caller can check eval score)
	if result.FinalResponse == nil {
		t.Fatal("expected final response")
	}

	if result.TotalTokens != 35 {
		t.Errorf("expected 35 total tokens, got %d", result.TotalTokens)
	}
}

// --- Guardrail Sandwich Tests ---

func TestGuardrailSandwich_Pass(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("PASS - input is safe", 5),
		makeResponse("Here is a helpful response about cooking.", 25),
		makeResponse("PASS - output is appropriate", 5),
	}, nil)

	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:    "guardrail-pass",
		Pattern: "guardrail_sandwich",
		Steps: []WorkflowStep{
			{Name: "pre_check"},
			{Name: "main"},
			{Name: "post_check"},
		},
	}

	result, err := we.Execute(context.Background(), config, makeRequest("How do I make pasta?"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(result.Steps))
	}

	// Final response should be the main response (not guardrail)
	content := extractResponseContent(result.FinalResponse)
	if content != "Here is a helpful response about cooking." {
		t.Errorf("expected main response as final, got %q", content)
	}

	if result.TotalTokens != 35 {
		t.Errorf("expected 35 total tokens, got %d", result.TotalTokens)
	}
}

func TestGuardrailSandwich_PreBlock(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("BLOCK - inappropriate content detected", 5),
	}, nil)

	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:    "guardrail-pre-block",
		Pattern: "guardrail_sandwich",
		Steps: []WorkflowStep{
			{Name: "pre_check"},
			{Name: "main"},
			{Name: "post_check"},
		},
	}

	result, err := we.Execute(context.Background(), config, makeRequest("something bad"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have 1 step (pre-guardrail blocked)
	if len(result.Steps) != 1 {
		t.Fatalf("expected 1 step (blocked at pre-guardrail), got %d", len(result.Steps))
	}

	content := extractResponseContent(result.FinalResponse)
	if content != "BLOCK - inappropriate content detected" {
		t.Errorf("expected block response, got %q", content)
	}
}

func TestGuardrailSandwich_PostBlock(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("PASS - input ok", 5),
		makeResponse("Some potentially harmful output", 25),
		makeResponse("BLOCK - output contains harmful content", 5),
	}, nil)

	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:    "guardrail-post-block",
		Pattern: "guardrail_sandwich",
		Steps: []WorkflowStep{
			{Name: "pre_check"},
			{Name: "main"},
			{Name: "post_check"},
		},
	}

	result, err := we.Execute(context.Background(), config, makeRequest("query"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All 3 steps should have run
	if len(result.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(result.Steps))
	}

	// Final response should be the post-guardrail block response
	content := extractResponseContent(result.FinalResponse)
	if content != "BLOCK - output contains harmful content" {
		t.Errorf("expected post-guardrail block as final response, got %q", content)
	}
}

// --- Edge Case Tests ---

func TestWorkflow_EmptySteps(t *testing.T) {
	exec := newMockExecutor(nil, nil)
	we := NewWorkflowExecutor(exec)

	config := &WorkflowConfig{
		Name:    "empty",
		Pattern: "sequential",
		Steps:   []WorkflowStep{},
	}

	_, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err == nil {
		t.Fatal("expected error for empty steps")
	}
	if err.Error() != "workflow has no steps" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWorkflow_UnknownPattern(t *testing.T) {
	exec := newMockExecutor(nil, nil)
	we := NewWorkflowExecutor(exec)

	config := &WorkflowConfig{
		Name:    "bad-pattern",
		Pattern: "nonexistent",
		Steps:   []WorkflowStep{{Name: "step1"}},
	}

	_, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err == nil {
		t.Fatal("expected error for unknown pattern")
	}
	if err.Error() != `unknown workflow pattern: "nonexistent"` {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWorkflow_NilConfig(t *testing.T) {
	exec := newMockExecutor(nil, nil)
	we := NewWorkflowExecutor(exec)

	_, err := we.Execute(context.Background(), nil, makeRequest("test"))
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestEvalPipeline_TooFewSteps(t *testing.T) {
	exec := newMockExecutor(nil, nil)
	we := NewWorkflowExecutor(exec)

	config := &WorkflowConfig{
		Name:    "eval-one-step",
		Pattern: "eval_pipeline",
		Steps:   []WorkflowStep{{Name: "only_one"}},
	}

	_, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err == nil {
		t.Fatal("expected error for eval_pipeline with < 2 steps")
	}
}

func TestGuardrailSandwich_TooFewSteps(t *testing.T) {
	exec := newMockExecutor(nil, nil)
	we := NewWorkflowExecutor(exec)

	config := &WorkflowConfig{
		Name:    "guardrail-two-steps",
		Pattern: "guardrail_sandwich",
		Steps:   []WorkflowStep{{Name: "a"}, {Name: "b"}},
	}

	_, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err == nil {
		t.Fatal("expected error for guardrail_sandwich with < 3 steps")
	}
}

// --- Helper function tests ---

func TestExtractScore_JSON(t *testing.T) {
	score := extractScore(`{"score": 8.5, "reason": "good"}`)
	if score != 8.5 {
		t.Errorf("expected 8.5, got %f", score)
	}
}

func TestExtractScore_PlainNumber(t *testing.T) {
	score := extractScore("The score is 7.5 out of 10")
	if score != 7.5 {
		t.Errorf("expected 7.5, got %f", score)
	}
}

func TestContentSimilar_Exact(t *testing.T) {
	if !contentSimilar("hello world", "hello world") {
		t.Error("expected exact match to be similar")
	}
}

func TestContentSimilar_CaseInsensitive(t *testing.T) {
	if !contentSimilar("Hello World", "hello world") {
		t.Error("expected case-insensitive match to be similar")
	}
}

func TestContentSimilar_Different(t *testing.T) {
	if contentSimilar("hello", "goodbye") {
		t.Error("expected different strings to not be similar")
	}
}

func TestIsGuardrailBlock(t *testing.T) {
	tests := []struct {
		content string
		want    bool
	}{
		{"BLOCK - unsafe content", true},
		{"BLOCK", true},
		{"PASS - all good", false},
		{"block - lowercase", true},
		{"The response is fine", false},
		{"", false},
	}

	for _, tt := range tests {
		resp := makeResponse(tt.content, 5)
		got := isGuardrailBlock(resp)
		if got != tt.want {
			t.Errorf("isGuardrailBlock(%q) = %v, want %v", tt.content, got, tt.want)
		}
	}
}

func TestCloneRequest_NilSafe(t *testing.T) {
	clone := cloneRequest(nil)
	if clone == nil {
		t.Fatal("expected non-nil clone from nil input")
	}
	if len(clone.Messages) != 0 {
		t.Error("expected empty messages")
	}
}

func TestCloneRequest_Independence(t *testing.T) {
	original := makeRequest("hello")
	clone := cloneRequest(original)

	clone.Messages = append(clone.Messages, Message{
		Role:    "assistant",
		Content: json.RawMessage(`"world"`),
	})

	if len(original.Messages) != 1 {
		t.Error("modifying clone should not affect original")
	}
	if len(clone.Messages) != 2 {
		t.Error("clone should have 2 messages")
	}
}

func TestApplyStepOverrides_Model(t *testing.T) {
	req := makeRequest("test")
	step := WorkflowStep{Model: "gpt-4o"}
	result := applyStepOverrides(req, step)
	if result.Model != "gpt-4o" {
		t.Errorf("expected model 'gpt-4o', got %q", result.Model)
	}
}

func TestApplyStepOverrides_Temperature(t *testing.T) {
	req := makeRequest("test")
	temp := 0.5
	step := WorkflowStep{Temperature: &temp}
	result := applyStepOverrides(req, step)
	if result.Temperature == nil || *result.Temperature != 0.5 {
		t.Error("expected temperature 0.5")
	}
}

func TestApplyStepOverrides_SystemPrompt(t *testing.T) {
	req := makeRequest("test")
	step := WorkflowStep{SystemPrompt: "You are helpful"}
	result := applyStepOverrides(req, step)

	if len(result.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(result.Messages))
	}
	if result.Messages[0].Role != "system" {
		t.Error("expected system message first")
	}
}

func TestApplyTransform_AppendContext(t *testing.T) {
	req := makeRequest("original question")
	prevResp := makeResponse("previous answer", 10)
	step := WorkflowStep{Transform: "append_context", SystemPrompt: "elaborate"}

	result := applyTransform(req, prevResp, step)

	// Should have: original user + assistant (prev) + user (prompt)
	if len(result.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(result.Messages))
	}
	if result.Messages[1].Role != "assistant" {
		t.Error("expected assistant message at index 1")
	}
	if result.Messages[2].Role != "user" {
		t.Error("expected user message at index 2")
	}
}

func TestApplyTransform_Summarize(t *testing.T) {
	req := makeRequest("original")
	prevResp := makeResponse("long text here", 10)
	step := WorkflowStep{Transform: "summarize"}

	result := applyTransform(req, prevResp, step)

	lastMsg := result.Messages[len(result.Messages)-1]
	content := lastMsg.ContentString()
	if !orchestrationContainsSubstring(content, "Summarize the following") {
		t.Errorf("expected summarize prefix, got %q", content)
	}
}

func orchestrationContainsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && orchestrationContainsAt(s, sub))
}

func orchestrationContainsAt(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestSequentialWorkflow_StepOverrides(t *testing.T) {
	exec := newMockExecutor([]*ChatCompletionResponse{
		makeResponse("step 1 output", 10),
		makeResponse("step 2 output", 10),
	}, nil)

	temp := 0.2
	we := NewWorkflowExecutor(exec)
	config := &WorkflowConfig{
		Name:    "override-test",
		Pattern: "sequential",
		Steps: []WorkflowStep{
			{Name: "step1", Model: "gpt-4o"},
			{Name: "step2", Model: "claude-3-opus", Temperature: &temp, MaxTokens: 500},
		},
	}

	_, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	<-exec.mu
	calls := exec.calls
	exec.mu <- struct{}{}

	if calls[0].Model != "gpt-4o" {
		t.Errorf("step 1 model: expected gpt-4o, got %s", calls[0].Model)
	}
	if calls[1].Model != "claude-3-opus" {
		t.Errorf("step 2 model: expected claude-3-opus, got %s", calls[1].Model)
	}
	if calls[1].Temperature == nil || *calls[1].Temperature != 0.2 {
		t.Error("step 2 temperature should be 0.2")
	}
	if calls[1].MaxTokens == nil || *calls[1].MaxTokens != 500 {
		t.Error("step 2 max_tokens should be 500")
	}
}

func TestFanOut_MaxParallel(t *testing.T) {
	var concurrent atomic.Int64
	var maxConcurrent atomic.Int64

	limitExec := &concurrencyTracker{
		concurrent:    &concurrent,
		maxConcurrent: &maxConcurrent,
		resp:          makeResponse("output", 10),
		delay:         50 * time.Millisecond,
	}

	we := NewWorkflowExecutor(limitExec)
	config := &WorkflowConfig{
		Name:    "max-parallel",
		Pattern: "fan_out",
		Steps: []WorkflowStep{
			{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}, {Name: "e"},
		},
		MaxParallel:   2,
		ConsensusMode: "first",
	}

	result, err := we.Execute(context.Background(), config, makeRequest("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.FinalResponse == nil {
		t.Fatal("expected final response")
	}

	peak := maxConcurrent.Load()
	if peak > 2 {
		t.Errorf("max concurrent should be <= 2, got %d", peak)
	}
}

type concurrencyTracker struct {
	concurrent    *atomic.Int64
	maxConcurrent *atomic.Int64
	resp          *ChatCompletionResponse
	delay         time.Duration
}

func (c *concurrencyTracker) Execute(_ context.Context, _ *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	cur := c.concurrent.Add(1)
	for {
		old := c.maxConcurrent.Load()
		if cur <= old || c.maxConcurrent.CompareAndSwap(old, cur) {
			break
		}
	}
	time.Sleep(c.delay)
	c.concurrent.Add(-1)
	return c.resp, nil
}
